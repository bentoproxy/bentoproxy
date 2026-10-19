use crate::{
    auth::{Claims, JwtManager, UserRole},
    db::Database,
    device_ws::DeviceRegistry,
    mux::StreamMultiplexer,
    web::models::*,
};
use askama::Template;
use axum::{
    extract::{Extension, Form, Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use serde_json::json;
use axum_extra::extract::cookie::{Cookie, CookieJar};
use chrono::DateTime;
use std::sync::Arc;
use tracing::{error, info, warn};

/// How long an unclaimed announcement is kept. Long enough for someone to
/// unbox a device and get to their dashboard, short enough that abandoned
/// announcements disappear.
const PENDING_CLAIM_TTL_SECS: i64 = 24 * 60 * 60;
/// Wrong codes one owner may submit per window. The code is 40 bits, so this
/// makes guessing hopeless while leaving room for typos. Counted per owner,
/// never per device: otherwise one person's guessing would lock everyone
/// else's unclaimed nodes.
const MAX_CLAIM_ATTEMPTS: i64 = 10;
const CLAIM_ATTEMPT_WINDOW_SECS: i64 = 15 * 60;
/// Minimum gap between speed tests on one device. Tests put real traffic on a
/// volunteer's home connection, so they stay occasional and owner-initiated.
const SPEEDTEST_COOLDOWN_SECS: i64 = 5 * 60;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub registry: DeviceRegistry,
    pub mux: StreamMultiplexer,
    pub meters: crate::metrics::DeviceMeters,
    pub jwt_manager: Arc<JwtManager>,
    pub socks5_host: String,
    pub socks5_port: u16,
}

// Templates

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    device_count: usize,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: String,  // Empty string means no error
}

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterTemplate {
    error: String,  // Empty string means no error
}

#[derive(Template)]
#[template(path = "dashboard_owner.html")]
struct DashboardOwnerTemplate {
    email: String,
    devices: Vec<DeviceInfo>,
    online_count: usize,
    total_count: usize,
    /// Nodes on the network that no owner has claimed yet.
    pending: Vec<PendingNode>,
}

#[derive(Template)]
#[template(path = "dashboard_user.html")]
struct DashboardUserTemplate {
    email: String,
    api_key: String,
    socks5_host: String,
    socks5_port: u16,
}

// Handlers

pub async fn index(State(state): State<AppState>) -> impl IntoResponse {
    let device_count = state.registry.count();
    let template = IndexTemplate { device_count };
    HtmlTemplate(template)
}

pub async fn login_page(jar: CookieJar) -> impl IntoResponse {
    // If already logged in, redirect to dashboard
    if jar.get("token").is_some() {
        return Redirect::to("/dashboard").into_response();
    }

    let template = LoginTemplate { error: String::new() };
    HtmlTemplate(template).into_response()
}

pub async fn login_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    // Try device owner first
    match state.db.authenticate_device_owner(&form.email, &form.password) {
        Ok(Some(owner)) => {
            let claims = Claims::new(owner.id, owner.email, UserRole::DeviceOwner);
            let token = state.jwt_manager.create_token(claims).unwrap();

            let jar = jar.add(Cookie::new("token", token));
            return (jar, Redirect::to("/dashboard")).into_response();
        }
        Ok(None) => {}
        Err(e) => {
            error!("Database error during login: {}", e);
        }
    }

    // Try proxy user
    match state.db.authenticate_proxy_user(&form.email, &form.password) {
        Ok(Some(user)) => {
            let claims = Claims::new(user.id, user.email, UserRole::ProxyUser);
            let token = state.jwt_manager.create_token(claims).unwrap();

            let jar = jar.add(Cookie::new("token", token));
            return (jar, Redirect::to("/dashboard")).into_response();
        }
        Ok(None) => {}
        Err(e) => {
            error!("Database error during login: {}", e);
        }
    }

    // Login failed
    let template = LoginTemplate {
        error: "Invalid email or password".to_string(),
    };
    HtmlTemplate(template).into_response()
}

pub async fn register_page(jar: CookieJar) -> impl IntoResponse {
    // If already logged in, redirect to dashboard
    if jar.get("token").is_some() {
        return Redirect::to("/dashboard").into_response();
    }

    let template = RegisterTemplate { error: String::new() };
    HtmlTemplate(template).into_response()
}

pub async fn register_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<RegisterForm>,
) -> impl IntoResponse {
    // Basic validation
    if form.email.is_empty() || form.password.is_empty() {
        let template = RegisterTemplate {
            error: "Email and password are required".to_string(),
        };
        return HtmlTemplate(template).into_response();
    }

    if form.password.len() < 8 {
        let template = RegisterTemplate {
            error: "Password must be at least 8 characters".to_string(),
        };
        return HtmlTemplate(template).into_response();
    }

    // Create user based on role
    let result = if form.role == "device_owner" {
        state
            .db
            .create_device_owner(&form.email, &form.password)
            .map(|id| (id, UserRole::DeviceOwner))
    } else {
        state
            .db
            .create_proxy_user(&form.email, &form.password)
            .map(|id| (id, UserRole::ProxyUser))
    };

    match result {
        Ok((user_id, role)) => {
            info!("New user registered: {} (role: {:?})", form.email, role);
            let claims = Claims::new(user_id, form.email, role);
            let token = state.jwt_manager.create_token(claims).unwrap();

            let jar = jar.add(Cookie::new("token", token));
            (jar, Redirect::to("/dashboard")).into_response()
        }
        Err(e) => {
            error!("Failed to create user: {}", e);
            let template = RegisterTemplate {
                error: "Email already exists or database error".to_string(),
            };
            HtmlTemplate(template).into_response()
        }
    }
}

pub async fn logout(jar: CookieJar) -> impl IntoResponse {
    let jar = jar.remove(Cookie::from("token"));
    (jar, Redirect::to("/"))
}

pub async fn dashboard(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> impl IntoResponse {
    match claims.role {
        UserRole::DeviceOwner => {
            // Get devices for this owner
            let devices = match state.db.get_devices_for_owner(&claims.sub) {
                Ok(devices) => devices
                    .into_iter()
                    .map(|d| {
                        let traffic = state.db.device_traffic(&d.id).unwrap_or_default();
                        let live = state.meters.snapshot(&d.id);
                        DeviceInfo {
                        streams: state.mux.device_stream_count(&d.id),
                        down_bps: live.down_bps,
                        up_bps: live.up_bps,
                        down_today: human_bytes(traffic.bytes_down_today as u64),
                        up_today: human_bytes(traffic.bytes_up_today as u64),
                        peak_down: human_rate(traffic.peak_down_bps as u64),
                        id: d.id.clone(),
                        name: d.name.unwrap_or_else(|| "Unnamed".to_string()),
                        is_active: d.is_active,
                        is_online: state.registry.get_device(&d.id).is_some(),
                        created_at: DateTime::from_timestamp(d.created_at, 0)
                            .unwrap()
                            .format("%Y-%m-%d %H:%M")
                            .to_string(),
                        last_seen_at: d.last_seen_at.map(|ts| {
                            DateTime::from_timestamp(ts, 0)
                                .unwrap()
                                .format("%Y-%m-%d %H:%M")
                                .to_string()
                        }).unwrap_or_else(|| "Never".to_string()),
                    }})
                    .collect(),
                Err(e) => {
                    error!("Failed to get devices: {}", e);
                    vec![]
                }
            };

            let total_count = devices.len();
            let online_count = devices.iter().filter(|d| d.is_online).count();

            let pending = match state.db.list_pending_claims(PENDING_CLAIM_TTL_SECS) {
                Ok(nodes) => nodes
                    .into_iter()
                    .map(|n| PendingNode {
                        hw_id: n.hw_id,
                        model: n.model.unwrap_or_else(|| "unknown".to_string()),
                        waiting_since: DateTime::from_timestamp(n.announced_at, 0)
                            .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                            .unwrap_or_default(),
                    })
                    .collect(),
                Err(e) => {
                    error!("failed to list pending claims: {}", e);
                    vec![]
                }
            };

            let template = DashboardOwnerTemplate {
                email: claims.email,
                devices,
                pending,
                online_count,
                total_count,
            };
            HtmlTemplate(template).into_response()
        }
        UserRole::ProxyUser => {
            // Get API key from database
            let api_key = match state.db.get_proxy_user_by_id(&claims.sub) {
                Ok(Some(user)) => user.api_key,
                _ => "Error loading API key".to_string(),
            };

            let template = DashboardUserTemplate {
                email: claims.email,
                api_key,
                socks5_host: state.socks5_host.clone(),
                socks5_port: state.socks5_port,
            };
            HtmlTemplate(template).into_response()
        }
    }
}

// Helper to render Askama templates
struct HtmlTemplate<T>(T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => {
                error!("Template rendering error: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to render template: {}", err),
                )
                    .into_response()
            }
        }
    }
}

/// Register a new device for the signed-in owner.
///
/// Returns the device ID and token as JSON. The token is shown to the owner
/// once, here, because it is not recoverable later: the firmware's setup page
/// is the only place it needs to be entered. A future claim flow will hand the
/// token straight to the device instead, so the owner never handles it.
pub async fn create_device(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Form(form): Form<NewDeviceForm>,
) -> Response {
    // Proxy users consume the network; only owners contribute nodes to it.
    if claims.role != UserRole::DeviceOwner {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "only device owners can register devices" })),
        )
            .into_response();
    }

    let name = form
        .name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());

    match state.db.create_device(&claims.sub, name) {
        Ok(device) => {
            info!("registered device {} for owner {}", device.id, claims.sub);
            (
                StatusCode::CREATED,
                Json(json!({
                    "device_id": device.id,
                    "device_token": device.token,
                    "name": device.name,
                })),
            )
                .into_response()
        }
        Err(e) => {
            error!("failed to register device for {}: {}", claims.sub, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "could not register the device" })),
            )
                .into_response()
        }
    }
}

/// A node tells the orchestrator it exists and is waiting for an owner.
///
/// Unauthenticated by necessity: the device has no credentials yet. It carries
/// only its hardware id and the code printed on its case, neither of which
/// grants access to anything. Announcements expire, so this cannot be used to
/// fill the table.
pub async fn announce_device(
    State(state): State<AppState>,
    Form(form): Form<DeviceAnnounceForm>,
) -> Response {
    let hw_id = form.hw_id.trim();
    let code = form.claim_code.trim().to_uppercase();

    // Cheap shape checks so junk never reaches the database.
    if hw_id.is_empty() || hw_id.len() > 64 || code.len() < 8 || code.len() > 32 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid hw_id or claim_code" })),
        )
            .into_response();
    }

    // Opportunistic cleanup; announcing is the only thing that grows this table.
    if let Err(e) = state.db.prune_pending_claims(PENDING_CLAIM_TTL_SECS) {
        error!("failed to prune pending claims: {}", e);
    }

    match state.db.announce_pending(hw_id, &code, form.model.as_deref()) {
        Ok(()) => {
            info!("node {} announced itself, awaiting a claim", hw_id);
            (StatusCode::OK, Json(json!({ "status": "pending" }))).into_response()
        }
        Err(e) => {
            error!("failed to record announcement from {}: {}", hw_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "could not record the announcement" })),
            )
                .into_response()
        }
    }
}

/// A node polls for the credentials an owner's claim produced.
///
/// Returns them exactly once; afterwards the node has them in NVS and the row
/// is gone. Knowing a hardware id alone yields nothing until an owner has
/// entered that device's printed code.
pub async fn poll_claim(State(state): State<AppState>, Path(hw_id): Path<String>) -> Response {
    match state.db.take_claimed_credentials(&hw_id) {
        Ok(Some((device_id, token))) => {
            info!("node {} collected its credentials as {}", hw_id, device_id);
            (
                StatusCode::OK,
                Json(json!({
                    "status": "claimed",
                    "device_id": device_id,
                    "device_token": token,
                })),
            )
                .into_response()
        }
        Ok(None) => (StatusCode::OK, Json(json!({ "status": "pending" }))).into_response(),
        Err(e) => {
            error!("failed to read claim for {}: {}", hw_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "could not read the claim" })),
            )
                .into_response()
        }
    }
}

/// An owner claims a waiting node by the code printed on it.
pub async fn claim_device(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Form(form): Form<ClaimDeviceForm>,
) -> Response {
    if claims.role != UserRole::DeviceOwner {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "only device owners can claim devices" })),
        )
            .into_response();
    }

    match state
        .db
        .recent_claim_attempts(&claims.sub, CLAIM_ATTEMPT_WINDOW_SECS)
    {
        Ok(attempts) if attempts >= MAX_CLAIM_ATTEMPTS => {
            warn!("owner {} hit the claim attempt limit", claims.sub);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": format!(
                        "too many incorrect codes — wait {} minutes and try again",
                        CLAIM_ATTEMPT_WINDOW_SECS / 60
                    )
                })),
            )
                .into_response();
        }
        Ok(_) => {}
        Err(e) => {
            error!("failed to read claim attempts for {}: {}", claims.sub, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "could not check the claim rate limit" })),
            )
                .into_response();
        }
    }

    match state.db.claim_by_code(&claims.sub, &form.code) {
        Ok(Some(device)) => {
            info!("owner {} claimed device {}", claims.sub, device.id);
            (
                StatusCode::OK,
                Json(json!({
                    "status": "claimed",
                    "device_id": device.id,
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "no node is waiting with that code — check the code on the device, \
                          and that the node is powered on and connected to your WiFi"
            })),
        )
            .into_response(),
        Err(e) => {
            error!("claim failed for owner {}: {}", claims.sub, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "could not claim the device" })),
            )
                .into_response()
        }
    }
}

/// Per-device live throughput, polled by the dashboard.
///
/// Rates come from in-memory counters, so an ongoing transfer is visible;
/// daily totals come from recorded flows.
pub async fn device_stats(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Response {
    if claims.role != UserRole::DeviceOwner {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "not a device owner" }))).into_response();
    }

    let devices = match state.db.get_devices_for_owner(&claims.sub) {
        Ok(devices) => devices,
        Err(e) => {
            error!("failed to list devices for {}: {}", claims.sub, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "could not read devices" })),
            )
                .into_response();
        }
    };

    let stats: Vec<_> = devices
        .into_iter()
        .map(|d| {
            let live = state.meters.snapshot(&d.id);
            let traffic = state.db.device_traffic(&d.id).unwrap_or_default();
            json!({
                "device_id": d.id,
                "online": state.registry.get_device(&d.id).is_some(),
                "streams": state.mux.device_stream_count(&d.id),
                "down_bps": live.down_bps,
                "up_bps": live.up_bps,
                "down_bps_1m": live.down_bps_1m,
                "up_bps_1m": live.up_bps_1m,
                "down_today": human_bytes(traffic.bytes_down_today as u64),
                "up_today": human_bytes(traffic.bytes_up_today as u64),
                // Raw figures too, so the page can total them up itself.
                "down_bytes_today": traffic.bytes_down_today,
                "up_bytes_today": traffic.bytes_up_today,
                "flows_today": traffic.flows_today,
                "peak_down": human_rate(traffic.peak_down_bps as u64),
                "down_rate": human_rate(live.down_bps),
                "up_rate": human_rate(live.up_bps),
            })
        })
        .collect();

    (StatusCode::OK, Json(json!({ "devices": stats }))).into_response()
}

/// Bytes as a short human string, e.g. "1.4 MB".
fn human_bytes(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10), ("B", 1)];

    for (unit, size) in UNITS {
        if bytes >= size {
            // Whole bytes read better without a decimal point.
            return if size == 1 {
                format!("{bytes} B")
            } else {
                format!("{:.1} {unit}", bytes as f64 / size as f64)
            };
        }
    }

    "0 B".to_string()
}

/// A rate as a short human string, e.g. "1.1 MB/s".
fn human_rate(bytes_per_sec: u64) -> String {
    if bytes_per_sec == 0 {
        return "—".to_string();
    }
    format!("{}/s", human_bytes(bytes_per_sec))
}

/// Measure one device's download speed, on request.
///
/// Never called on a schedule: the traffic lands on the owner's home
/// connection, so a test happens only when they ask for one, and not more
/// often than the cooldown allows.
pub async fn speed_test(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(device_id): Path<String>,
) -> Response {
    if claims.role != UserRole::DeviceOwner {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "only device owners can test a device" })),
        )
            .into_response();
    }

    match state.db.device_belongs_to(&device_id, &claims.sub) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "no such device" })),
            )
                .into_response()
        }
        Err(e) => {
            error!("ownership check failed for {}: {}", device_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "could not check the device" })),
            )
                .into_response();
        }
    }

    if state.registry.get_device(&device_id).is_none() {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "that node is offline" })),
        )
            .into_response();
    }

    // Respect the cooldown, measured from the last recorded attempt.
    if let Ok(Some(previous)) = state.db.latest_speed_test(&device_id) {
        let age = chrono::Utc::now().timestamp() - previous.ran_at;
        if age < SPEEDTEST_COOLDOWN_SECS {
            let wait = SPEEDTEST_COOLDOWN_SECS - age;
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": format!("tested {}s ago — try again in {}s", age, wait)
                })),
            )
                .into_response();
        }
    }

    let outcome = crate::speedtest::run(&state.mux, &device_id, crate::speedtest::DEFAULT_BYTES)
        .await
        .map_err(|e| e.to_string());

    if let Err(e) = state.db.record_speed_test(&device_id, &outcome) {
        error!("could not store the speed test for {}: {}", device_id, e);
    }

    // Answer 200 either way and carry success in the body: Cloudflare replaces
    // a 5xx from the origin with its own HTML error page, which reaches the
    // browser as unparseable JSON and hides the real reason.
    match outcome {
        Ok(measurement) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "down_bps": measurement.down_bps,
                "down_rate": human_rate(measurement.down_bps),
                "bytes": measurement.bytes,
                "duration_ms": measurement.duration_ms,
            })),
        )
            .into_response(),
        Err(e) => {
            warn!("speed test on {} failed: {}", device_id, e);
            (StatusCode::OK, Json(json!({ "ok": false, "error": e }))).into_response()
        }
    }
}
