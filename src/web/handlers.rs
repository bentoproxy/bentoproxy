use crate::{
    auth::{Claims, JwtManager, UserRole},
    db::Database,
    device_ws::DeviceRegistry,
    mux::StreamMultiplexer,
    web::models::*,
};
use askama::Template;
use axum::{
    extract::{Extension, Form, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use chrono::DateTime;
use std::sync::Arc;
use tracing::{error, info};

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub registry: DeviceRegistry,
    pub mux: StreamMultiplexer,
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
                    .map(|d| DeviceInfo {
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
                    })
                    .collect(),
                Err(e) => {
                    error!("Failed to get devices: {}", e);
                    vec![]
                }
            };

            let total_count = devices.len();
            let online_count = devices.iter().filter(|d| d.is_online).count();

            let template = DashboardOwnerTemplate {
                email: claims.email,
                devices,
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
