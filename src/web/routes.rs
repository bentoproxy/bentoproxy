use crate::web::handlers::*;
use axum::{
    extract::{Request, State},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use axum_extra::extract::cookie::CookieJar;
use tower_http::{
    services::ServeDir,
    trace::TraceLayer,
};
use tracing::error;

pub fn create_router(state: AppState) -> Router {
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/", get(index))
        .route("/login", get(login_page).post(login_submit))
        .route("/register", get(register_page).post(register_submit))
        .route("/logout", get(logout));

    // Protected routes (auth required)
    let protected_routes = Router::new()
        .route("/dashboard", get(dashboard))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Combine routes
    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .route("/ws/device", get(crate::device_ws::handle_upgrade))  // WebSocket for devices
        .nest_service("/static", ServeDir::new("static"))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Authentication middleware
async fn auth_middleware(
    State(state): State<AppState>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    // Get token from cookie
    let token = jar
        .get("token")
        .map(|cookie| cookie.value().to_string());

    if let Some(token) = token {
        // Verify token
        match state.jwt_manager.verify_token(&token) {
            Ok(claims) => {
                // Add claims to request extensions
                request.extensions_mut().insert(claims);
                return Ok(next.run(request).await);
            }
            Err(e) => {
                error!("Token verification failed: {}", e);
            }
        }
    }

    // No valid token, redirect to login
    Err((jar, Redirect::to("/login")))
}
