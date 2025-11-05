use bentoproxy_orchestrator::{
    auth::JwtManager,
    db::Database,
    device_ws::DeviceRegistry,
    mux::StreamMultiplexer,
    socks5,
    web::{create_router, handlers::AppState},
};
use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,bentoproxy_orchestrator=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting BentoProxy Orchestrator...");

    // Load configuration from environment
    let config = Config::from_env();
    info!("Configuration loaded: {:?}", config);

    // Open database
    let db = Database::open(&config.database_path).expect("Failed to open database");
    info!("Database opened at {}", config.database_path.display());

    // Create device registry
    let registry = DeviceRegistry::new(db.clone());
    info!("Device registry initialized");

    // Create stream multiplexer
    let mux = StreamMultiplexer::new(registry.clone());
    info!("Stream multiplexer initialized");

    // Create JWT manager
    let jwt_manager = Arc::new(JwtManager::new(&config.jwt_secret));

    // Create app state for web handlers
    let app_state = AppState {
        db: db.clone(),
        registry: registry.clone(),
        mux: mux.clone(),
        jwt_manager: jwt_manager.clone(),
        socks5_host: config.socks5_host.clone(),
        socks5_port: config.socks5_port,
    };

    // Create unified web router (includes WebSocket endpoint for devices)
    let web_router = create_router(app_state)
        .layer(CorsLayer::new().allow_origin(Any));

    // Spawn SOCKS5 server
    let socks5_addr: SocketAddr = format!("0.0.0.0:{}", config.socks5_port)
        .parse()
        .unwrap();
    let socks5_registry = registry.clone();
    let socks5_db = db.clone();
    let socks5_mux = mux.clone();
    tokio::spawn(async move {
        info!("SOCKS5 server listening on {}", socks5_addr);
        if let Err(e) = socks5::run_server(socks5_addr, socks5_registry, socks5_db, socks5_mux, config.require_socks5_auth).await
        {
            error!("SOCKS5 server error: {}", e);
        }
    });

    // Start unified web server (HTTP + WebSocket)
    let web_addr: SocketAddr = format!("0.0.0.0:{}", config.http_port).parse().unwrap();
    info!("HTTP + WebSocket server listening on {}", web_addr);
    info!("  - Web dashboard: https://bentoproxy.com (or staging.bentoproxy.com)");
    info!("  - Device WebSocket: wss://bentoproxy.com/ws/device");
    let listener = TcpListener::bind(web_addr).await.unwrap();
    axum::serve(listener, web_router).await.unwrap();
}

/// Application configuration
#[derive(Debug, Clone)]
struct Config {
    pub http_port: u16,
    pub socks5_port: u16,
    pub socks5_host: String,
    pub database_path: PathBuf,
    pub jwt_secret: String,
    pub require_socks5_auth: bool,
}

impl Config {
    fn from_env() -> Self {
        let app_env = env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());

        let http_port = env::var("HTTP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);

        let socks5_port = env::var("SOCKS5_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(1080);

        let socks5_host = env::var("SOCKS5_HOST").unwrap_or_else(|_| "localhost".to_string());

        let database_path = env::var("DATABASE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let base = PathBuf::from(format!("/opt/apps/bentoproxy/{}", app_env));
                base.join("data/bento.db")
            });

        // Ensure database directory exists
        if let Some(parent) = database_path.parent() {
            std::fs::create_dir_all(parent).expect("Failed to create database directory");
        }

        let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| {
            use rand::Rng;
            let secret: String = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(64)
                .map(char::from)
                .collect();
            eprintln!("WARNING: JWT_SECRET not set, using random secret: {}", secret);
            eprintln!("Set JWT_SECRET environment variable for production use");
            secret
        });

        let require_socks5_auth = env::var("REQUIRE_SOCKS5_AUTH")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(true);

        Self {
            http_port,
            socks5_port,
            socks5_host,
            database_path,
            jwt_secret,
            require_socks5_auth,
        }
    }
}
