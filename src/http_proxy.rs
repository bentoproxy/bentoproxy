use crate::{
    db::Database,
    device_ws::DeviceRegistry,
};
use std::net::SocketAddr;
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error, info, warn};

/// Run HTTP CONNECT proxy server
pub async fn run_server(
    listen_addr: SocketAddr,
    registry: DeviceRegistry,
    db: Database,
    mux: crate::mux::StreamMultiplexer,
) -> Result<(), HttpProxyError> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| HttpProxyError::BindError(e.to_string()))?;

    info!("HTTP CONNECT proxy listening on {}", listen_addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                debug!("New HTTP proxy connection from {}", peer_addr);
                let registry = registry.clone();
                let db = db.clone();
                let mux = mux.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, registry, db, mux).await {
                        error!("HTTP proxy client error from {}: {}", peer_addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept HTTP proxy connection: {}", e);
            }
        }
    }
}

/// Handle a single HTTP proxy client connection
async fn handle_client(
    stream: TcpStream,
    registry: DeviceRegistry,
    db: Database,
    mux: crate::mux::StreamMultiplexer,
) -> Result<(), HttpProxyError> {
    let mut reader = BufReader::new(stream);

    // Read first line: "CONNECT host:port HTTP/1.1" or "GET http://... HTTP/1.1"
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .await
        .map_err(|e| HttpProxyError::IoError(e.to_string()))?;

    let request_line = request_line.trim();
    debug!("HTTP proxy request: {}", request_line);

    // Parse request line
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(HttpProxyError::InvalidRequest(
            "Invalid request line".to_string(),
        ));
    }

    let method = parts[0];
    let target = parts[1];

    // Only support CONNECT for now (HTTPS tunneling)
    if method != "CONNECT" {
        // For regular HTTP requests, we'd need to parse the full URL
        // For now, return 405 Method Not Allowed
        let response = b"HTTP/1.1 405 Method Not Allowed\r\n\r\n";
        let stream = reader.into_inner();
        let mut stream = stream;
        stream.write_all(response).await?;
        return Err(HttpProxyError::UnsupportedMethod(method.to_string()));
    }

    // Parse CONNECT target: "host:port"
    let (host, port) = parse_host_port(target)?;

    debug!("HTTP CONNECT to {}:{}", host, port);

    // Read headers (including Proxy-Authorization)
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| HttpProxyError::IoError(e.to_string()))?;

        if line.trim().is_empty() {
            break; // End of headers
        }
        headers.push(line);
    }

    // Parse Proxy-Authorization header
    let proxy_user_id = parse_proxy_authorization(&headers, &db).await?;

    // Check if port is allowed
    if is_port_blocked(port) {
        warn!("Blocked HTTP CONNECT to prohibited port {}", port);
        let response = b"HTTP/1.1 403 Forbidden\r\n\r\n";
        let stream = reader.into_inner();
        let mut stream = stream;
        stream.write_all(response).await?;
        return Err(HttpProxyError::PortBlocked(port));
    }

    // Get an available device
    let device_session = registry
        .get_any_device()
        .ok_or(HttpProxyError::NoDevicesAvailable)?;

    debug!("Selected device {} for proxy", device_session.device_id);

    // Create channel for receiving data from device
    let (http_tx, mut http_rx) = tokio::sync::mpsc::unbounded_channel();

    // Create stream via multiplexer (sends OPEN frame to device)
    let (stream_id, ack_rx) = mux
        .create_stream(&device_session.device_id, &host, port, http_tx)
        .await
        .map_err(|e| HttpProxyError::DeviceError(e))?;

    // Wait for ACK from device (with timeout)
    tokio::time::timeout(tokio::time::Duration::from_secs(5), ack_rx)
        .await
        .map_err(|_| HttpProxyError::DeviceError("Device ACK timeout".to_string()))?
        .map_err(|_| HttpProxyError::DeviceError("Device ACK channel closed".to_string()))?;

    debug!("Received ACK from device for stream {}", stream_id);

    // Send success reply to client
    let stream = reader.into_inner();
    let mut stream = stream;
    stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .map_err(|e| HttpProxyError::IoError(e.to_string()))?;

    // Start database flow tracking
    let flow_id = db
        .start_flow(
            &device_session.device_id,
            proxy_user_id.as_deref(),
            stream_id,
            &host,
            port,
        )
        .map_err(|e| HttpProxyError::DatabaseError(e.to_string()))?;

    info!(
        "HTTP CONNECT flow started: stream_id={}, flow_id={}, target={}:{}",
        stream_id, flow_id, host, port
    );

    // Bidirectional data relay (identical to SOCKS5 after handshake)
    let (mut http_read, mut http_write) = stream.split();
    let mut bytes_up = 0u64;
    let mut bytes_down = 0u64;

    let relay_result: Result<(), HttpProxyError> = tokio::select! {
        // Client -> Device
        result = async {
            let mut buf = vec![0u8; 8192];
            loop {
                match http_read.read(&mut buf).await {
                    Ok(0) => {
                        debug!("HTTP client closed connection (stream {})", stream_id);
                        return Ok(());
                    }
                    Ok(n) => {
                        bytes_up += n as u64;
                        let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                        if let Err(e) = mux.send_to_device(stream_id, data) {
                            error!("Failed to send to device: {}", e);
                            return Err(HttpProxyError::DeviceError(e));
                        }
                    }
                    Err(e) => {
                        error!("Error reading from HTTP client: {}", e);
                        return Err(HttpProxyError::IoError(e.to_string()));
                    }
                }
            }
        } => result,

        // Device -> Client
        result = async {
            loop {
                match http_rx.recv().await {
                    Some(data) => {
                        bytes_down += data.len() as u64;
                        if let Err(e) = http_write.write_all(&data).await {
                            error!("Error writing to HTTP client: {}", e);
                            return Err(HttpProxyError::IoError(e.to_string()));
                        }
                    }
                    None => {
                        debug!("Device closed stream {}", stream_id);
                        return Ok(());
                    }
                }
            }
        } => result,
    };

    // End flow with byte counts
    if let Err(e) = db.end_flow(flow_id, Some((bytes_up, bytes_down))) {
        error!("Failed to end flow {}: {}", flow_id, e);
    }

    info!(
        "HTTP CONNECT flow ended: stream_id={}, bytes_up={}, bytes_down={}",
        stream_id, bytes_up, bytes_down
    );

    // Close stream in multiplexer
    mux.close_stream(stream_id, &device_session.device_id);

    relay_result
}

/// Parse "host:port" string
fn parse_host_port(target: &str) -> Result<(String, u16), HttpProxyError> {
    let parts: Vec<&str> = target.split(':').collect();
    if parts.len() != 2 {
        return Err(HttpProxyError::InvalidRequest(format!(
            "Invalid host:port format: {}",
            target
        )));
    }

    let host = parts[0].to_string();
    let port = parts[1]
        .parse::<u16>()
        .map_err(|_| HttpProxyError::InvalidRequest(format!("Invalid port: {}", parts[1])))?;

    Ok((host, port))
}

/// Parse Proxy-Authorization header (Basic auth with API key)
async fn parse_proxy_authorization(
    headers: &[String],
    db: &Database,
) -> Result<Option<String>, HttpProxyError> {
    // Find Proxy-Authorization header
    let auth_header = headers
        .iter()
        .find(|h| h.to_lowercase().starts_with("proxy-authorization:"));

    let auth_header = match auth_header {
        Some(h) => h,
        None => {
            // No authentication provided
            return Err(HttpProxyError::AuthenticationRequired);
        }
    };

    // Parse "Proxy-Authorization: Basic <base64>"
    let parts: Vec<&str> = auth_header.split_whitespace().collect();
    if parts.len() < 3 || parts[1].to_lowercase() != "basic" {
        return Err(HttpProxyError::InvalidAuthentication(
            "Expected Basic authentication".to_string(),
        ));
    }

    let encoded = parts[2];
    use base64::{Engine as _, engine::general_purpose};
    let decoded = general_purpose::STANDARD.decode(encoded).map_err(|_| {
        HttpProxyError::InvalidAuthentication("Invalid base64 encoding".to_string())
    })?;

    let credentials = String::from_utf8(decoded).map_err(|_| {
        HttpProxyError::InvalidAuthentication("Invalid UTF-8 in credentials".to_string())
    })?;

    // Format is "username:password" or "api:api_key"
    let parts: Vec<&str> = credentials.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(HttpProxyError::InvalidAuthentication(
            "Invalid credentials format".to_string(),
        ));
    }

    let api_key = parts[1]; // Password field contains API key

    // Validate API key
    match db.get_proxy_user_by_api_key(api_key) {
        Ok(Some(user)) => {
            debug!("HTTP proxy user authenticated: {}", user.email);
            Ok(Some(user.id))
        }
        Ok(None) => {
            warn!("HTTP proxy authentication failed: invalid API key");
            Err(HttpProxyError::AuthenticationFailed)
        }
        Err(e) => {
            error!("Database error during HTTP proxy auth: {}", e);
            Err(HttpProxyError::DatabaseError(e.to_string()))
        }
    }
}

/// Check if port is blocked (security)
fn is_port_blocked(port: u16) -> bool {
    const BLOCKED_PORTS: &[u16] = &[
        25,   // SMTP
        135,  // MS RPC
        139,  // NetBIOS
        445,  // SMB
        1433, // MSSQL
        3306, // MySQL
        5432, // PostgreSQL
        6379, // Redis
    ];

    BLOCKED_PORTS.contains(&port)
}

#[derive(Debug, Error)]
pub enum HttpProxyError {
    #[error("I/O error: {0}")]
    IoError(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Unsupported method: {0}")]
    UnsupportedMethod(String),

    #[error("Authentication required")]
    AuthenticationRequired,

    #[error("Invalid authentication: {0}")]
    InvalidAuthentication(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Port {0} is blocked")]
    PortBlocked(u16),

    #[error("No devices available")]
    NoDevicesAvailable,

    #[error("Device error: {0}")]
    DeviceError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Bind error: {0}")]
    BindError(String),
}

impl From<std::io::Error> for HttpProxyError {
    fn from(err: std::io::Error) -> Self {
        HttpProxyError::IoError(err.to_string())
    }
}
