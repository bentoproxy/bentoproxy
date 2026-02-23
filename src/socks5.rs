use crate::{
    db::Database,
    device_ws::DeviceRegistry,
};
use bytes::{BufMut, BytesMut};
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, error, info, warn};

const SOCKS_VERSION: u8 = 0x05;

const AUTH_METHOD_NO_AUTH: u8 = 0x00;
const AUTH_METHOD_USERNAME_PASSWORD: u8 = 0x02;
const AUTH_METHOD_NO_ACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCESS: u8 = 0x00;
const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;

/// Run SOCKS5 proxy server
pub async fn run_server(
    listen_addr: SocketAddr,
    registry: DeviceRegistry,
    db: Database,
    mux: crate::mux::StreamMultiplexer,
    require_auth: bool,
) -> Result<(), Socks5Error> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| Socks5Error::BindError(e.to_string()))?;

    info!("SOCKS5 server listening on {}", listen_addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                debug!("New SOCKS5 connection from {}", peer_addr);
                let registry = registry.clone();
                let db = db.clone();
                let mux = mux.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, registry, db, mux, require_auth).await {
                        error!("SOCKS5 client error from {}: {}", peer_addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept SOCKS5 connection: {}", e);
            }
        }
    }
}

/// Handle a single SOCKS5 client connection
async fn handle_client(
    mut stream: TcpStream,
    registry: DeviceRegistry,
    db: Database,
    mux: crate::mux::StreamMultiplexer,
    require_auth: bool,
) -> Result<(), Socks5Error> {
    // Step 1: Method selection
    let auth_method = handshake_methods(&mut stream, require_auth).await?;

    // Step 2: Authentication (if required)
    let proxy_user_id = if auth_method == AUTH_METHOD_USERNAME_PASSWORD {
        Some(authenticate_user(&mut stream, &db).await?)
    } else {
        None
    };

    // Step 3: Request (CONNECT)
    let (host, port) = parse_request(&mut stream).await?;

    debug!("SOCKS5 CONNECT to {}:{}", host, port);

    // Check if port is allowed
    if is_port_blocked(port) {
        warn!("Blocked SOCKS5 connection to prohibited port {}", port);
        send_reply(&mut stream, REP_CONNECTION_NOT_ALLOWED).await?;
        return Err(Socks5Error::PortBlocked(port));
    }

    // Check if host is private/reserved (SSRF protection)
    if is_host_blocked(&host) {
        warn!("Blocked connection to private/reserved host: {}", host);
        send_reply(&mut stream, REP_CONNECTION_NOT_ALLOWED).await?;
        return Err(Socks5Error::HostBlocked(host));
    }

    // Get best available device (least-connections with capacity check)
    let device_session = registry
        .get_best_device(&mux)
        .ok_or(Socks5Error::NoDevicesAvailable)?;

    debug!("Selected device {} for proxy", device_session.device_id);

    // Create channel for receiving data from device
    let (socks5_tx, mut socks5_rx) = tokio::sync::mpsc::unbounded_channel();

    // Create stream via multiplexer (sends OPEN frame to device)
    let (stream_id, ack_rx) = mux
        .create_stream(&device_session.device_id, &host, port, socks5_tx)
        .await
        .map_err(|e| Socks5Error::DeviceError(e))?;

    // Wait for ACK from device (with timeout)
    tokio::time::timeout(tokio::time::Duration::from_secs(5), ack_rx)
        .await
        .map_err(|_| Socks5Error::DeviceError("Device ACK timeout".to_string()))?
        .map_err(|_| Socks5Error::DeviceError("Device ACK channel closed".to_string()))?;

    debug!("Received ACK from device for stream {}", stream_id);

    // Send success reply to client
    send_reply(&mut stream, REP_SUCCESS).await?;

    // Start database flow tracking
    let flow_id = db
        .start_flow(
            &device_session.device_id,
            proxy_user_id.as_deref(),
            stream_id,
            &host,
            port,
        )
        .map_err(|e| Socks5Error::DatabaseError(e.to_string()))?;

    info!(
        "SOCKS5 flow started: stream_id={}, flow_id={}, target={}:{}",
        stream_id, flow_id, host, port
    );

    // Bidirectional data relay
    let (mut socks5_read, mut socks5_write) = stream.split();
    let mut bytes_up = 0u64;
    let mut bytes_down = 0u64;

    let relay_result: Result<(), Socks5Error> = tokio::select! {
        // Client -> Device
        result = async {
            let mut buf = vec![0u8; 8192];
            loop {
                match socks5_read.read(&mut buf).await {
                    Ok(0) => {
                        debug!("SOCKS5 client closed connection (stream {})", stream_id);
                        return Ok(());
                    }
                    Ok(n) => {
                        bytes_up += n as u64;
                        let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                        if let Err(e) = mux.send_to_device(stream_id, data) {
                            error!("Failed to send to device: {}", e);
                            return Err(Socks5Error::DeviceError(e));
                        }
                    }
                    Err(e) => {
                        error!("Error reading from SOCKS5 client: {}", e);
                        return Err(Socks5Error::IoError(e.to_string()));
                    }
                }
            }
        } => result,

        // Device -> Client
        result = async {
            loop {
                match socks5_rx.recv().await {
                    Some(data) => {
                        bytes_down += data.len() as u64;
                        if let Err(e) = socks5_write.write_all(&data).await {
                            error!("Error writing to SOCKS5 client: {}", e);
                            return Err(Socks5Error::IoError(e.to_string()));
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
        "SOCKS5 flow ended: stream_id={}, bytes_up={}, bytes_down={}",
        stream_id, bytes_up, bytes_down
    );

    // Close stream in multiplexer
    mux.close_stream(stream_id, &device_session.device_id);

    relay_result
}

/// SOCKS5 handshake: method selection
async fn handshake_methods(stream: &mut TcpStream, require_auth: bool) -> Result<u8, Socks5Error> {
    // Read: VER(1) | NMETHODS(1) | METHODS(NMETHODS)
    let mut buf = [0u8; 2];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Socks5Error::IoError(e.to_string()))?;

    let version = buf[0];
    let nmethods = buf[1] as usize;

    if version != SOCKS_VERSION {
        return Err(Socks5Error::UnsupportedVersion(version));
    }

    let mut methods = vec![0u8; nmethods];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|e| Socks5Error::IoError(e.to_string()))?;

    // Choose auth method
    let selected_method = if require_auth {
        if methods.contains(&AUTH_METHOD_USERNAME_PASSWORD) {
            AUTH_METHOD_USERNAME_PASSWORD
        } else {
            AUTH_METHOD_NO_ACCEPTABLE
        }
    } else if methods.contains(&AUTH_METHOD_NO_AUTH) {
        AUTH_METHOD_NO_AUTH
    } else {
        AUTH_METHOD_NO_ACCEPTABLE
    };

    // Send: VER(1) | METHOD(1)
    stream
        .write_all(&[SOCKS_VERSION, selected_method])
        .await
        .map_err(|e| Socks5Error::IoError(e.to_string()))?;

    if selected_method == AUTH_METHOD_NO_ACCEPTABLE {
        return Err(Socks5Error::NoAcceptableMethod);
    }

    Ok(selected_method)
}

/// SOCKS5 username/password authentication
async fn authenticate_user(stream: &mut TcpStream, db: &Database) -> Result<String, Socks5Error> {
    // Read: VER(1) | ULEN(1) | USERNAME(ULEN) | PLEN(1) | PASSWORD(PLEN)
    let mut buf = [0u8; 2];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Socks5Error::IoError(e.to_string()))?;

    let auth_version = buf[0];
    let ulen = buf[1] as usize;

    if auth_version != 0x01 {
        return Err(Socks5Error::InvalidAuthVersion(auth_version));
    }

    let mut username = vec![0u8; ulen];
    stream
        .read_exact(&mut username)
        .await
        .map_err(|e| Socks5Error::IoError(e.to_string()))?;

    let mut plen_buf = [0u8; 1];
    stream
        .read_exact(&mut plen_buf)
        .await
        .map_err(|e| Socks5Error::IoError(e.to_string()))?;
    let plen = plen_buf[0] as usize;

    let mut password = vec![0u8; plen];
    stream
        .read_exact(&mut password)
        .await
        .map_err(|e| Socks5Error::IoError(e.to_string()))?;

    let _username_str = String::from_utf8_lossy(&username);
    let password_str = String::from_utf8_lossy(&password);

    // For SOCKS5, we use API key as password (username can be anything or "api")
    let api_key = password_str.as_ref();

    match db.get_proxy_user_by_api_key(api_key) {
        Ok(Some(user)) => {
            debug!("SOCKS5 user authenticated: {}", user.email);
            // Send success: VER(1) | STATUS(1)
            stream
                .write_all(&[0x01, 0x00])
                .await
                .map_err(|e| Socks5Error::IoError(e.to_string()))?;
            Ok(user.id)
        }
        Ok(None) => {
            warn!("SOCKS5 authentication failed: invalid API key");
            // Send failure
            stream
                .write_all(&[0x01, 0x01])
                .await
                .map_err(|e| Socks5Error::IoError(e.to_string()))?;
            Err(Socks5Error::AuthenticationFailed)
        }
        Err(e) => {
            error!("Database error during SOCKS5 auth: {}", e);
            stream
                .write_all(&[0x01, 0x01])
                .await
                .map_err(|e| Socks5Error::IoError(e.to_string()))?;
            Err(Socks5Error::DatabaseError(e.to_string()))
        }
    }
}

/// Parse SOCKS5 request (CONNECT command)
async fn parse_request(stream: &mut TcpStream) -> Result<(String, u16), Socks5Error> {
    // Read: VER(1) | CMD(1) | RSV(1) | ATYP(1) | DST.ADDR | DST.PORT(2)
    let mut buf = [0u8; 4];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Socks5Error::IoError(e.to_string()))?;

    let version = buf[0];
    let cmd = buf[1];
    let atyp = buf[3];

    if version != SOCKS_VERSION {
        return Err(Socks5Error::UnsupportedVersion(version));
    }

    if cmd != CMD_CONNECT {
        return Err(Socks5Error::UnsupportedCommand(cmd));
    }

    // Parse destination address
    let host = match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream
                .read_exact(&mut addr)
                .await
                .map_err(|e| Socks5Error::IoError(e.to_string()))?;
            format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream
                .read_exact(&mut len_buf)
                .await
                .map_err(|e| Socks5Error::IoError(e.to_string()))?;
            let len = len_buf[0] as usize;

            let mut domain = vec![0u8; len];
            stream
                .read_exact(&mut domain)
                .await
                .map_err(|e| Socks5Error::IoError(e.to_string()))?;

            String::from_utf8(domain).map_err(|_| Socks5Error::InvalidDomain)?
        }
        ATYP_IPV6 => {
            // Read 16 bytes for IPv6
            let mut addr = [0u8; 16];
            stream
                .read_exact(&mut addr)
                .await
                .map_err(|e| Socks5Error::IoError(e.to_string()))?;
            format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]
            )
        }
        _ => return Err(Socks5Error::UnsupportedAddressType(atyp)),
    };

    // Read port
    let mut port_buf = [0u8; 2];
    stream
        .read_exact(&mut port_buf)
        .await
        .map_err(|e| Socks5Error::IoError(e.to_string()))?;
    let port = u16::from_be_bytes(port_buf);

    Ok((host, port))
}

/// Send SOCKS5 reply
async fn send_reply(stream: &mut TcpStream, reply_code: u8) -> Result<(), Socks5Error> {
    // Send: VER(1) | REP(1) | RSV(1) | ATYP(1) | BND.ADDR | BND.PORT(2)
    // For simplicity, use 0.0.0.0:0 as bind address
    let mut response = BytesMut::with_capacity(10);
    response.put_u8(SOCKS_VERSION);
    response.put_u8(reply_code);
    response.put_u8(0x00); // Reserved
    response.put_u8(ATYP_IPV4);
    response.put_u32(0); // 0.0.0.0
    response.put_u16(0); // Port 0

    stream
        .write_all(&response)
        .await
        .map_err(|e| Socks5Error::IoError(e.to_string()))?;

    Ok(())
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

/// Check if an IP address is private/reserved and should be blocked (SSRF protection)
fn is_ip_blocked(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback()             // 127.0.0.0/8
                || ipv4.is_private()        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || ipv4.is_link_local()     // 169.254.0.0/16
                || ipv4.is_unspecified()    // 0.0.0.0
                || ipv4.is_broadcast()      // 255.255.255.255
                || ipv4.octets()[0] == 100 && (ipv4.octets()[1] & 0xC0) == 64  // 100.64.0.0/10 (CGNAT)
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()             // ::1
                || ipv6.is_unspecified()   // ::
                || (ipv6.segments()[0] & 0xfe00) == 0xfc00  // fc00::/7 (ULA)
                || (ipv6.segments()[0] & 0xffc0) == 0xfe80  // fe80::/10 (link-local)
                // IPv4-mapped IPv6 (::ffff:x.x.x.x) — check the embedded IPv4
                || match ipv6.to_ipv4_mapped() {
                    Some(ipv4) => is_ip_blocked(&IpAddr::V4(ipv4)),
                    None => false,
                }
        }
    }
}

/// Check if a host is blocked (SSRF protection — blocks private IPs and reserved hostnames)
fn is_host_blocked(host: &str) -> bool {
    // Check if it's a direct IP address
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_ip_blocked(&ip);
    }

    // Block reserved hostnames
    let lower = host.to_lowercase();
    lower == "localhost"
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower.ends_with(".localhost")
}

#[derive(Debug, Error)]
pub enum Socks5Error {
    #[error("I/O error: {0}")]
    IoError(String),

    #[error("Unsupported SOCKS version: {0}")]
    UnsupportedVersion(u8),

    #[error("No acceptable authentication method")]
    NoAcceptableMethod,

    #[error("Invalid authentication version: {0}")]
    InvalidAuthVersion(u8),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Unsupported command: {0}")]
    UnsupportedCommand(u8),

    #[error("Unsupported address type: {0}")]
    UnsupportedAddressType(u8),

    #[error("Invalid domain name")]
    InvalidDomain,

    #[error("Port {0} is blocked")]
    PortBlocked(u16),

    #[error("Host blocked: {0}")]
    HostBlocked(String),

    #[error("No devices available")]
    NoDevicesAvailable,

    #[error("Device error: {0}")]
    DeviceError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Bind error: {0}")]
    BindError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // --- is_ip_blocked IPv4 ---

    #[test]
    fn blocks_loopback_v4() {
        assert!(is_ip_blocked(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_ip_blocked(&"127.0.0.1".parse().unwrap()));
        assert!(is_ip_blocked(&"127.255.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_rfc1918() {
        assert!(is_ip_blocked(&"10.0.0.1".parse().unwrap()));
        assert!(is_ip_blocked(&"10.255.255.255".parse().unwrap()));
        assert!(is_ip_blocked(&"172.16.0.1".parse().unwrap()));
        assert!(is_ip_blocked(&"172.31.255.255".parse().unwrap()));
        assert!(is_ip_blocked(&"192.168.0.1".parse().unwrap()));
        assert!(is_ip_blocked(&"192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_link_local_v4() {
        assert!(is_ip_blocked(&"169.254.0.1".parse().unwrap()));
        assert!(is_ip_blocked(&"169.254.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_unspecified_and_broadcast() {
        assert!(is_ip_blocked(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(is_ip_blocked(&IpAddr::V4(Ipv4Addr::BROADCAST)));
    }

    #[test]
    fn blocks_cgnat() {
        assert!(is_ip_blocked(&"100.64.0.1".parse().unwrap()));
        assert!(is_ip_blocked(&"100.127.255.255".parse().unwrap()));
        // Just outside CGNAT range
        assert!(!is_ip_blocked(&"100.128.0.0".parse().unwrap()));
        assert!(!is_ip_blocked(&"100.63.255.255".parse().unwrap()));
    }

    #[test]
    fn allows_public_v4() {
        assert!(!is_ip_blocked(&"8.8.8.8".parse().unwrap()));
        assert!(!is_ip_blocked(&"1.1.1.1".parse().unwrap()));
        assert!(!is_ip_blocked(&"93.184.216.34".parse().unwrap()));
    }

    // --- is_ip_blocked IPv6 ---

    #[test]
    fn blocks_loopback_v6() {
        assert!(is_ip_blocked(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn blocks_unspecified_v6() {
        assert!(is_ip_blocked(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn blocks_ula_v6() {
        assert!(is_ip_blocked(&"fc00::1".parse().unwrap()));
        assert!(is_ip_blocked(&"fd12:3456::1".parse().unwrap()));
    }

    #[test]
    fn blocks_link_local_v6() {
        assert!(is_ip_blocked(&"fe80::1".parse().unwrap()));
        assert!(is_ip_blocked(&"fe80::abcd:1234".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv4_mapped_v6() {
        // ::ffff:127.0.0.1
        assert!(is_ip_blocked(&"::ffff:127.0.0.1".parse().unwrap()));
        // ::ffff:192.168.1.1
        assert!(is_ip_blocked(&"::ffff:192.168.1.1".parse().unwrap()));
        // ::ffff:10.0.0.1
        assert!(is_ip_blocked(&"::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn allows_public_v6() {
        assert!(!is_ip_blocked(&"2606:4700::1111".parse().unwrap()));
        assert!(!is_ip_blocked(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn allows_public_ipv4_mapped_v6() {
        // ::ffff:8.8.8.8
        assert!(!is_ip_blocked(&"::ffff:8.8.8.8".parse().unwrap()));
    }

    // --- is_host_blocked ---

    #[test]
    fn blocks_localhost_hostname() {
        assert!(is_host_blocked("localhost"));
        assert!(is_host_blocked("LOCALHOST"));
        assert!(is_host_blocked("Localhost"));
    }

    #[test]
    fn blocks_reserved_tlds() {
        assert!(is_host_blocked("myhost.local"));
        assert!(is_host_blocked("service.internal"));
        assert!(is_host_blocked("app.localhost"));
        assert!(is_host_blocked("MYHOST.LOCAL"));
    }

    #[test]
    fn blocks_ip_strings() {
        assert!(is_host_blocked("127.0.0.1"));
        assert!(is_host_blocked("10.0.0.1"));
        assert!(is_host_blocked("192.168.1.1"));
        assert!(is_host_blocked("::1"));
    }

    #[test]
    fn allows_public_hostnames() {
        assert!(!is_host_blocked("example.com"));
        assert!(!is_host_blocked("google.com"));
        assert!(!is_host_blocked("ifconfig.me"));
    }

    #[test]
    fn does_not_false_positive_on_partial_matches() {
        // "local" as a suffix but not ".local"
        assert!(!is_host_blocked("notlocal"));
        assert!(!is_host_blocked("mylocal"));
        // contains "localhost" but isn't the hostname or a subdomain
        assert!(!is_host_blocked("notlocalhost.com"));
    }

    // --- is_port_blocked ---

    #[test]
    fn blocks_dangerous_ports() {
        assert!(is_port_blocked(25));
        assert!(is_port_blocked(3306));
        assert!(is_port_blocked(6379));
    }

    #[test]
    fn allows_standard_ports() {
        assert!(!is_port_blocked(80));
        assert!(!is_port_blocked(443));
        assert!(!is_port_blocked(8080));
    }
}
