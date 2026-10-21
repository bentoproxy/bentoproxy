use crate::{db::Database, protocol::{Frame, FrameType, ProtocolError}};
use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::Response,
};
use bytes::Bytes;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Shared state for device registry
#[derive(Clone)]
pub struct DeviceRegistry {
    devices: Arc<DashMap<String, DeviceSession>>,
    /// Devices that recently failed to open a stream: when they may be
    /// tried again, and how many failures in a row led there.
    benched: Arc<DashMap<String, (Instant, u32)>>,
    db: Database,
}

/// First bench after a failed open; doubles per further failure in a row.
const BENCH_BASE: Duration = Duration::from_secs(15);
const BENCH_MAX: Duration = Duration::from_secs(300);

impl DeviceRegistry {
    pub fn new(db: Database) -> Self {
        Self {
            devices: Arc::new(DashMap::new()),
            benched: Arc::new(DashMap::new()),
            db,
        }
    }

    /// Get a connected device for proxying
    pub fn get_device(&self, device_id: &str) -> Option<DeviceSession> {
        self.devices.get(device_id).map(|entry| entry.value().clone())
    }

    /// Get device with fewest active streams that still has capacity (least-connections routing)
    pub fn get_best_device(&self, mux: &crate::mux::StreamMultiplexer) -> Option<DeviceSession> {
        self.get_best_device_excluding(mux, &[])
    }

    /// Least-connections choice among devices not in `exclude`.
    ///
    /// Benched devices are passed over while any other device has room, but
    /// still used when nothing else does: a flaky node beats no node.
    pub fn get_best_device_excluding(
        &self,
        mux: &crate::mux::StreamMultiplexer,
        exclude: &[String],
    ) -> Option<DeviceSession> {
        let now = Instant::now();
        self.devices
            .iter()
            .map(|entry| {
                let device = entry.value().clone();
                let count = mux.device_stream_count(&device.device_id);
                let benched = self
                    .benched
                    .get(&device.device_id)
                    .is_some_and(|b| b.0 > now);
                (device, count, benched)
            })
            .filter(|(device, count, _)| {
                // Reserved nodes are never part of the pool, not even when
                // everything else is busy: their exit is kept for one use.
                !device.reserved
                    && *count < device.max_conns
                    && !exclude.contains(&device.device_id)
            })
            .min_by_key(|(_, count, benched)| (*benched, *count))
            .map(|(device, _, _)| device)
    }

    /// A device did not acknowledge a new stream in time: route around it.
    ///
    /// Nodes on home and coworking networks drop out for minutes at a time
    /// while staying connected, and least-connections routing kept handing
    /// them new streams, so the scraper's health check failed and it paused
    /// for half an hour although another node was fine.
    pub fn report_open_failure(&self, device_id: &str) {
        let mut entry = self
            .benched
            .entry(device_id.to_string())
            .or_insert((Instant::now(), 0));
        let failures = entry.1 + 1;
        let bench = (BENCH_BASE * 2u32.saturating_pow(failures - 1)).min(BENCH_MAX);
        *entry = (Instant::now() + bench, failures);
        warn!(
            "Device {} failed to open a stream ({} in a row); benched for {}s",
            device_id,
            failures,
            bench.as_secs()
        );
    }

    /// A device opened a stream: whatever was wrong has passed.
    pub fn report_open_success(&self, device_id: &str) {
        if let Some((_, (_, failures))) = self.benched.remove(device_id) {
            info!("Device {} is opening streams again after {} failures", device_id, failures);
        }
    }

    /// Register a connected device
    fn register(&self, device_id: String, session: DeviceSession) {
        self.devices.insert(device_id, session);
    }

    /// Unregister a disconnected device, but only if the session_nonce matches
    /// (prevents a stale cleanup from removing a newer reconnected session)
    fn unregister(&self, device_id: &str, session_nonce: u64) {
        self.devices.remove_if(device_id, |_, session| {
            session.session_nonce == session_nonce
        });
    }

    /// Drop a device's session so nothing is routed to it any more.
    ///
    /// Its socket stays open until the next write fails, which is enough: a
    /// deleted device can no longer authenticate, so it never comes back.
    pub fn forget(&self, device_id: &str) -> bool {
        self.devices.remove(device_id).is_some()
    }

    pub fn count(&self) -> usize {
        self.devices.len()
    }
}

/// Upper bound on a capacity a device may declare for itself.
const MAX_DECLARED_STREAMS: usize = 512;

/// Device session handle
#[derive(Clone)]
pub struct DeviceSession {
    pub device_id: String,
    pub sender: mpsc::UnboundedSender<Frame>,
    pub max_conns: usize,
    pub session_nonce: u64,
    /// Only for traffic that names this node; never chosen for the pool.
    pub reserved: bool,
}

impl DeviceSession {
    pub fn send_frame(&self, frame: Frame) -> Result<(), String> {
        self.sender
            .send(frame)
            .map_err(|e| format!("Failed to send frame: {}", e))
    }
}

/// Handle WebSocket upgrade for devices
pub async fn handle_upgrade(
    ws: WebSocketUpgrade,
    State(app_state): State<crate::web::handlers::AppState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_device_connection(socket, app_state.registry, app_state.mux))
}

/// Handle individual device WebSocket connection
async fn handle_device_connection(socket: WebSocket, registry: DeviceRegistry, mux: crate::mux::StreamMultiplexer) {
    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Wait for AUTH frame (with timeout)
    let auth_timeout = tokio::time::timeout(Duration::from_secs(30), ws_receiver.next()).await;

    let (device_id, db_session_id, max_conns, reserved) = match auth_timeout {
        Ok(Some(Ok(Message::Binary(data)))) => {
            match authenticate_device(&registry.db, Bytes::from(data)).await {
                Ok(Some((device_id, session_id, max_conns, reserved))) => {
                    info!(
                        "Device authenticated: {} (max_conns={}{})",
                        device_id,
                        max_conns,
                        if reserved { ", reserved" } else { "" }
                    );

                    // Send AUTH acknowledgment (empty DATA frame with ACK flag)
                    let ack_frame = Frame::data_ack(0);
                    if let Err(e) = ws_sender.send(Message::Binary(ack_frame.to_bytes().to_vec())).await {
                        error!("Failed to send AUTH ACK: {}", e);
                        return;
                    }

                    (device_id, session_id, max_conns, reserved)
                }
                Ok(None) => {
                    warn!("Device authentication failed: invalid credentials");
                    let _ = ws_sender.close().await;
                    return;
                }
                Err(e) => {
                    error!("Device authentication error: {}", e);
                    let _ = ws_sender.close().await;
                    return;
                }
            }
        }
        Ok(Some(Ok(_))) => {
            warn!("Expected binary AUTH frame, got other message type");
            let _ = ws_sender.close().await;
            return;
        }
        Ok(Some(Err(e))) => {
            error!("WebSocket error during auth: {}", e);
            return;
        }
        Ok(None) => {
            warn!("WebSocket closed before auth");
            return;
        }
        Err(_) => {
            warn!("Device authentication timeout");
            let _ = ws_sender.close().await;
            return;
        }
    };

    // Create channel for sending frames to device
    let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();

    // Unique nonce for this session — used to prevent stale cleanup from
    // removing a newer reconnected session
    let session_nonce: u64 = rand::random();

    // Create device session
    let session = DeviceSession {
        device_id: device_id.clone(),
        sender: tx,
        max_conns,
        session_nonce,
        reserved,
    };

    // Register device in registry (replaces any previous session)
    registry.register(device_id.clone(), session);

    info!("Device session started: {}", device_id);

    // Update last seen
    if let Err(e) = registry.db.update_device_last_seen(&device_id) {
        error!("Failed to update device last_seen: {}", e);
    }

    // Spawn task to send frames to device
    let device_id_sender = device_id.clone();
    let mut send_task = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            debug!("Sending frame to device {}: {:?}", device_id_sender, frame.frame_type);
            let bytes = frame.to_bytes();
            if let Err(e) = ws_sender.send(Message::Binary(bytes.to_vec())).await {
                error!("Failed to send frame to device {}: {}", device_id_sender, e);
                break;
            }
        }
    });

    // Spawn task to receive frames from device
    let device_id_receiver = device_id.clone();
    let _db = registry.db.clone();
    let mux_recv = mux.clone();
    let mut recv_task = tokio::spawn(async move {
        let mut last_ping = Instant::now();

        while let Some(result) = ws_receiver.next().await {
            match result {
                Ok(Message::Binary(data)) => {
                    match Frame::from_bytes(Bytes::from(data)) {
                        Ok(frame) => {
                            match frame.frame_type {
                                FrameType::Ping => {
                                    debug!("Received PING from device {}", device_id_receiver);
                                    last_ping = Instant::now();
                                    // Pings are handled implicitly, no response needed
                                }
                                FrameType::Data => {
                                    // Device is sending data for a stream
                                    debug!(
                                        "Received DATA from device {} for stream {} ({} bytes)",
                                        device_id_receiver, frame.stream_id, frame.payload.len()
                                    );
                                    mux_recv.handle_device_frame(&device_id_receiver, frame);
                                }
                                FrameType::Close => {
                                    debug!(
                                        "Received CLOSE from device {} for stream {}",
                                        device_id_receiver, frame.stream_id
                                    );
                                    mux_recv.handle_device_frame(&device_id_receiver, frame);
                                }
                                FrameType::Error => {
                                    if let Ok(error_code) = frame.parse_error() {
                                        warn!(
                                            "Received ERROR from device {} for stream {}: code {}",
                                            device_id_receiver, frame.stream_id, error_code
                                        );
                                    }
                                    mux_recv.handle_device_frame(&device_id_receiver, frame);
                                }
                                _ => {
                                    warn!(
                                        "Unexpected frame type from device {}: {:?}",
                                        device_id_receiver, frame.frame_type
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to parse frame from device {}: {}", device_id_receiver, e);
                        }
                    }
                }
                Ok(Message::Close(_)) => {
                    info!("Device {} sent close frame", device_id_receiver);
                    break;
                }
                Ok(_) => {
                    warn!("Received non-binary message from device {}", device_id_receiver);
                }
                Err(e) => {
                    error!("WebSocket error from device {}: {}", device_id_receiver, e);
                    break;
                }
            }

            // Check for timeout (no ping in 90s)
            if last_ping.elapsed() > Duration::from_secs(90) {
                warn!("Device {} timed out (no ping)", device_id_receiver);
                break;
            }
        }

        debug!("Device {} receive loop ended", device_id_receiver);
    });

    // Spawn keepalive task (send PING every 30s)
    let device_id_keepalive = device_id.clone();
    let registry_keepalive = registry.clone();
    let mut keepalive_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Some(session) = registry_keepalive.get_device(&device_id_keepalive) {
                debug!("Sending PING to device {}", device_id_keepalive);
                if session.send_frame(Frame::ping()).is_err() {
                    error!("Failed to send PING to device {}", device_id_keepalive);
                    break;
                }
            } else {
                // Device no longer in registry
                break;
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = &mut send_task => {
            debug!("Send task completed for device {}", device_id);
        }
        _ = &mut recv_task => {
            debug!("Receive task completed for device {}", device_id);
        }
        _ = &mut keepalive_task => {
            debug!("Keepalive task completed for device {}", device_id);
        }
    }

    // Cleanup — only unregister if this is still OUR session (not a newer reconnection)
    info!("Device disconnected: {}", device_id);
    mux.close_all_device_streams(&device_id);
    registry.unregister(&device_id, session_nonce);

    // End database session
    if let Err(e) = registry.db.end_device_session(db_session_id, Some("disconnect")) {
        error!("Failed to end device session: {}", e);
    }

    // Abort other tasks
    send_task.abort();
    recv_task.abort();
    keepalive_task.abort();
}

/// Authenticate device from AUTH frame
async fn authenticate_device(
    db: &Database,
    data: Bytes,
) -> Result<Option<(String, i64, usize, bool)>, ProtocolError> {
    let frame = Frame::from_bytes(data)?;

    if frame.frame_type != FrameType::Auth {
        return Ok(None);
    }

    let (device_id, token) = frame.parse_auth()?;

    // Check credentials in database
    match db.authenticate_device(&device_id, &token) {
        Ok(Some(device)) => {
            if !device.is_active {
                warn!("Device {} is not active", device_id);
                return Ok(None);
            }

            // A node that declares its capacity knows it better than the
            // database default, which was set by hand per device. Clamped,
            // since the value comes from the device: overclaiming would only
            // overload that owner's node, but it should not be able to ask
            // for an unbounded share of traffic.
            let max_conns = match frame.parse_auth_capabilities() {
                Some(caps) => {
                    let declared = (caps.max_streams as usize).clamp(1, MAX_DECLARED_STREAMS);
                    info!(
                        "Device {} declares {:?} with capacity {} (database had {})",
                        device_id, caps.kind, declared, device.max_conns
                    );
                    declared
                }
                None => device.max_conns.max(1) as usize,
            };

            // Start session in database
            match db.start_device_session(&device_id) {
                Ok(session_id) => Ok(Some((device_id, session_id, max_conns, device.reserved))),
                Err(e) => {
                    error!("Failed to start device session: {}", e);
                    Ok(None)
                }
            }
        }
        Ok(None) => Ok(None),
        Err(e) => {
            error!("Database error during device authentication: {}", e);
            Ok(None)
        }
    }
}
