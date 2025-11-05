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
    db: Database,
}

impl DeviceRegistry {
    pub fn new(db: Database) -> Self {
        Self {
            devices: Arc::new(DashMap::new()),
            db,
        }
    }

    /// Get a connected device for proxying
    pub fn get_device(&self, device_id: &str) -> Option<DeviceSession> {
        self.devices.get(device_id).map(|entry| entry.value().clone())
    }

    /// Get first available active device (for MVP - simple round-robin later)
    pub fn get_any_device(&self) -> Option<DeviceSession> {
        self.devices.iter().next().map(|entry| entry.value().clone())
    }

    /// Register a connected device
    fn register(&self, device_id: String, session: DeviceSession) {
        self.devices.insert(device_id, session);
    }

    /// Unregister a disconnected device
    fn unregister(&self, device_id: &str) {
        self.devices.remove(device_id);
    }

    pub fn count(&self) -> usize {
        self.devices.len()
    }
}

/// Device session handle
#[derive(Clone)]
pub struct DeviceSession {
    pub device_id: String,
    pub sender: mpsc::UnboundedSender<Frame>,
    pub max_conns: usize,
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

    let (device_id, db_session_id) = match auth_timeout {
        Ok(Some(Ok(Message::Binary(data)))) => {
            match authenticate_device(&registry.db, Bytes::from(data)).await {
                Ok(Some((device_id, session_id))) => {
                    info!("Device authenticated: {}", device_id);

                    // Send AUTH acknowledgment (empty DATA frame with ACK flag)
                    let ack_frame = Frame::data_ack(0);
                    if let Err(e) = ws_sender.send(Message::Binary(ack_frame.to_bytes().to_vec())).await {
                        error!("Failed to send AUTH ACK: {}", e);
                        return;
                    }

                    (device_id, session_id)
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

    // Create device session
    let session = DeviceSession {
        device_id: device_id.clone(),
        sender: tx,
        max_conns: 8, // From DB, but hardcoded for MVP
    };

    // Register device in registry
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

    // Cleanup
    info!("Device disconnected: {}", device_id);
    registry.unregister(&device_id);

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
) -> Result<Option<(String, i64)>, ProtocolError> {
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

            // Start session in database
            match db.start_device_session(&device_id) {
                Ok(session_id) => Ok(Some((device_id, session_id))),
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
