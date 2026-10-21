//! Stream multiplexer for routing frames between SOCKS5 clients and devices
//!
//! The multiplexer maintains a registry of active streams and routes DATA/CLOSE/ERROR
//! frames bidirectionally between SOCKS5 handlers and device WebSocket connections.

use crate::protocol::{Frame, FrameType};
use bytes::Bytes;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

/// Unique identifier for a stream
pub type StreamId = u32;

/// How long a device has to acknowledge a new stream.
pub const ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Devices tried per connection before giving up on it.
const OPEN_ATTEMPTS: usize = 2;

/// Proxy username that pins a connection to one node: `api-node-<device_id>`.
/// Any other username (conventionally `api`) leaves the choice to the pool.
const NODE_USERNAME_PREFIX: &str = "api-node-";

/// The node a client asked for in its proxy username, if any.
pub fn requested_node(username: &str) -> Option<&str> {
    username
        .strip_prefix(NODE_USERNAME_PREFIX)
        .filter(|id| !id.is_empty())
}

/// Why a stream could not be opened.
#[derive(Debug)]
pub enum OpenError {
    /// No connected device has room for another stream.
    NoDevices,
    /// The node the client asked for is not connected, or is full.
    NodeUnavailable(String),
    /// The device refused, e.g. the target was unreachable from it.
    Rejected(String),
    /// Every device tried failed to acknowledge in time.
    Timeout,
    Other(String),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::NoDevices => write!(f, "No devices available"),
            OpenError::NodeUnavailable(id) => write!(f, "Requested node {id} is not available"),
            OpenError::Rejected(e) => write!(f, "Device ACK channel closed: {e}"),
            OpenError::Timeout => write!(f, "Device ACK timeout"),
            OpenError::Other(e) => write!(f, "{e}"),
        }
    }
}

/// A single proxied stream (SOCKS5 client <-> Device <-> TCP target)
pub struct Stream {
    pub stream_id: StreamId,
    pub device_id: String,
    /// Channel to send data back to SOCKS5/HTTP client
    pub socks5_sender: mpsc::UnboundedSender<Bytes>,
    /// Signal when stream is opened (ACK received)
    pub close_notify: Option<oneshot::Sender<()>>,
    /// When this stream was created
    pub created_at: Instant,
}

/// Central stream multiplexer
#[derive(Clone)]
pub struct StreamMultiplexer {
    /// Active streams: stream_id -> Stream
    streams: Arc<DashMap<StreamId, Stream>>,
    /// Device registry reference (to send frames to devices)
    device_registry: crate::device_ws::DeviceRegistry,
    /// Live per-device throughput, for the dashboard
    meters: crate::metrics::DeviceMeters,
}

impl StreamMultiplexer {
    /// Create a new stream multiplexer
    pub fn new(device_registry: crate::device_ws::DeviceRegistry) -> Self {
        Self::with_meters(device_registry, crate::metrics::DeviceMeters::new())
    }

    /// Create a multiplexer that reports throughput into shared meters.
    pub fn with_meters(
        device_registry: crate::device_ws::DeviceRegistry,
        meters: crate::metrics::DeviceMeters,
    ) -> Self {
        Self {
            streams: Arc::new(DashMap::new()),
            device_registry,
            meters,
        }
    }

    /// Open a stream to `host:port` on the best device, moving to another
    /// device if the first does not acknowledge in time.
    ///
    /// Only a missing ACK moves on: a device that answers with an error is
    /// working, and its error (usually the target refusing) is the answer.
    ///
    /// With `node` set the stream goes there or nowhere: a client that names
    /// a node needs that exit, and leaving from another would defeat it.
    pub async fn open_stream(
        &self,
        host: &str,
        port: u16,
        sender: mpsc::UnboundedSender<Bytes>,
        node: Option<&str>,
    ) -> Result<(crate::device_ws::DeviceSession, StreamId), OpenError> {
        let registry = &self.device_registry;

        if let Some(node) = node {
            let device = registry
                .get_device(node)
                .filter(|d| self.device_stream_count(&d.device_id) < d.max_conns)
                .ok_or_else(|| OpenError::NodeUnavailable(node.to_string()))?;
            return self.open_on(&device, host, port, sender).await;
        }

        let mut tried: Vec<String> = Vec::new();

        for _ in 0..OPEN_ATTEMPTS {
            let Some(device) = registry.get_best_device_excluding(self, &tried) else {
                break;
            };
            match self.open_on(&device, host, port, sender.clone()).await {
                Err(OpenError::Timeout) => tried.push(device.device_id),
                other => return other,
            }
        }

        if tried.is_empty() {
            Err(OpenError::NoDevices)
        } else {
            Err(OpenError::Timeout)
        }
    }

    /// Open a stream on one device and wait for it to acknowledge.
    async fn open_on(
        &self,
        device: &crate::device_ws::DeviceSession,
        host: &str,
        port: u16,
        sender: mpsc::UnboundedSender<Bytes>,
    ) -> Result<(crate::device_ws::DeviceSession, StreamId), OpenError> {
        let registry = &self.device_registry;
        let (stream_id, ack_rx) = self
            .create_stream(&device.device_id, host, port, sender)
            .await
            .map_err(OpenError::Other)?;

        match tokio::time::timeout(ACK_TIMEOUT, ack_rx).await {
            Ok(Ok(())) => {
                registry.report_open_success(&device.device_id);
                Ok((device.clone(), stream_id))
            }
            Ok(Err(_)) => {
                // Answered, but with an error: not the device's fault.
                self.remove_stream(stream_id);
                Err(OpenError::Rejected(format!("{host}:{port}")))
            }
            Err(_) => {
                registry.report_open_failure(&device.device_id);
                self.close_stream(stream_id, &device.device_id);
                Err(OpenError::Timeout)
            }
        }
    }

    /// Create a new stream and send OPEN frame to device
    ///
    /// Returns (stream_id, oneshot receiver for ACK)
    pub async fn create_stream(
        &self,
        device_id: &str,
        host: &str,
        port: u16,
        socks5_sender: mpsc::UnboundedSender<Bytes>,
    ) -> Result<(StreamId, oneshot::Receiver<()>), String> {
        let stream_id = rand::random::<u32>();
        let (ack_tx, ack_rx) = oneshot::channel();

        let stream = Stream {
            stream_id,
            device_id: device_id.to_string(),
            socks5_sender,
            close_notify: Some(ack_tx),
            created_at: Instant::now(),
        };

        self.streams.insert(stream_id, stream);

        let open_frame = Frame::open(stream_id, host, port);
        if let Some(device) = self.device_registry.get_device(device_id) {
            device
                .send_frame(open_frame)
                .map_err(|e| format!("Failed to send OPEN to device: {}", e))?;
            info!(
                "Created stream {} for device {} ({}:{})",
                stream_id, device_id, host, port
            );
            Ok((stream_id, ack_rx))
        } else {
            self.streams.remove(&stream_id);
            Err(format!("Device {} not connected", device_id))
        }
    }

    /// Handle a frame received from a device
    pub fn handle_device_frame(&self, device_id: &str, frame: Frame) {
        let stream_id = frame.stream_id;

        match frame.frame_type {
            FrameType::Data => {
                if frame.flags.has_ack() && frame.payload.is_empty() {
                    debug!("Received OPEN ACK for stream {}", stream_id);
                    // Fix Bug #2: update in-place instead of remove/reinsert
                    if let Some(mut entry) = self.streams.get_mut(&stream_id) {
                        if let Some(ack_tx) = entry.close_notify.take() {
                            let _ = ack_tx.send(());
                        }
                    }
                } else {
                    if let Some(stream) = self.streams.get(&stream_id) {
                        // Counted here rather than on flow completion: a long
                        // download should show up while it is running.
                        self.meters.record_down(device_id, frame.payload.len());

                        if let Err(e) = stream.socks5_sender.send(frame.payload.clone()) {
                            error!("Failed to send data to client: {}", e);
                            drop(stream); // Release DashMap read lock before close
                            self.close_stream(stream_id, device_id);
                        } else {
                            debug!(
                                "Routed {} bytes from device to client (stream {})",
                                frame.payload.len(),
                                stream_id
                            );
                        }
                    } else {
                        warn!(
                            "Received DATA for unknown stream {} from device {}",
                            stream_id, device_id
                        );
                    }
                }
            }

            FrameType::Close => {
                debug!("Device closed stream {}", stream_id);
                self.close_stream(stream_id, device_id);
            }

            FrameType::Error => {
                if let Ok(error_code) = frame.parse_error() {
                    error!(
                        "Device {} reported error {} for stream {}",
                        device_id, error_code, stream_id
                    );
                }
                self.close_stream(stream_id, device_id);
            }

            _ => {
                warn!(
                    "Unexpected frame type {:?} for stream {} from device {}",
                    frame.frame_type, stream_id, device_id
                );
            }
        }
    }

    /// Send data from client to device
    pub fn send_to_device(&self, stream_id: StreamId, data: Bytes) -> Result<(), String> {
        if let Some(stream) = self.streams.get(&stream_id) {
            let device_id = stream.device_id.clone();
            drop(stream); // Release the lock

            if let Some(device) = self.device_registry.get_device(&device_id) {
                let data_frame = Frame::data(stream_id, data.clone());
                device
                    .send_frame(data_frame)
                    .map_err(|e| format!("Failed to send DATA to device: {}", e))?;
                self.meters.record_up(&device_id, data.len());
                debug!(
                    "Sent {} bytes from client to device (stream {})",
                    data.len(),
                    stream_id
                );
                Ok(())
            } else {
                Err(format!("Device {} not connected", device_id))
            }
        } else {
            Err(format!("Stream {} not found", stream_id))
        }
    }

    /// Close and remove a stream
    pub fn close_stream(&self, stream_id: StreamId, device_id: &str) {
        if let Some((_, _stream)) = self.streams.remove(&stream_id) {
            // Dropping _stream drops the socks5_sender, which causes
            // the relay loop's recv() to return None and exit cleanly.
            if let Some(device) = self.device_registry.get_device(device_id) {
                let close_frame = Frame::close(stream_id);
                if let Err(e) = device.send_frame(close_frame) {
                    error!("Failed to send CLOSE to device: {}", e);
                }
            }
            debug!("Closed stream {}", stream_id);
        }
    }

    /// Remove a stream without sending CLOSE to device (used when relay loop exits)
    pub fn remove_stream(&self, stream_id: StreamId) {
        if self.streams.remove(&stream_id).is_some() {
            debug!("Removed stream {} (relay exited)", stream_id);
        }
    }

    /// Get number of active streams
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Get number of active streams for a specific device
    /// Fix Bug #4: collect device IDs first to avoid nested DashMap locks
    pub fn device_stream_count(&self, device_id: &str) -> usize {
        self.streams
            .iter()
            .filter(|entry| entry.value().device_id == device_id)
            .count()
    }

    /// Remove all streams belonging to a device (called on device disconnect)
    pub fn close_all_device_streams(&self, device_id: &str) -> usize {
        let stream_ids: Vec<StreamId> = self
            .streams
            .iter()
            .filter(|entry| entry.value().device_id == device_id)
            .map(|entry| *entry.key())
            .collect();
        let count = stream_ids.len();
        for id in stream_ids {
            // Removing drops the socks5_sender, causing relay loops to exit
            self.streams.remove(&id);
        }
        if count > 0 {
            info!("Cleaned up {} orphaned streams for device {}", count, device_id);
        }
        count
    }

    /// Periodic cleanup: remove streams with dead senders or that exceeded max age.
    /// Returns number of streams removed.
    pub fn cleanup_stale_streams(&self, max_age_secs: u64) -> usize {
        let now = Instant::now();
        let mut removed = 0;

        let stale_ids: Vec<(StreamId, String)> = self
            .streams
            .iter()
            .filter(|entry| {
                let stream = entry.value();
                // Dead sender (client disconnected but stream wasn't cleaned up)
                stream.socks5_sender.is_closed()
                    // Or stream exceeded max age (hung connection)
                    || now.duration_since(stream.created_at).as_secs() > max_age_secs
            })
            .map(|entry| (*entry.key(), entry.value().device_id.clone()))
            .collect();

        for (stream_id, device_id) in stale_ids {
            if let Some((_, _stream)) = self.streams.remove(&stream_id) {
                // Send CLOSE to device for stale streams
                if let Some(device) = self.device_registry.get_device(&device_id) {
                    let _ = device.send_frame(Frame::close(stream_id));
                }
                removed += 1;
            }
        }

        if removed > 0 {
            info!(
                "Cleaned up {} stale streams ({} remaining)",
                removed,
                self.streams.len()
            );
        }

        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stream_lifecycle() {
        let db = crate::db::Database::open(":memory:").unwrap();
        let registry = crate::device_ws::DeviceRegistry::new(db);
        let mux = StreamMultiplexer::new(registry);

        assert_eq!(mux.stream_count(), 0);
    }
}
