//! Stream multiplexer for routing frames between SOCKS5 clients and devices
//!
//! The multiplexer maintains a registry of active streams and routes DATA/CLOSE/ERROR
//! frames bidirectionally between SOCKS5 handlers and device WebSocket connections.

use crate::protocol::{Frame, FrameType};
use bytes::Bytes;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

/// Unique identifier for a stream
pub type StreamId = u32;

/// A single proxied stream (SOCKS5 client <-> Device <-> TCP target)
pub struct Stream {
    pub stream_id: StreamId,
    pub device_id: String,
    /// Channel to send data back to SOCKS5 client
    pub socks5_sender: mpsc::UnboundedSender<Bytes>,
    /// Signal when stream is closed
    pub close_notify: Option<oneshot::Sender<()>>,
}

/// Central stream multiplexer
#[derive(Clone)]
pub struct StreamMultiplexer {
    /// Active streams: stream_id -> Stream
    streams: Arc<DashMap<StreamId, Stream>>,
    /// Device registry reference (to send frames to devices)
    device_registry: crate::device_ws::DeviceRegistry,
}

impl StreamMultiplexer {
    /// Create a new stream multiplexer
    pub fn new(device_registry: crate::device_ws::DeviceRegistry) -> Self {
        Self {
            streams: Arc::new(DashMap::new()),
            device_registry,
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
        // Allocate stream ID
        let stream_id = rand::random::<u32>();

        // Create ACK notification channel
        let (ack_tx, ack_rx) = oneshot::channel();

        // Store stream
        let stream = Stream {
            stream_id,
            device_id: device_id.to_string(),
            socks5_sender,
            close_notify: Some(ack_tx),
        };

        self.streams.insert(stream_id, stream);

        // Send OPEN frame to device
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
    ///
    /// Routes DATA frames to SOCKS5 client, handles CLOSE/ERROR
    pub fn handle_device_frame(&self, device_id: &str, frame: Frame) {
        let stream_id = frame.stream_id;

        match frame.frame_type {
            FrameType::Data => {
                // Check if this is an ACK for OPEN (empty DATA with ACK flag)
                if frame.flags.has_ack() && frame.payload.is_empty() {
                    debug!("Received OPEN ACK for stream {}", stream_id);
                    // Signal ACK received
                    if let Some((_, mut stream)) = self.streams.remove(&stream_id) {
                        if let Some(ack_tx) = stream.close_notify.take() {
                            let _ = ack_tx.send(());
                        }
                        // Re-insert stream without the ack_tx
                        self.streams.insert(
                            stream_id,
                            Stream {
                                stream_id: stream.stream_id,
                                device_id: stream.device_id,
                                socks5_sender: stream.socks5_sender,
                                close_notify: None,
                            },
                        );
                    }
                } else {
                    // Regular data - route to SOCKS5 client
                    if let Some(stream) = self.streams.get(&stream_id) {
                        if let Err(e) = stream.socks5_sender.send(frame.payload.clone()) {
                            error!("Failed to send data to SOCKS5 client: {}", e);
                            self.close_stream(stream_id, device_id);
                        } else {
                            debug!(
                                "Routed {} bytes from device to SOCKS5 (stream {})",
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
                info!("Device closed stream {}", stream_id);
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

    /// Send data from SOCKS5 client to device
    pub fn send_to_device(&self, stream_id: StreamId, data: Bytes) -> Result<(), String> {
        if let Some(stream) = self.streams.get(&stream_id) {
            let device_id = stream.device_id.clone();
            drop(stream); // Release the lock

            if let Some(device) = self.device_registry.get_device(&device_id) {
                let data_frame = Frame::data(stream_id, data.clone());
                device
                    .send_frame(data_frame)
                    .map_err(|e| format!("Failed to send DATA to device: {}", e))?;
                debug!(
                    "Sent {} bytes from SOCKS5 to device (stream {})",
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

    /// Close a stream
    pub fn close_stream(&self, stream_id: StreamId, device_id: &str) {
        if let Some((_, _stream)) = self.streams.remove(&stream_id) {
            // Send CLOSE frame to device
            if let Some(device) = self.device_registry.get_device(device_id) {
                let close_frame = Frame::close(stream_id);
                if let Err(e) = device.send_frame(close_frame) {
                    error!("Failed to send CLOSE to device: {}", e);
                }
            }

            info!("Closed stream {}", stream_id);
        }
    }

    /// Get number of active streams
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Get number of active streams for a specific device
    pub fn device_stream_count(&self, device_id: &str) -> usize {
        self.streams
            .iter()
            .filter(|entry| entry.value().device_id == device_id)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stream_lifecycle() {
        // This is a minimal test - full integration tests will be in main tests
        let db = crate::db::Database::open(":memory:").unwrap();
        let registry = crate::device_ws::DeviceRegistry::new(db);
        let mux = StreamMultiplexer::new(registry);

        assert_eq!(mux.stream_count(), 0);
    }
}
