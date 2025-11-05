//! Device Simulator - Simulates an ESP32 device node
//!
//! This simulator connects to the orchestrator via WebSocket, authenticates,
//! and handles proxy streams by creating real TCP connections to target hosts.
//!
//! Usage:
//!   cargo run --example device_simulator -- --device-id <id> --token <token> [--url ws://localhost:8002/ws/device]

use bentoproxy_orchestrator::protocol::{Frame, FrameType};
use bytes::Bytes;
use clap::Parser;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, info, warn};

#[derive(Parser)]
#[command(name = "device-simulator")]
#[command(about = "Simulates a BentoProxy ESP32 device node")]
struct Args {
    /// Device ID
    #[arg(short, long)]
    device_id: String,

    /// Authentication token
    #[arg(short, long)]
    token: String,

    /// Orchestrator WebSocket URL
    #[arg(short, long, default_value = "ws://localhost:8002/ws/device")]
    url: String,
}

/// Active TCP stream for a proxied connection
struct ProxyStream {
    tcp_write: tokio::net::tcp::OwnedWriteHalf,
    sender: mpsc::UnboundedSender<Frame>,
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,device_simulator=debug".into()),
        )
        .init();

    let args = Args::parse();

    info!("Device Simulator starting");
    info!("Device ID: {}", args.device_id);
    info!("Connecting to: {}", args.url);

    loop {
        match run_device(&args).await {
            Ok(()) => {
                info!("Device connection closed normally");
                break;
            }
            Err(e) => {
                error!("Device error: {}", e);
                info!("Reconnecting in 5 seconds...");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    }
}

async fn run_device(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    // Connect to orchestrator
    let (ws_stream, _) = connect_async(&args.url).await?;
    info!("WebSocket connected");

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // Send AUTH frame
    let auth_frame = Frame::auth(&args.device_id, &args.token);
    ws_sender
        .send(Message::Binary(auth_frame.to_bytes().to_vec()))
        .await?;
    info!("Sent AUTH frame");

    // Wait for AUTH ACK (DATA frame with stream_id=0, ACK flag, empty payload)
    match ws_receiver.next().await {
        Some(Ok(Message::Binary(data))) => {
            let frame = Frame::from_bytes(Bytes::from(data))?;
            if frame.frame_type == FrameType::Data
                && frame.stream_id == 0
                && frame.flags.has_ack()
                && frame.payload.is_empty()
            {
                info!("Received AUTH ACK - device authenticated!");
            } else {
                return Err(format!("Expected AUTH ACK, got {:?}", frame.frame_type).into());
            }
        }
        Some(Ok(msg)) => {
            return Err(format!("Expected binary AUTH ACK, got {:?}", msg).into());
        }
        Some(Err(e)) => return Err(e.into()),
        None => return Err("WebSocket closed before AUTH ACK".into()),
    }

    // Create channel for sending frames to orchestrator
    let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<Frame>();

    // Map of active streams: stream_id -> ProxyStream
    let streams: Arc<DashMap<u32, ProxyStream>> = Arc::new(DashMap::new());

    // Spawn task to send frames to orchestrator
    let send_task = tokio::spawn(async move {
        while let Some(frame) = frame_rx.recv().await {
            debug!("Sending frame: type={:?}, stream_id={}", frame.frame_type, frame.stream_id);
            if let Err(e) = ws_sender.send(Message::Binary(frame.to_bytes().to_vec())).await {
                error!("Failed to send frame: {}", e);
                break;
            }
        }
        info!("Send task ending");
    });

    // Spawn task to receive frames from orchestrator
    let streams_recv = streams.clone();
    let frame_tx_clone = frame_tx.clone();
    let recv_task = tokio::spawn(async move {
        while let Some(result) = ws_receiver.next().await {
            match result {
                Ok(Message::Binary(data)) => {
                    match Frame::from_bytes(Bytes::from(data)) {
                        Ok(frame) => {
                            match frame.frame_type {
                                FrameType::Open => {
                                    debug!("Received OPEN for stream {}", frame.stream_id);
                                    handle_open(frame, &streams_recv, frame_tx_clone.clone()).await;
                                }
                                FrameType::Data => {
                                    debug!(
                                        "Received DATA for stream {} ({} bytes)",
                                        frame.stream_id,
                                        frame.payload.len()
                                    );
                                    handle_data(frame, &streams_recv).await;
                                }
                                FrameType::Close => {
                                    debug!("Received CLOSE for stream {}", frame.stream_id);
                                    handle_close(frame.stream_id, &streams_recv).await;
                                }
                                FrameType::Ping => {
                                    debug!("Received PING");
                                    // Pings are implicit, no response needed
                                }
                                _ => {
                                    warn!("Unexpected frame type: {:?}", frame.frame_type);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to parse frame: {}", e);
                        }
                    }
                }
                Ok(Message::Close(_)) => {
                    info!("Orchestrator closed WebSocket");
                    break;
                }
                Ok(_) => {
                    warn!("Received non-binary message");
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    break;
                }
            }
        }
        info!("Receive task ending");
    });

    // Wait for either task to complete
    tokio::select! {
        _ = send_task => {
            info!("Send task completed");
        }
        _ = recv_task => {
            info!("Receive task completed");
        }
    }

    Ok(())
}

/// Handle OPEN frame - create TCP connection to target
async fn handle_open(
    frame: Frame,
    streams: &Arc<DashMap<u32, ProxyStream>>,
    frame_tx: mpsc::UnboundedSender<Frame>,
) {
    let stream_id = frame.stream_id;

    // Parse host and port
    let (host, port) = match frame.parse_open() {
        Ok((h, p)) => (h, p),
        Err(e) => {
            error!("Failed to parse OPEN frame: {}", e);
            let _ = frame_tx.send(Frame::error(stream_id, 1));
            return;
        }
    };

    info!("Opening TCP connection to {}:{} (stream {})", host, port, stream_id);

    // Create TCP connection
    match TcpStream::connect(format!("{}:{}", host, port)).await {
        Ok(tcp_stream) => {
            info!("Connected to {}:{} (stream {})", host, port, stream_id);

            // Split TCP stream into read and write halves to avoid lock contention
            let (tcp_read, tcp_write) = tcp_stream.into_split();

            // Send ACK (empty DATA frame with ACK flag)
            let ack_frame = Frame::data_ack(stream_id);
            if let Err(e) = frame_tx.send(ack_frame) {
                error!("Failed to send OPEN ACK: {}", e);
                return;
            }

            // Store write half in map
            streams.insert(
                stream_id,
                ProxyStream {
                    tcp_write,
                    sender: frame_tx.clone(),
                },
            );

            // Spawn task to read from TCP (owns the read half, no lock needed!)
            let streams_read = streams.clone();
            let sender = frame_tx.clone();
            tokio::spawn(async move {
                let mut tcp_read = tcp_read;
                let mut buf = vec![0u8; 8192];

                loop {
                    match tcp_read.read(&mut buf).await {
                        Ok(0) => {
                            debug!("TCP connection closed (stream {})", stream_id);
                            let _ = sender.send(Frame::close(stream_id));
                            break;
                        }
                        Ok(n) => {
                            let data = Bytes::copy_from_slice(&buf[..n]);
                            debug!("Read {} bytes from TCP (stream {})", n, stream_id);
                            if let Err(e) = sender.send(Frame::data(stream_id, data)) {
                                error!("Failed to send DATA frame: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Error reading from TCP (stream {}): {}", stream_id, e);
                            let _ = sender.send(Frame::error(stream_id, 2));
                            break;
                        }
                    }
                }

                // Remove stream from map
                streams_read.remove(&stream_id);
                info!("Stream {} closed", stream_id);
            });
        }
        Err(e) => {
            error!("Failed to connect to {}:{}: {}", host, port, e);
            let _ = frame_tx.send(Frame::error(stream_id, 1));
        }
    }
}

/// Handle DATA frame - write to TCP connection
async fn handle_data(frame: Frame, streams: &Arc<DashMap<u32, ProxyStream>>) {
    let stream_id = frame.stream_id;

    if let Some(mut entry) = streams.get_mut(&stream_id) {
        match entry.tcp_write.write_all(&frame.payload).await {
            Ok(()) => {
                debug!("Wrote {} bytes to TCP (stream {})", frame.payload.len(), stream_id);
            }
            Err(e) => {
                error!("Error writing to TCP (stream {}): {}", stream_id, e);
                let _ = entry.sender.send(Frame::error(stream_id, 3));
                streams.remove(&stream_id);
            }
        }
    } else {
        warn!("Received DATA for unknown stream {}", stream_id);
    }
}

/// Handle CLOSE frame - close TCP connection
async fn handle_close(stream_id: u32, streams: &Arc<DashMap<u32, ProxyStream>>) {
    if let Some((_, _stream)) = streams.remove(&stream_id) {
        info!("Closed stream {} (TCP connection will drop)", stream_id);
    } else {
        warn!("Received CLOSE for unknown stream {}", stream_id);
    }
}
