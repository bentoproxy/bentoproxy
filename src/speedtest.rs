//! On-demand throughput measurement for one exit node.
//!
//! Deliberately never automatic. A node sits on someone's home connection, so
//! unrequested transfers would add traffic the owner did not ask for and give
//! their network a pattern to notice. Tests run only when an owner presses the
//! button for a device they own, and are rate limited.
//!
//! The target is Cloudflare's speed endpoint over plain HTTP: it looks like
//! ordinary Cloudflare traffic from the node's network, unlike a download from
//! a speedtest-branded host, and it avoids terminating TLS over a relayed
//! stream.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use tracing::{debug, info};

use crate::mux::StreamMultiplexer;

const TARGET_HOST: &str = "speed.cloudflare.com";
const TARGET_PORT: u16 = 80;
/// Default transfer size. Big enough to measure past TCP slow-start, small
/// enough not to be a burden on a home connection.
pub const DEFAULT_BYTES: u64 = 5 * 1024 * 1024;
/// Hard cap, so a request cannot ask a volunteer's node for a huge download.
pub const MAX_BYTES: u64 = 25 * 1024 * 1024;
/// Whole-test budget, including waiting for the node to open the connection.
const TEST_TIMEOUT: Duration = Duration::from_secs(30);
const ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// What a completed test measured.
#[derive(Debug, Clone)]
pub struct Measurement {
    pub bytes: u64,
    pub duration_ms: u64,
    /// Bytes per second over the transfer itself, excluding setup.
    pub down_bps: u64,
}

/// Download through `device_id` and measure the rate.
pub async fn run(mux: &StreamMultiplexer, device_id: &str, bytes: u64) -> Result<Measurement> {
    let bytes = bytes.clamp(1024, MAX_BYTES);
    info!("speed test on {device_id}: requesting {bytes} bytes");

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();

    let (stream_id, ack_rx) = mux
        .create_stream(device_id, TARGET_HOST, TARGET_PORT, tx)
        .await
        .map_err(|e| anyhow!("could not open a stream on {device_id}: {e}"))?;

    // Make sure the stream is closed however this function exits.
    let result = measure(mux, device_id, stream_id, ack_rx, &mut rx, bytes).await;
    mux.close_stream(stream_id, device_id);

    result
}

async fn measure(
    mux: &StreamMultiplexer,
    device_id: &str,
    stream_id: u32,
    ack_rx: tokio::sync::oneshot::Receiver<()>,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<Bytes>,
    bytes: u64,
) -> Result<Measurement> {
    tokio::time::timeout(ACK_TIMEOUT, ack_rx)
        .await
        .map_err(|_| anyhow!("{device_id} did not open the connection in time"))?
        .map_err(|_| anyhow!("{device_id} closed the connection while opening"))?;

    let request = format!(
        "GET /__down?bytes={bytes} HTTP/1.1\r\n\
         Host: {TARGET_HOST}\r\n\
         User-Agent: bentoproxy-speedtest/1\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\
         \r\n"
    );
    mux.send_to_device(stream_id, Bytes::from(request))
        .map_err(|e| anyhow!("could not send the request through {device_id}: {e}"))?;

    let mut received = 0u64;
    let mut header_bytes = 0u64;
    let mut headers_done = false;
    let mut pending = Vec::new();
    // Timed from the first byte back, so the measurement excludes DNS, the
    // TCP handshake and the node's own round trip.
    let mut first_byte_at: Option<Instant> = None;
    let deadline = Instant::now() + TEST_TIMEOUT;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(anyhow!("test timed out after {}s", TEST_TIMEOUT.as_secs()));
        }

        let chunk = match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(chunk)) => chunk,
            // The target closed the connection: that is the end of the body.
            Ok(None) => break,
            Err(_) if first_byte_at.is_none() => {
                // Connected, asked, heard nothing: the node's network let the
                // TCP handshake through but not the traffic, which is what a
                // captive portal or a port-80 block looks like from here.
                return Err(anyhow!(
                    "connected to {TARGET_HOST} but no data came back in {}s — \
                     this node's network may block or intercept port 80",
                    TEST_TIMEOUT.as_secs()
                ));
            }
            Err(_) => {
                return Err(anyhow!(
                    "transfer stalled after {} bytes",
                    received.saturating_sub(header_bytes)
                ))
            }
        };

        if first_byte_at.is_none() {
            first_byte_at = Some(Instant::now());
        }
        received += chunk.len() as u64;

        if !headers_done {
            // Headers are not payload; find their end to measure the body only.
            pending.extend_from_slice(&chunk);
            if let Some(position) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                header_bytes = (position + 4) as u64;
                headers_done = true;

                let status_line = String::from_utf8_lossy(&pending[..position.min(128)]);
                debug!("speed test response: {}", status_line.lines().next().unwrap_or(""));
                if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
                    return Err(anyhow!(
                        "target answered: {}",
                        status_line.lines().next().unwrap_or("unknown status")
                    ));
                }
                pending = Vec::new();
            } else if pending.len() > 16 * 1024 {
                return Err(anyhow!("no HTTP response headers from the target"));
            }
        }

        if headers_done && received - header_bytes >= bytes {
            break;
        }
    }

    let body = received.saturating_sub(header_bytes);
    let elapsed = first_byte_at
        .ok_or_else(|| anyhow!("no data came back through {device_id}"))?
        .elapsed();

    // A transfer too short to time would divide by ~0 and report nonsense.
    let duration_ms = elapsed.as_millis().max(1) as u64;
    if body < 1024 {
        return Err(anyhow!("only {body} bytes came back; the transfer failed"));
    }

    let down_bps = body * 1000 / duration_ms;
    info!(
        "speed test on {device_id}: {body} bytes in {duration_ms}ms ({} KB/s)",
        down_bps / 1024
    );

    Ok(Measurement {
        bytes: body,
        duration_ms,
        down_bps,
    })
}
