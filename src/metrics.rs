//! Live per-device throughput counters.
//!
//! The flows table records bytes only when a flow ends, so a long transfer is
//! invisible while it is happening — no use for a dashboard that should show
//! what a node is doing right now. Counting in memory keeps the proxy's hot
//! path free of database writes; the flows table remains the record for
//! history and billing.
//!
//! Each device gets a ring of per-second buckets, so a rate is a sum over the
//! last N buckets. Reads take no sample and reset nothing, which means several
//! dashboards can poll the same device without stealing each other's window.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use serde::Serialize;

/// Seconds of history kept per device. One minute is enough for a live
/// reading and costs 16 bytes per second per device.
const WINDOW_SECS: usize = 60;

/// Bytes relayed in one second, in each direction.
#[derive(Default)]
struct Bucket {
    /// Unix second this bucket holds, so stale buckets can be ignored rather
    /// than cleared by a timer.
    second: AtomicU64,
    up: AtomicU64,
    down: AtomicU64,
}

#[derive(Default)]
struct DeviceCounters {
    total_up: AtomicU64,
    total_down: AtomicU64,
    buckets: Vec<Bucket>,
}

impl DeviceCounters {
    fn new() -> Self {
        Self {
            total_up: AtomicU64::new(0),
            total_down: AtomicU64::new(0),
            buckets: (0..WINDOW_SECS).map(|_| Bucket::default()).collect(),
        }
    }

    fn add(&self, up: u64, down: u64) {
        self.total_up.fetch_add(up, Ordering::Relaxed);
        self.total_down.fetch_add(down, Ordering::Relaxed);

        let now = unix_secs();
        let bucket = &self.buckets[(now as usize) % WINDOW_SECS];

        // A bucket holding a different second is a whole window old: take it
        // over rather than adding to someone else's total.
        if bucket.second.swap(now, Ordering::Relaxed) != now {
            bucket.up.store(up, Ordering::Relaxed);
            bucket.down.store(down, Ordering::Relaxed);
        } else {
            bucket.up.fetch_add(up, Ordering::Relaxed);
            bucket.down.fetch_add(down, Ordering::Relaxed);
        }
    }

    /// Bytes per second over the last `window` seconds, ignoring the current
    /// second because it is still filling.
    fn rate(&self, window: u64) -> (u64, u64) {
        let now = unix_secs();
        let oldest = now.saturating_sub(window);

        let (mut up, mut down) = (0u64, 0u64);
        for bucket in &self.buckets {
            let second = bucket.second.load(Ordering::Relaxed);
            if second >= oldest && second < now {
                up += bucket.up.load(Ordering::Relaxed);
                down += bucket.down.load(Ordering::Relaxed);
            }
        }

        (up / window, down / window)
    }
}

/// Throughput for one device at a moment in time.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Snapshot {
    /// Bytes per second, averaged over the last 10 seconds.
    pub up_bps: u64,
    pub down_bps: u64,
    /// Bytes per second, averaged over the last minute.
    pub up_bps_1m: u64,
    pub down_bps_1m: u64,
    /// Totals since the orchestrator started.
    pub total_up: u64,
    pub total_down: u64,
}

/// Live counters for every device, shared across the proxy and the dashboard.
#[derive(Clone, Default)]
pub struct DeviceMeters {
    devices: Arc<DashMap<String, DeviceCounters>>,
}

impl DeviceMeters {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes sent to a device, on their way to the target.
    pub fn record_up(&self, device_id: &str, bytes: usize) {
        self.record(device_id, bytes as u64, 0);
    }

    /// Bytes received from a device, on their way back to the client.
    pub fn record_down(&self, device_id: &str, bytes: usize) {
        self.record(device_id, 0, bytes as u64);
    }

    fn record(&self, device_id: &str, up: u64, down: u64) {
        if let Some(counters) = self.devices.get(device_id) {
            counters.add(up, down);
            return;
        }

        // First traffic for this device; the entry may already exist by the
        // time we insert, which entry() resolves for us.
        self.devices
            .entry(device_id.to_string())
            .or_insert_with(DeviceCounters::new)
            .add(up, down);
    }

    pub fn snapshot(&self, device_id: &str) -> Snapshot {
        let Some(counters) = self.devices.get(device_id) else {
            return Snapshot::default();
        };

        let (up_bps, down_bps) = counters.rate(10);
        let (up_bps_1m, down_bps_1m) = counters.rate(60);

        Snapshot {
            up_bps,
            down_bps,
            up_bps_1m,
            down_bps_1m,
            total_up: counters.total_up.load(Ordering::Relaxed),
            total_down: counters.total_down.load(Ordering::Relaxed),
        }
    }

    /// Forget a device's counters, for one that has been deleted.
    #[allow(dead_code)]
    pub fn forget(&self, device_id: &str) {
        self.devices.remove(device_id);
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_accumulate_in_both_directions() {
        let meters = DeviceMeters::new();
        meters.record_down("dev-1", 1500);
        meters.record_down("dev-1", 500);
        meters.record_up("dev-1", 300);

        let snapshot = meters.snapshot("dev-1");
        assert_eq!(snapshot.total_down, 2000);
        assert_eq!(snapshot.total_up, 300);
    }

    #[test]
    fn unknown_device_reads_as_zero() {
        let meters = DeviceMeters::new();
        let snapshot = meters.snapshot("dev-missing");
        assert_eq!(snapshot.total_down, 0);
        assert_eq!(snapshot.down_bps, 0);
    }

    #[test]
    fn devices_are_counted_separately() {
        let meters = DeviceMeters::new();
        meters.record_down("dev-1", 100);
        meters.record_down("dev-2", 900);

        assert_eq!(meters.snapshot("dev-1").total_down, 100);
        assert_eq!(meters.snapshot("dev-2").total_down, 900);
    }

    #[test]
    fn a_stale_bucket_is_taken_over_not_added_to() {
        let counters = DeviceCounters::new();
        let index = (unix_secs() as usize) % WINDOW_SECS;

        // Pretend this bucket holds a second from a previous window.
        counters.buckets[index].second.store(unix_secs() - 300, Ordering::Relaxed);
        counters.buckets[index].down.store(999_999, Ordering::Relaxed);

        counters.add(0, 10);
        assert_eq!(
            counters.buckets[index].down.load(Ordering::Relaxed),
            10,
            "a bucket from an earlier window must be replaced, not accumulated"
        );
    }
}
