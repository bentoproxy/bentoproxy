use serde::{Deserialize, Serialize};

/// User registration form
#[derive(Debug, Deserialize)]
pub struct RegisterForm {
    pub email: String,
    pub password: String,
    pub role: String, // "device_owner" or "proxy_user"
}

/// User login form
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub email: String,
    pub password: String,
}

/// Device creation form
#[derive(Debug, Deserialize)]
pub struct CreateDeviceForm {
    pub name: Option<String>,
}

/// Template data for pages
#[derive(Debug, Serialize)]
pub struct IndexPageData {
    pub title: String,
    pub device_count: usize,
}

#[derive(Debug, Serialize)]
pub struct DashboardOwnerData {
    pub email: String,
    pub devices: Vec<DeviceInfo>,
}

#[derive(Debug, Serialize)]
pub struct DashboardUserData {
    pub email: String,
    pub api_key: String,
    pub socks5_host: String,
    pub socks5_port: u16,
}

#[derive(Debug, Serialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,  // "Unnamed" if None
    pub is_active: bool,
    pub is_online: bool,
    pub created_at: String,
    pub last_seen_at: String,  // "Never" if None
    /// Streams in flight right now.
    pub streams: usize,
    /// Live rates in bytes per second, averaged over the last 10 seconds.
    pub down_bps: u64,
    pub up_bps: u64,
    /// Traffic since midnight, pre-formatted for display.
    pub down_today: String,
    pub up_today: String,
    /// Best sustained rate ever recorded for this device.
    pub peak_down: String,
}

#[derive(Debug, Serialize)]
pub struct LoginPageData {
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterPageData {
    pub error: Option<String>,
}

/// Optional friendly name supplied when registering a device.
#[derive(Debug, Deserialize)]
pub struct NewDeviceForm {
    pub name: Option<String>,
}

/// A node announcing itself before any owner has claimed it.
#[derive(Debug, Deserialize)]
pub struct DeviceAnnounceForm {
    pub hw_id: String,
    pub claim_code: String,
    pub model: Option<String>,
}

/// The code an owner reads off a device to claim it.
#[derive(Debug, Deserialize)]
pub struct ClaimDeviceForm {
    pub code: String,
}

/// A node waiting to be claimed, as shown on the dashboard.
#[derive(Debug, Serialize)]
pub struct PendingNode {
    pub hw_id: String,
    pub model: String,
    pub waiting_since: String,
}
