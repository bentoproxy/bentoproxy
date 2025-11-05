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
}

#[derive(Debug, Serialize)]
pub struct LoginPageData {
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterPageData {
    pub error: Option<String>,
}
