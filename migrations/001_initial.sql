-- BentoProxy Initial Database Schema

-- Device owners (people who run nodes and earn money)
CREATE TABLE IF NOT EXISTS device_owners (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_device_owners_email ON device_owners(email);

-- Proxy users (people who use the proxy service)
CREATE TABLE IF NOT EXISTS proxy_users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    api_key TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_proxy_users_email ON proxy_users(email);
CREATE INDEX idx_proxy_users_api_key ON proxy_users(api_key);

-- Devices (ESP32 hardware nodes)
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    name TEXT,
    max_conns INTEGER NOT NULL DEFAULT 8,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER,
    FOREIGN KEY(owner_id) REFERENCES device_owners(id) ON DELETE CASCADE
);

CREATE INDEX idx_devices_owner ON devices(owner_id);
CREATE INDEX idx_devices_token ON devices(token);
CREATE INDEX idx_devices_active ON devices(is_active);

-- Device sessions (WebSocket connection sessions)
CREATE TABLE IF NOT EXISTS device_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    disconnect_reason TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX idx_sessions_device ON device_sessions(device_id);
CREATE INDEX idx_sessions_active ON device_sessions(ended_at) WHERE ended_at IS NULL;

-- Flows (individual proxied connections/streams)
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    proxy_user_id TEXT,
    stream_id INTEGER NOT NULL,
    target_host TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    bytes_up INTEGER NOT NULL DEFAULT 0,
    bytes_down INTEGER NOT NULL DEFAULT 0,
    error_code INTEGER,
    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
    FOREIGN KEY(proxy_user_id) REFERENCES proxy_users(id) ON DELETE SET NULL
);

CREATE INDEX idx_flows_device ON flows(device_id);
CREATE INDEX idx_flows_user ON flows(proxy_user_id);
CREATE INDEX idx_flows_started ON flows(started_at);

-- Usage rollups (daily aggregated usage for billing)
CREATE TABLE IF NOT EXISTS usage_rollups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    day DATE NOT NULL,
    bytes_up INTEGER NOT NULL DEFAULT 0,
    bytes_down INTEGER NOT NULL DEFAULT 0,
    flow_count INTEGER NOT NULL DEFAULT 0,
    uptime_minutes INTEGER NOT NULL DEFAULT 0,
    UNIQUE(device_id, day),
    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX idx_rollups_device_day ON usage_rollups(device_id, day);
CREATE INDEX idx_rollups_day ON usage_rollups(day);
