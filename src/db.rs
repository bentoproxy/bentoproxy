use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{NaiveDate, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use rusqlite_migration::{Migrations, M};
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Database handle with connection pool (simplified for SQLite)
#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    /// Open database connection and run migrations
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut conn = Connection::open(path)?;

        // Enable foreign keys
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;

        // Run migrations
        let migrations = Migrations::new(vec![M::up(include_str!("../migrations/001_initial.sql"))]);

        migrations
            .to_latest(&mut conn)
            .context("Failed to run database migrations")?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Create a new device owner
    pub fn create_device_owner(&self, email: &str, password: &str) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let password_hash = hash_password(password)?;
        let created_at = Utc::now().timestamp();

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO device_owners (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            params![id, email, password_hash, created_at],
        )?;

        Ok(id)
    }

    /// Create a new proxy user
    pub fn create_proxy_user(&self, email: &str, password: &str) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let password_hash = hash_password(password)?;
        let api_key = generate_api_key();
        let created_at = Utc::now().timestamp();

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO proxy_users (id, email, password_hash, api_key, created_at) VALUES (?, ?, ?, ?, ?)",
            params![id, email, password_hash, api_key, created_at],
        )?;

        Ok(id)
    }

    /// Authenticate device owner
    pub fn authenticate_device_owner(&self, email: &str, password: &str) -> Result<Option<DeviceOwner>> {
        let conn = self.conn.lock().unwrap();
        let result: Option<(String, String, String)> = conn
            .query_row(
                "SELECT id, email, password_hash FROM device_owners WHERE email = ?",
                params![email],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;

        if let Some((id, email, password_hash)) = result {
            if verify_password(password, &password_hash)? {
                return Ok(Some(DeviceOwner { id, email }));
            }
        }

        Ok(None)
    }

    /// Authenticate proxy user
    pub fn authenticate_proxy_user(&self, email: &str, password: &str) -> Result<Option<ProxyUser>> {
        let conn = self.conn.lock().unwrap();
        let result: Option<(String, String, String, String)> = conn
            .query_row(
                "SELECT id, email, password_hash, api_key FROM proxy_users WHERE email = ?",
                params![email],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;

        if let Some((id, email, password_hash, api_key)) = result {
            if verify_password(password, &password_hash)? {
                return Ok(Some(ProxyUser { id, email, api_key }));
            }
        }

        Ok(None)
    }

    /// Get proxy user by API key (for SOCKS5 auth)
    pub fn get_proxy_user_by_api_key(&self, api_key: &str) -> Result<Option<ProxyUser>> {
        let conn = self.conn.lock().unwrap();
        let result: Option<(String, String, String)> = conn
            .query_row(
                "SELECT id, email, api_key FROM proxy_users WHERE api_key = ?",
                params![api_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;

        Ok(result.map(|(id, email, api_key)| ProxyUser { id, email, api_key }))
    }

    /// Get proxy user by ID
    pub fn get_proxy_user_by_id(&self, user_id: &str) -> Result<Option<ProxyUser>> {
        let conn = self.conn.lock().unwrap();
        let result: Option<(String, String, String)> = conn
            .query_row(
                "SELECT id, email, api_key FROM proxy_users WHERE id = ?",
                params![user_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;

        Ok(result.map(|(id, email, api_key)| ProxyUser { id, email, api_key }))
    }

    /// Create a new device
    pub fn create_device(&self, owner_id: &str, name: Option<String>) -> Result<Device> {
        let id = format!("dev-{}", Uuid::new_v4().to_string().split('-').next().unwrap());
        let token = generate_api_key();
        let created_at = Utc::now().timestamp();

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO devices (id, owner_id, token, name, created_at) VALUES (?, ?, ?, ?, ?)",
            params![id, owner_id, token, name, created_at],
        )?;

        Ok(Device {
            id: id.clone(),
            owner_id: owner_id.to_string(),
            token,
            name,
            max_conns: 8,
            is_active: true,
            created_at,
            last_seen_at: None,
        })
    }

    /// Authenticate device by token
    pub fn authenticate_device(&self, device_id: &str, token: &str) -> Result<Option<Device>> {
        let conn = self.conn.lock().unwrap();
        let result: Option<(String, String, String, Option<String>, i32, i32, i64, Option<i64>)> = conn
            .query_row(
                "SELECT id, owner_id, token, name, max_conns, is_active, created_at, last_seen_at FROM devices WHERE id = ? AND token = ?",
                params![device_id, token],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()?;

        Ok(result.map(
            |(id, owner_id, token, name, max_conns, is_active, created_at, last_seen_at)| Device {
                id,
                owner_id,
                token,
                name,
                max_conns,
                is_active: is_active != 0,
                created_at,
                last_seen_at,
            },
        ))
    }

    /// Update device last seen timestamp
    pub fn update_device_last_seen(&self, device_id: &str) -> Result<()> {
        let last_seen_at = Utc::now().timestamp();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE devices SET last_seen_at = ? WHERE id = ?",
            params![last_seen_at, device_id],
        )?;
        Ok(())
    }

    /// Get devices for owner
    pub fn get_devices_for_owner(&self, owner_id: &str) -> Result<Vec<Device>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, owner_id, token, name, max_conns, is_active, created_at, last_seen_at FROM devices WHERE owner_id = ? ORDER BY created_at DESC",
        )?;

        let devices = stmt
            .query_map(params![owner_id], |row| {
                Ok(Device {
                    id: row.get(0)?,
                    owner_id: row.get(1)?,
                    token: row.get(2)?,
                    name: row.get(3)?,
                    max_conns: row.get(4)?,
                    is_active: row.get::<_, i32>(5)? != 0,
                    created_at: row.get(6)?,
                    last_seen_at: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(devices)
    }

    /// Start a device session
    pub fn start_device_session(&self, device_id: &str) -> Result<i64> {
        let started_at = Utc::now().timestamp();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO device_sessions (device_id, started_at) VALUES (?, ?)",
            params![device_id, started_at],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// End a device session
    pub fn end_device_session(&self, session_id: i64, reason: Option<&str>) -> Result<()> {
        let ended_at = Utc::now().timestamp();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE device_sessions SET ended_at = ?, disconnect_reason = ? WHERE id = ?",
            params![ended_at, reason, session_id],
        )?;
        Ok(())
    }

    /// Start a flow
    pub fn start_flow(
        &self,
        device_id: &str,
        proxy_user_id: Option<&str>,
        stream_id: u32,
        target_host: &str,
        target_port: u16,
    ) -> Result<i64> {
        let started_at = Utc::now().timestamp();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO flows (device_id, proxy_user_id, stream_id, target_host, target_port, started_at) VALUES (?, ?, ?, ?, ?, ?)",
            params![device_id, proxy_user_id, stream_id as i32, target_host, target_port as i32, started_at],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Update flow bytes
    pub fn update_flow_bytes(&self, flow_id: i64, bytes_up: u64, bytes_down: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE flows SET bytes_up = bytes_up + ?, bytes_down = bytes_down + ? WHERE id = ?",
            params![bytes_up as i64, bytes_down as i64, flow_id],
        )?;
        Ok(())
    }

    /// End a flow
    pub fn end_flow(&self, flow_id: i64, bytes: Option<(u64, u64)>) -> Result<()> {
        let ended_at = Utc::now().timestamp();
        let conn = self.conn.lock().unwrap();

        if let Some((bytes_up, bytes_down)) = bytes {
            conn.execute(
                "UPDATE flows SET ended_at = ?, bytes_up = ?, bytes_down = ? WHERE id = ?",
                params![ended_at, bytes_up as i64, bytes_down as i64, flow_id],
            )?;
        } else {
            conn.execute(
                "UPDATE flows SET ended_at = ? WHERE id = ?",
                params![ended_at, flow_id],
            )?;
        }
        Ok(())
    }

    /// Update usage rollup for today
    pub fn update_usage_rollup(&self, device_id: &str, bytes_up: u64, bytes_down: u64) -> Result<()> {
        let today = Utc::now().date_naive();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO usage_rollups (device_id, day, bytes_up, bytes_down, flow_count)
             VALUES (?, ?, ?, ?, 1)
             ON CONFLICT(device_id, day) DO UPDATE SET
             bytes_up = bytes_up + excluded.bytes_up,
             bytes_down = bytes_down + excluded.bytes_down,
             flow_count = flow_count + excluded.flow_count",
            params![device_id, today.to_string(), bytes_up as i64, bytes_down as i64],
        )?;
        Ok(())
    }

    /// Get usage stats for device
    pub fn get_usage_stats(&self, device_id: &str, days: i32) -> Result<Vec<UsageRollup>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT day, bytes_up, bytes_down, flow_count, uptime_minutes
             FROM usage_rollups
             WHERE device_id = ?
             ORDER BY day DESC
             LIMIT ?",
        )?;

        let rollups = stmt
            .query_map(params![device_id, days], |row| {
                Ok(UsageRollup {
                    day: NaiveDate::parse_from_str(&row.get::<_, String>(0)?, "%Y-%m-%d").unwrap(),
                    bytes_up: row.get::<_, i64>(1)? as u64,
                    bytes_down: row.get::<_, i64>(2)? as u64,
                    flow_count: row.get(3)?,
                    uptime_minutes: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rollups)
    }
}

// Models

#[derive(Debug, Clone)]
pub struct DeviceOwner {
    pub id: String,
    pub email: String,
}

#[derive(Debug, Clone)]
pub struct ProxyUser {
    pub id: String,
    pub email: String,
    pub api_key: String,
}

#[derive(Debug, Clone)]
pub struct Device {
    pub id: String,
    pub owner_id: String,
    pub token: String,
    pub name: Option<String>,
    pub max_conns: i32,
    pub is_active: bool,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct UsageRollup {
    pub day: NaiveDate,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub flow_count: i32,
    pub uptime_minutes: i32,
}

// Password hashing helpers

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?
        .to_string();
    Ok(password_hash)
}

fn verify_password(password: &str, password_hash: &str) -> Result<bool> {
    let parsed_hash =
        PasswordHash::new(password_hash).map_err(|e| anyhow::anyhow!("Invalid password hash: {}", e))?;
    let argon2 = Argon2::default();
    Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
}

fn generate_api_key() -> String {
    format!("bento_{}", Uuid::new_v4().to_string().replace('-', ""))
}
