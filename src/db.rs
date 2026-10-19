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
        let migrations = Migrations::new(vec![
            M::up(include_str!("../migrations/001_initial.sql")),
            M::up(include_str!("../migrations/002_pending_claims.sql")),
            M::up(include_str!("../migrations/003_claim_attempts.sql")),
            M::up(include_str!("../migrations/004_speed_tests.sql")),
        ]);

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


/// A node waiting for an owner to claim it.
#[derive(Debug, Clone)]
pub struct PendingClaim {
    pub hw_id: String,
    pub model: Option<String>,
    pub announced_at: i64,
}

impl Database {
    /// Record (or refresh) a node announcing itself as unclaimed.
    ///
    /// Called by the device itself, with no authentication — it has no
    /// credentials yet. A row already claimed is left alone so a late
    /// announce cannot discard credentials the node has not collected.
    pub fn announce_pending(&self, hw_id: &str, claim_code: &str, model: Option<&str>) -> Result<()> {
        let now = Utc::now().timestamp();
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT INTO pending_claims (hw_id, claim_code, model, created_at, announced_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(hw_id) DO UPDATE SET
                announced_at = excluded.announced_at,
                claim_code = CASE WHEN pending_claims.claimed_at IS NULL
                                  THEN excluded.claim_code ELSE pending_claims.claim_code END,
                model = excluded.model",
            params![hw_id, claim_code, model, now, now],
        )?;

        Ok(())
    }

    /// Nodes seen within `max_age_secs` that no owner has claimed.
    ///
    /// Expired rows are dropped here as well as on announce: a network whose
    /// nodes are all claimed never announces again, so announce-time pruning
    /// alone would leave stale rows on the dashboard forever.
    pub fn list_pending_claims(&self, max_age_secs: i64) -> Result<Vec<PendingClaim>> {
        self.prune_pending_claims(max_age_secs)?;

        let cutoff = Utc::now().timestamp() - max_age_secs;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT hw_id, model, announced_at FROM pending_claims
             WHERE claimed_at IS NULL AND announced_at >= ?
             ORDER BY announced_at DESC",
        )?;

        let rows = stmt
            .query_map(params![cutoff], |row| {
                Ok(PendingClaim {
                    hw_id: row.get(0)?,
                    model: row.get(1)?,
                    announced_at: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(rows)
    }

    /// Failed claim attempts by this owner within the window.
    ///
    /// Counted per owner: a per-device counter would let one person lock every
    /// unclaimed node in the system by submitting wrong codes.
    pub fn recent_claim_attempts(&self, owner_id: &str, window_secs: i64) -> Result<i64> {
        let cutoff = Utc::now().timestamp() - window_secs;
        let conn = self.conn.lock().unwrap();

        // Opportunistic cleanup of attempts that no longer count.
        conn.execute("DELETE FROM claim_attempts WHERE attempted_at < ?", params![cutoff])?;

        Ok(conn.query_row(
            "SELECT COUNT(*) FROM claim_attempts WHERE owner_id = ? AND attempted_at >= ?",
            params![owner_id, cutoff],
            |row| row.get(0),
        )?)
    }

    /// Bind an unclaimed node to an owner by its printed code.
    ///
    /// Returns the created device, or None when no unclaimed node matches, in
    /// which case the attempt is recorded against this owner.
    pub fn claim_by_code(&self, owner_id: &str, code: &str) -> Result<Option<Device>> {
        let code = code.trim().to_uppercase();

        let hw_id: Option<String> = {
            let conn = self.conn.lock().unwrap();
            conn.query_row(
                "SELECT hw_id FROM pending_claims
                 WHERE claim_code = ? AND claimed_at IS NULL",
                params![code],
                |row| row.get(0),
            )
            .optional()?
        };

        let Some(hw_id) = hw_id else {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO claim_attempts (owner_id, attempted_at) VALUES (?, ?)",
                params![owner_id, Utc::now().timestamp()],
            )?;
            return Ok(None);
        };

        // create_device takes the lock itself, so it must run outside ours.
        let device = self.create_device(owner_id, None)?;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE pending_claims SET device_id = ?, token = ?, claimed_at = ? WHERE hw_id = ?",
            params![device.id, device.token, Utc::now().timestamp(), hw_id],
        )?;

        Ok(Some(device))
    }

    /// Hand over credentials to the node that announced `hw_id`, once.
    ///
    /// The row is deleted on pickup: the credentials live in the device's NVS
    /// from then on, and leaving a copy here would be a second place to leak
    /// them from.
    pub fn take_claimed_credentials(&self, hw_id: &str) -> Result<Option<(String, String)>> {
        let conn = self.conn.lock().unwrap();

        let found: Option<(String, String)> = conn
            .query_row(
                "SELECT device_id, token FROM pending_claims
                 WHERE hw_id = ? AND claimed_at IS NOT NULL",
                params![hw_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        if found.is_some() {
            conn.execute("DELETE FROM pending_claims WHERE hw_id = ?", params![hw_id])?;
        }

        Ok(found)
    }

    /// Drop announcements nobody claimed, so the table cannot grow unbounded
    /// from unauthenticated announces.
    pub fn prune_pending_claims(&self, max_age_secs: i64) -> Result<usize> {
        let cutoff = Utc::now().timestamp() - max_age_secs;
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute(
            "DELETE FROM pending_claims WHERE claimed_at IS NULL AND announced_at < ?",
            params![cutoff],
        )?)
    }
}


/// Recorded traffic for one device, from completed flows.
#[derive(Debug, Clone, Default)]
pub struct DeviceTraffic {
    pub bytes_up_today: i64,
    pub bytes_down_today: i64,
    pub flows_today: i64,
    /// Best sustained rate seen on a single flow, in bytes per second. Only
    /// flows lasting at least a second count, since shorter ones divide by a
    /// rounded duration.
    pub peak_down_bps: i64,
}

impl Database {
    /// Traffic totals for a device since midnight, plus its best observed rate.
    pub fn device_traffic(&self, device_id: &str) -> Result<DeviceTraffic> {
        let conn = self.conn.lock().unwrap();

        let (bytes_up_today, bytes_down_today, flows_today) = conn.query_row(
            "SELECT COALESCE(SUM(bytes_up), 0), COALESCE(SUM(bytes_down), 0), COUNT(*)
             FROM flows
             WHERE device_id = ? AND started_at >= strftime('%s', 'now', 'start of day')",
            params![device_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

        let peak_down_bps = conn
            .query_row(
                "SELECT COALESCE(MAX(bytes_down / (ended_at - started_at)), 0)
                 FROM flows
                 WHERE device_id = ? AND ended_at IS NOT NULL
                   AND ended_at - started_at >= 1",
                params![device_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);

        Ok(DeviceTraffic {
            bytes_up_today,
            bytes_down_today,
            flows_today,
            peak_down_bps,
        })
    }
}


/// The last speed test recorded for a device.
#[derive(Debug, Clone)]
pub struct SpeedTestResult {
    pub ran_at: i64,
    pub down_bps: i64,
    pub ok: bool,
    pub error: Option<String>,
}

impl Database {
    pub fn record_speed_test(
        &self,
        device_id: &str,
        result: &Result<crate::speedtest::Measurement, String>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().timestamp();

        match result {
            Ok(m) => conn.execute(
                "INSERT INTO speed_tests (device_id, ran_at, bytes, duration_ms, down_bps, ok)
                 VALUES (?, ?, ?, ?, ?, 1)",
                params![device_id, now, m.bytes as i64, m.duration_ms as i64, m.down_bps as i64],
            )?,
            Err(e) => conn.execute(
                "INSERT INTO speed_tests (device_id, ran_at, ok, error) VALUES (?, ?, 0, ?)",
                params![device_id, now, e],
            )?,
        };

        Ok(())
    }

    pub fn latest_speed_test(&self, device_id: &str) -> Result<Option<SpeedTestResult>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT ran_at, down_bps, ok, error FROM speed_tests
                 WHERE device_id = ? ORDER BY ran_at DESC LIMIT 1",
                params![device_id],
                |row| {
                    Ok(SpeedTestResult {
                        ran_at: row.get(0)?,
                        down_bps: row.get(1)?,
                        ok: row.get::<_, i64>(2)? == 1,
                        error: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    /// Does this device belong to this owner?
    pub fn device_belongs_to(&self, device_id: &str, owner_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT 1 FROM devices WHERE id = ? AND owner_id = ?",
                params![device_id, owner_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some())
    }
}

fn generate_api_key() -> String {
    format!("bento_{}", Uuid::new_v4().to_string().replace('-', ""))
}
