use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::{info, warn};

/// Traffic data point as returned by queries (from either raw or aggregated table).
#[derive(Debug, Clone)]
pub struct TrafficRecord {
    pub timestamp_ms: i64,   // unix milliseconds
    pub download_bps: f64,
    pub upload_bps: f64,
}

/// A user-assigned device override stored in SQLite.
#[derive(Debug, Clone)]
pub struct DeviceOverride {
    pub mac: String,
    pub custom_name: Option<String>,
    pub custom_type: Option<String>,
    pub updated_at: i64,
}

/// A simple SQLite-backed store for traffic history and device overrides.
///
/// Thread-safe via a Mutex — writes are infrequent (every poll tick),
/// reads are REST API queries (low concurrency).
pub struct TrafficDb {
    conn: Mutex<Connection>,
}

impl TrafficDb {
    /// Open (or create) the SQLite database at the given path.
    pub fn open(path: &PathBuf) -> Result<Self, rusqlite::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let conn = Connection::open(path)?;

        // Enable WAL mode for better concurrent read/write performance.
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

        // Raw 5-second data
        conn.execute(
            "CREATE TABLE IF NOT EXISTS traffic_points (
                ts          INTEGER PRIMARY KEY,
                download_bps REAL NOT NULL,
                upload_bps   REAL NOT NULL
            )",
            [],
        )?;

        // 1-minute aggregated data for older records
        conn.execute(
            "CREATE TABLE IF NOT EXISTS traffic_1m (
                bucket       INTEGER PRIMARY KEY,
                download_avg REAL NOT NULL,
                upload_avg   REAL NOT NULL
            )",
            [],
        )?;

        // Simple key-value config store
        conn.execute(
            "CREATE TABLE IF NOT EXISTS config (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        // User-assigned device name/type overrides
        conn.execute(
            "CREATE TABLE IF NOT EXISTS device_overrides (
                mac         TEXT PRIMARY KEY,
                custom_name TEXT,
                custom_type TEXT,
                updated_at  INTEGER NOT NULL DEFAULT (unixepoch())
            )",
            [],
        )?;

        info!("Traffic DB opened at {}", path.display());
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Insert a single raw traffic point (idempotent on timestamp).
    pub fn insert(&self, ts_ms: i64, download_bps: f64, upload_bps: f64) {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(e) => {
                warn!("TrafficDB lock poisoned: {e}");
                return;
            }
        };
        if let Err(e) = conn.execute(
            "INSERT OR IGNORE INTO traffic_points (ts, download_bps, upload_bps) VALUES (?1, ?2, ?3)",
            params![ts_ms, download_bps, upload_bps],
        ) {
            warn!("TrafficDB insert failed: {e}");
        }
    }

    /// Query traffic records between `from_ms` (inclusive) and `to_ms` (exclusive).
    ///
    /// Merges raw `traffic_points` (recent) and `traffic_1m` (older history).
    /// Returns records ordered by timestamp ascending. Caps at 14400 rows.
    pub fn query(&self, from_ms: i64, to_ms: i64) -> Vec<TrafficRecord> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(e) => {
                warn!("TrafficDB lock poisoned: {e}");
                return vec![];
            }
        };

        let now_ms = current_time_ms();
        let raw_cutoff = now_ms - 7 * 86400 * 1000;

        let mut records: Vec<TrafficRecord> = Vec::new();

        // Query raw points
        {
            let mut stmt = match conn.prepare(
                "SELECT ts, download_bps, upload_bps
                 FROM traffic_points
                 WHERE ts >= ?1 AND ts < ?2
                 ORDER BY ts ASC
                 LIMIT 14400",
            ) {
                Ok(s) => s,
                Err(e) => {
                    warn!("TrafficDB prepare raw query failed: {e}");
                    return vec![];
                }
            };

            let raw_rows: Vec<TrafficRecord> = stmt
                .query_map(params![from_ms, to_ms], |row| {
                    Ok(TrafficRecord {
                        timestamp_ms: row.get(0)?,
                        download_bps: row.get(1)?,
                        upload_bps: row.get(2)?,
                    })
                })
                .ok()
                .into_iter()
                .flat_map(|r| r.filter_map(|x| x.ok()))
                .collect();

            records.extend(raw_rows);
        }

        // Query 1-minute aggregated points for older range
        let agg_to = to_ms.min(raw_cutoff);
        if from_ms < agg_to {
            let mut stmt = match conn.prepare(
                "SELECT bucket, download_avg, upload_avg
                 FROM traffic_1m
                 WHERE bucket >= ?1 AND bucket < ?2
                 ORDER BY bucket ASC
                 LIMIT 14400",
            ) {
                Ok(s) => s,
                Err(e) => {
                    warn!("TrafficDB prepare 1m query failed: {e}");
                    return records;
                }
            };

            let agg_rows: Vec<TrafficRecord> = stmt
                .query_map(params![from_ms, agg_to], |row| {
                    Ok(TrafficRecord {
                        timestamp_ms: row.get(0)?,
                        download_bps: row.get(1)?,
                        upload_bps: row.get(2)?,
                    })
                })
                .ok()
                .into_iter()
                .flat_map(|r| r.filter_map(|x| x.ok()))
                .collect();

            records.extend(agg_rows);
        }

        records.sort_by_key(|r| r.timestamp_ms);
        records.dedup_by_key(|r| r.timestamp_ms);
        if records.len() > 14400 {
            records.truncate(14400);
        }

        records
    }

    /// Aggregate raw data older than `raw_days` into 1-minute AVG buckets,
    /// then delete raw + old aggregated data beyond `total_days`.
    pub fn aggregate_and_prune(&self, raw_days: i64, total_days: i64) {
        let now_ms = current_time_ms();
        let raw_cutoff = now_ms - raw_days * 86400 * 1000;
        let total_cutoff = now_ms - total_days * 86400 * 1000;

        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(e) => {
                warn!("TrafficDB lock poisoned during aggregate: {e}");
                return;
            }
        };

        // Aggregate raw points older than raw_cutoff into 1-minute buckets
        let raw_rows: Vec<(i64, f64, f64)> = {
            let mut stmt = match conn.prepare(
                "SELECT ts, download_bps, upload_bps
                 FROM traffic_points
                 WHERE ts < ?1
                 ORDER BY ts ASC",
            ) {
                Ok(s) => s,
                Err(e) => {
                    warn!("TrafficDB aggregate select failed: {e}");
                    return;
                }
            };

            stmt.query_map(params![raw_cutoff], |row| {
                Ok((row.get::<_, i64>(0)?,
                    row.get::<_, f64>(1)?,
                    row.get::<_, f64>(2)?))
            })
            .ok()
            .into_iter()
            .flat_map(|r| r.filter_map(|x| x.ok()))
            .collect()
        };

        // Build 1-minute buckets
        let mut bucket_sums: Vec<(i64, f64, f64, i64)> = Vec::new();
        for (ts, dl, ul) in &raw_rows {
            let bucket = ts / 60000 * 60000;
            if let Some(last) = bucket_sums.last_mut() {
                if last.0 == bucket {
                    last.1 += dl;
                    last.2 += ul;
                    last.3 += 1;
                    continue;
                }
            }
            bucket_sums.push((bucket, *dl, *ul, 1));
        }

        if !bucket_sums.is_empty() {
            let mut insert_stmt = match conn.prepare(
                "INSERT OR REPLACE INTO traffic_1m (bucket, download_avg, upload_avg)
                 VALUES (?1, ?2, ?3)",
            ) {
                Ok(s) => s,
                Err(e) => {
                    warn!("TrafficDB aggregate insert prepare failed: {e}");
                    return;
                }
            };

            for (bucket, dl_sum, ul_sum, count) in &bucket_sums {
                let c = *count as f64;
                if let Err(e) = insert_stmt.execute(params![bucket, dl_sum / c, ul_sum / c]) {
                    warn!("TrafficDB aggregate insert failed: {e}");
                }
            }

            let total_points: i64 = bucket_sums.iter().map(|(_, _, _, c)| c).sum();
            info!(
                "TrafficDB aggregated {} buckets ({} raw points)",
                bucket_sums.len(),
                total_points,
            );
        }

        // Delete old raw points
        match conn.execute("DELETE FROM traffic_points WHERE ts < ?1", params![raw_cutoff]) {
            Ok(deleted) => {
                if deleted > 0 {
                    info!("TrafficDB deleted {} raw points older than {} ms", deleted, raw_cutoff);
                }
            }
            Err(e) => warn!("TrafficDB delete raw failed: {e}"),
        }

        // Delete old 1-minute buckets
        match conn.execute("DELETE FROM traffic_1m WHERE bucket < ?1", params![total_cutoff]) {
            Ok(deleted) => {
                if deleted > 0 {
                    info!("TrafficDB deleted {} aggregated buckets older than {} ms", deleted, total_cutoff);
                }
            }
            Err(e) => warn!("TrafficDB delete 1m failed: {e}"),
        }
    }

    /// Delete all records older than `before_ms`. Legacy; prefer `aggregate_and_prune`.
    pub fn prune(&self, before_ms: i64) {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(e) => {
                warn!("TrafficDB lock poisoned during prune: {e}");
                return;
            }
        };
        match conn.execute(
            "DELETE FROM traffic_points WHERE ts < ?1",
            params![before_ms],
        ) {
            Ok(deleted) => {
                if deleted > 0 {
                    info!("TrafficDB pruned {} old records", deleted);
                }
            }
            Err(e) => warn!("TrafficDB prune failed: {e}"),
        }
    }

    // ── Device Overrides ─────────────────────────────────────────

    /// Insert or update a device override.
    /// If both custom_name and custom_type are None, delete the override instead.
    pub fn upsert_device_override(
        &self,
        mac: &str,
        custom_name: Option<&str>,
        custom_type: Option<&str>,
    ) -> Result<(), rusqlite::Error> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(e) => {
                warn!("TrafficDB lock poisoned during upsert_device_override: {e}");
                return Ok(());
            }
        };
        if custom_name.is_none() && custom_type.is_none() {
            conn.execute("DELETE FROM device_overrides WHERE mac = ?1", params![mac])?;
        } else {
            conn.execute(
                "INSERT OR REPLACE INTO device_overrides (mac, custom_name, custom_type, updated_at)
                 VALUES (?1, ?2, ?3, unixepoch())",
                params![mac, custom_name, custom_type],
            )?;
        }
        Ok(())
    }

    /// Get all device overrides.
    pub fn get_all_device_overrides(&self) -> Vec<DeviceOverride> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(e) => {
                warn!("TrafficDB lock poisoned during get_all_device_overrides: {e}");
                return vec![];
            }
        };
        let mut stmt = match conn.prepare(
            "SELECT mac, custom_name, custom_type, updated_at FROM device_overrides",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("TrafficDB prepare overrides query failed: {e}");
                return vec![];
            }
        };
        stmt.query_map([], |row| {
            Ok(DeviceOverride {
                mac: row.get(0)?,
                custom_name: row.get(1)?,
                custom_type: row.get(2)?,
                updated_at: row.get(3)?,
            })
        })
        .ok()
        .into_iter()
        .flat_map(|r| r.filter_map(|x| x.ok()))
        .collect()
    }

    /// Delete a device override by MAC.
    #[allow(dead_code)]
    pub fn delete_device_override(&self, mac: &str) -> Result<(), rusqlite::Error> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(e) => {
                warn!("TrafficDB lock poisoned during delete_device_override: {e}");
                return Ok(());
            }
        };
        conn.execute("DELETE FROM device_overrides WHERE mac = ?1", params![mac])?;
        Ok(())
    }

    // ── Config Store ────────────────────────────────────────────

    /// Set a config key/value (INSERT OR REPLACE).
    pub fn set_config(&self, key: &str, value: &str) {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(e) => {
                warn!("TrafficDB lock poisoned during set_config: {e}");
                return;
            }
        };
        if let Err(e) = conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
            params![key, value],
        ) {
            warn!("TrafficDB set_config failed: {e}");
        }
    }

    /// Get all config entries as a HashMap.
    pub fn get_all_config(&self) -> HashMap<String, String> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(e) => {
                warn!("TrafficDB lock poisoned during get_all_config: {e}");
                return HashMap::new();
            }
        };
        let mut stmt = match conn.prepare("SELECT key, value FROM config") {
            Ok(s) => s,
            Err(e) => {
                warn!("TrafficDB prepare config query failed: {e}");
                return HashMap::new();
            }
        };
        stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .ok()
        .into_iter()
        .flat_map(|r| r.filter_map(|x| x.ok()))
        .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Device Override Application
// ═══════════════════════════════════════════════════════════════════

use crate::ws::protocol::WifiInfo;

/// Apply stored device overrides to the devices in a WifiInfo snapshot.
/// Called by the poll engine after each fetch, and by the API handler
/// after a user saves an override.
pub fn apply_device_overrides(wifi: &mut WifiInfo, db: &TrafficDb) {
    let overrides = db.get_all_device_overrides();
    if overrides.is_empty() {
        return;
    }
    let override_map: std::collections::HashMap<String, DeviceOverride> = overrides
        .into_iter()
        .map(|o| (o.mac.to_lowercase(), o))
        .collect();

    for device in &mut wifi.devices {
        if let Some(ov) = override_map.get(&device.mac.to_lowercase()) {
            if ov.custom_name.is_some() {
                device.custom_name = ov.custom_name.clone();
            }
            if ov.custom_type.is_some() {
                device.custom_type = ov.custom_type.clone();
            }
        }
    }
}

/// Get current unix time in milliseconds.
fn current_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
