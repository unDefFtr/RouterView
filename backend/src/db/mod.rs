use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::{info, warn};

use crate::secrets::EncryptedSecret;

mod key_management;
mod maintenance;
mod schema;
mod traffic_v4;
mod types;

#[allow(unused_imports)]
pub use key_management::{
    rotate_key, verify_key, KeyManagementError, KeyRotationReport, KeyVerificationReport,
};
pub use maintenance::{
    backup_database, check_database, export_legacy, migrate_database, restore_database,
};
#[allow(unused_imports)]
pub use traffic_v4::{
    CounterCheckpoint, CounterCheckpointInput, RouterInterfaceRecord, RouterRecord, TrafficBucket,
    TrafficCoverage, TrafficGapInput, TrafficQuality, TrafficQuery, TrafficQueryResult,
    TrafficSampleInput, TrafficTotals,
};
#[allow(unused_imports)]
pub use types::{
    BackupArtifact, DatabaseError, DatabaseReport, MigrationReport, RestoreReport,
    CURRENT_SCHEMA_VERSION,
};

/// A user-assigned device override stored in SQLite.
#[derive(Debug, Clone)]
pub struct DeviceOverride {
    pub mac: String,
    pub custom_name: Option<String>,
    pub custom_type: Option<String>,
    pub updated_at: i64,
}

/// A latency probe target stored in SQLite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeTargetRow {
    pub id: i64,
    pub name: String,
    pub host: String,
    pub category: String,
    pub sort_order: i64,
}

#[derive(Debug, Clone)]
pub struct AdminRecord {
    pub username: String,
    pub password_hash: String,
    pub credential_version: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthSessionRecord {
    pub id: String,
    #[serde(skip_serializing)]
    pub token_hash: Vec<u8>,
    #[serde(skip_serializing)]
    pub csrf_hash: Vec<u8>,
    pub username: String,
    pub role: String,
    pub kind: String,
    pub label: Option<String>,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub idle_expires_at: Option<i64>,
    pub absolute_expires_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct PairingRecord {
    pub id: String,
    pub role: String,
    pub label: String,
    pub expires_at: i64,
}

/// A simple SQLite-backed store for traffic history and device overrides.
///
/// Thread-safe via a Mutex — writes are infrequent (every poll tick),
/// reads are REST API queries (low concurrency).
pub struct TrafficDb {
    conn: Mutex<Connection>,
    _lock: Option<maintenance::DatabaseLock>,
    path: PathBuf,
}

impl TrafficDb {
    /// Open (or create) the SQLite database at the given path.
    #[cfg(test)]
    pub fn open(path: &Path) -> Result<Self, DatabaseError> {
        let (conn, lock, migration) = maintenance::open_runtime(path)?;

        // Seed default probe targets (idempotent — skips if any exist)
        seed_default_probe_targets_inner(&conn);

        if let Some(backup) = &migration.backup {
            info!(
                "Migrated traffic DB from v{} to v{}; verified backup: {} ({}, {} rows)",
                migration.from_version,
                migration.to_version,
                backup.path.display(),
                backup.sha256,
                backup.table_counts.values().sum::<u64>()
            );
        }
        info!("Traffic DB opened at {}", path.display());
        Ok(Self {
            conn: Mutex::new(conn),
            _lock: lock,
            path: path.to_path_buf(),
        })
    }

    /// Open only the configuration and security schema. The caller must load
    /// encrypted secrets and then call `finish_migrations` before serving.
    pub fn open_for_bootstrap(path: &Path) -> Result<Self, DatabaseError> {
        let (conn, lock) = maintenance::open_bootstrap_runtime(path)?;
        Ok(Self {
            conn: Mutex::new(conn),
            _lock: lock,
            path: path.to_path_buf(),
        })
    }

    pub fn finish_migrations(&self) -> Result<MigrationReport, DatabaseError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let migration = maintenance::finish_runtime_migration(&self.path, &mut conn)?;
        seed_default_probe_targets_inner(&conn);
        if let Some(backup) = &migration.backup {
            info!(
                "Migrated traffic DB from v{} to v{}; verified backup: {} ({}, {} rows)",
                migration.from_version,
                migration.to_version,
                backup.path.display(),
                backup.sha256,
                backup.table_counts.values().sum::<u64>()
            );
        }
        Ok(migration)
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
        let mut stmt = match conn
            .prepare("SELECT mac, custom_name, custom_type, updated_at FROM device_overrides")
        {
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

    // ── Probe Targets ─────────────────────────────────────────

    /// Get all probe targets ordered by sort_order, then id.
    pub fn get_all_probe_targets(&self) -> Vec<ProbeTargetRow> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(e) => {
                warn!("TrafficDB lock poisoned during get_all_probe_targets: {e}");
                return vec![];
            }
        };
        let mut stmt = match conn.prepare(
            "SELECT id, name, host, category, sort_order FROM probe_targets ORDER BY sort_order, id",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("TrafficDB prepare probe_targets query failed: {e}");
                return vec![];
            }
        };
        stmt.query_map([], |row| {
            Ok(ProbeTargetRow {
                id: row.get(0)?,
                name: row.get(1)?,
                host: row.get(2)?,
                category: row.get(3)?,
                sort_order: row.get(4)?,
            })
        })
        .ok()
        .into_iter()
        .flat_map(|r| r.filter_map(|x| x.ok()))
        .collect()
    }

    /// Replace all probe targets in a transaction (DELETE all + INSERT new).
    pub fn replace_all_probe_targets(&self, targets: &[ProbeTargetRow]) {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(e) => {
                warn!("TrafficDB lock poisoned during replace_all_probe_targets: {e}");
                return;
            }
        };

        // Wrap in a transaction for atomicity
        if let Err(e) = conn.execute_batch("BEGIN") {
            warn!("TrafficDB begin tx failed: {e}");
            return;
        }

        if let Err(e) = conn.execute("DELETE FROM probe_targets", []) {
            warn!("TrafficDB delete probe_targets failed: {e}");
            let _ = conn.execute_batch("ROLLBACK");
            return;
        }

        let mut insert_stmt = match conn.prepare(
            "INSERT INTO probe_targets (name, host, category, sort_order) VALUES (?1, ?2, ?3, ?4)",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("TrafficDB prepare insert probe_targets failed: {e}");
                let _ = conn.execute_batch("ROLLBACK");
                return;
            }
        };

        for t in targets {
            if let Err(e) = insert_stmt.execute(params![t.name, t.host, t.category, t.sort_order]) {
                warn!("TrafficDB insert probe_target failed: {e}");
            }
        }

        if let Err(e) = conn.execute_batch("COMMIT") {
            warn!("TrafficDB commit tx failed: {e}");
        }
    }

    /// Reset probe targets to defaults: DELETE all, re-seed.
    pub fn reset_probe_targets(&self) {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(e) => {
                warn!("TrafficDB lock poisoned during reset_probe_targets: {e}");
                return;
            }
        };
        if let Err(e) = conn.execute("DELETE FROM probe_targets", []) {
            warn!("TrafficDB delete probe_targets for reset failed: {e}");
        }
        seed_default_probe_targets_inner(&conn);
    }

    // ── Config Store ────────────────────────────────────────────

    /// Set a config key/value (INSERT OR REPLACE).
    #[cfg(test)]
    pub fn set_config(&self, key: &str, value: &str) -> Result<(), rusqlite::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Get all config entries as a HashMap.
    pub fn get_all_config(&self) -> Result<HashMap<String, String>, rusqlite::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let mut stmt = conn.prepare("SELECT key, value FROM config")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect()
    }

    pub fn instance_id(&self) -> Result<String, rusqlite::Error> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = conn.transaction()?;
        let existing = tx
            .query_row(
                "SELECT value FROM config WHERE key = 'instance_id'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let instance_id = existing.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        tx.execute(
            "INSERT OR IGNORE INTO config(key, value) VALUES ('instance_id', ?1)",
            params![instance_id],
        )?;
        tx.commit()?;
        Ok(instance_id)
    }

    pub fn load_secret(&self, name: &str) -> Result<Option<EncryptedSecret>, rusqlite::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        conn.query_row(
            "SELECT ciphertext, nonce, key_id FROM encrypted_secrets WHERE name = ?1",
            params![name],
            |row| {
                Ok(EncryptedSecret {
                    ciphertext: row.get(0)?,
                    nonce: row.get(1)?,
                    key_id: row.get(2)?,
                })
            },
        )
        .optional()
    }

    pub fn save_config_transaction(
        &self,
        values: &[(String, String)],
        secret: Option<(&str, &EncryptedSecret)>,
        delete_secret: Option<&str>,
        expected_revision: Option<u64>,
    ) -> Result<bool, rusqlite::Error> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = conn.transaction()?;
        let current_revision = tx
            .query_row(
                "SELECT value FROM config WHERE key = 'config_revision'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        if expected_revision.is_some_and(|expected| expected != current_revision) {
            tx.rollback()?;
            return Ok(false);
        }
        for (key, value) in values {
            tx.execute(
                "INSERT OR REPLACE INTO config(key, value) VALUES (?1, ?2)",
                params![key, value],
            )?;
        }
        if let Some((name, encrypted)) = secret {
            tx.execute(
                "INSERT INTO encrypted_secrets(name, ciphertext, nonce, key_id, updated_at)
                 VALUES (?1, ?2, ?3, ?4, unixepoch())
                 ON CONFLICT(name) DO UPDATE SET
                    ciphertext = excluded.ciphertext,
                    nonce = excluded.nonce,
                    key_id = excluded.key_id,
                    updated_at = excluded.updated_at",
                params![
                    name,
                    encrypted.ciphertext,
                    encrypted.nonce,
                    encrypted.key_id
                ],
            )?;
        }
        if let Some(name) = delete_secret {
            tx.execute(
                "DELETE FROM encrypted_secrets WHERE name = ?1",
                params![name],
            )?;
        }
        if expected_revision.is_some() {
            tx.execute(
                "INSERT OR REPLACE INTO config(key, value) VALUES ('config_revision', ?1)",
                params![current_revision.saturating_add(1).to_string()],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    pub fn migrate_plaintext_router_password(
        &self,
        encrypted: &EncryptedSecret,
    ) -> Result<(), rusqlite::Error> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        conn.execute_batch(
            "PRAGMA wal_checkpoint(TRUNCATE);
             PRAGMA journal_mode=DELETE;
             PRAGMA synchronous=FULL;
             PRAGMA secure_delete=ON;",
        )?;

        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO encrypted_secrets(name, ciphertext, nonce, key_id, updated_at)
             VALUES ('router_password', ?1, ?2, ?3, unixepoch())
             ON CONFLICT(name) DO UPDATE SET
                ciphertext = excluded.ciphertext,
                nonce = excluded.nonce,
                key_id = excluded.key_id,
                updated_at = excluded.updated_at",
            params![encrypted.ciphertext, encrypted.nonce, encrypted.key_id],
        )?;

        let stored: (Vec<u8>, Vec<u8>, String) = tx.query_row(
            "SELECT ciphertext, nonce, key_id
             FROM encrypted_secrets WHERE name = 'router_password'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if stored.0 != encrypted.ciphertext
            || stored.1 != encrypted.nonce
            || stored.2 != encrypted.key_id
        {
            return Err(rusqlite::Error::InvalidQuery);
        }

        tx.execute(
            "DELETE FROM config WHERE key IN ('router_password', 'routeros_password')",
            [],
        )?;
        tx.commit()?;

        // DELETE alone leaves recoverable bytes in old WAL frames and free
        // pages. Compact before the process starts accepting requests.
        conn.execute_batch(
            "VACUUM;
             PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;",
        )?;
        Ok(())
    }

    pub fn admin(&self) -> Result<Option<AdminRecord>, rusqlite::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        conn.query_row(
            "SELECT username, password_hash, credential_version FROM admins WHERE id = 1",
            [],
            |row| {
                Ok(AdminRecord {
                    username: row.get(0)?,
                    password_hash: row.get(1)?,
                    credential_version: row.get(2)?,
                })
            },
        )
        .optional()
    }

    pub fn create_admin(&self, username: &str, password_hash: &str) -> Result<(), rusqlite::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        conn.execute(
            "INSERT INTO admins(id, username, password_hash) VALUES (1, ?1, ?2)",
            params![username, password_hash],
        )?;
        Ok(())
    }

    pub fn replace_admin_password(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<(), rusqlite::Error> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE admins SET username = ?1, password_hash = ?2,
                 credential_version = credential_version + 1, updated_at = unixepoch()
             WHERE id = 1",
            params![username, password_hash],
        )?;
        tx.execute(
            "UPDATE auth_sessions SET revoked_at = unixepoch() WHERE revoked_at IS NULL",
            [],
        )?;
        tx.execute(
            "UPDATE pairing_codes SET used_at = unixepoch() WHERE used_at IS NULL",
            [],
        )?;
        tx.commit()
    }

    pub fn store_setup_token(
        &self,
        token_hash: &[u8],
        expires_at: i64,
    ) -> Result<(), rusqlite::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        conn.execute(
            "INSERT OR REPLACE INTO setup_tokens(id, token_hash, expires_at, used_at)
             VALUES (1, ?1, ?2, NULL)",
            params![token_hash, expires_at],
        )?;
        Ok(())
    }

    pub fn setup_token_is_valid(
        &self,
        token_hash: &[u8],
        now: i64,
    ) -> Result<bool, rusqlite::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        conn.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM setup_tokens
                 WHERE id = 1 AND token_hash = ?1
                   AND used_at IS NULL AND expires_at > ?2
             ) AND NOT EXISTS(SELECT 1 FROM admins)",
            params![token_hash, now],
            |row| row.get(0),
        )
    }

    pub fn consume_setup_and_create_admin(
        &self,
        token_hash: &[u8],
        now: i64,
        username: &str,
        password_hash: &str,
    ) -> Result<bool, rusqlite::Error> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE setup_tokens SET used_at = ?1
             WHERE id = 1 AND token_hash = ?2 AND used_at IS NULL AND expires_at > ?1
               AND NOT EXISTS(SELECT 1 FROM admins)",
            params![now, token_hash],
        )?;
        if changed != 1 {
            tx.rollback()?;
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO admins(id, username, password_hash) VALUES (1, ?1, ?2)",
            params![username, password_hash],
        )?;
        tx.commit()?;
        Ok(true)
    }

    #[cfg(test)]
    pub fn insert_session(&self, session: &AuthSessionRecord) -> Result<(), rusqlite::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        insert_session_inner(&conn, session)?;
        Ok(())
    }

    pub fn insert_standard_session_if_admin_version(
        &self,
        session: &AuthSessionRecord,
        expected_credential_version: i64,
    ) -> Result<bool, rusqlite::Error> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let credentials_unchanged: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM admins
                 WHERE id = 1 AND username = ?1 AND credential_version = ?2
             )",
            params![session.username, expected_credential_version],
            |row| row.get(0),
        )?;
        if !credentials_unchanged || session.kind != "standard" || session.role != "admin" {
            tx.rollback()?;
            return Ok(false);
        }
        insert_session_inner(&tx, session)?;
        tx.commit()?;
        Ok(true)
    }

    pub fn session_by_token_hash(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<AuthSessionRecord>, rusqlite::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        conn.query_row(
            "SELECT id, token_hash, csrf_hash, username, role, kind, label, created_at,
                    last_seen_at, idle_expires_at, absolute_expires_at, revoked_at
             FROM auth_sessions WHERE token_hash = ?1",
            params![token_hash],
            map_session_row,
        )
        .optional()
    }

    pub fn touch_session_if_active_throttled(
        &self,
        id: &str,
        username: &str,
        role: &str,
        kind: &str,
        now: i64,
        minimum_interval_secs: i64,
    ) -> Result<bool, rusqlite::Error> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE auth_sessions SET last_seen_at = ?1,
                idle_expires_at = CASE WHEN kind = 'standard' THEN ?1 + 43200 ELSE NULL END
             WHERE id = ?2
               AND username = ?3
               AND role = ?4
               AND kind = ?5
               AND revoked_at IS NULL
               AND absolute_expires_at > ?1
               AND (idle_expires_at IS NULL OR idle_expires_at > ?1)
               AND last_seen_at <= ?1 - ?6",
            params![now, id, username, role, kind, minimum_interval_secs],
        )?;
        let active = if changed == 1 {
            true
        } else {
            session_is_active_inner(&tx, id, username, role, kind, now)?
        };
        tx.commit()?;
        Ok(active)
    }

    pub fn session_is_active(
        &self,
        id: &str,
        username: &str,
        role: &str,
        kind: &str,
        now: i64,
    ) -> Result<bool, rusqlite::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        session_is_active_inner(&conn, id, username, role, kind, now)
    }

    pub fn list_sessions(&self) -> Result<Vec<AuthSessionRecord>, rusqlite::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let mut stmt = conn.prepare(
            "SELECT id, token_hash, csrf_hash, username, role, kind, label, created_at,
                    last_seen_at, idle_expires_at, absolute_expires_at, revoked_at
             FROM auth_sessions ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], map_session_row)?;
        rows.collect()
    }

    pub fn revoke_session(&self, id: &str, now: i64) -> Result<bool, rusqlite::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let changed = conn.execute(
            "UPDATE auth_sessions SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
            params![now, id],
        )?;
        Ok(changed == 1)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_pairing_if_authorized(
        &self,
        pairing: &PairingRecord,
        code_hash: &[u8],
        creator_session_id: &str,
        creator_username: &str,
        creator_role: &str,
        creator_kind: &str,
        now: i64,
        expected_credential_version: Option<i64>,
    ) -> Result<bool, rusqlite::Error> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let authorized: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM auth_sessions AS session
                 JOIN admins AS admin ON admin.id = 1
                 WHERE session.id = ?1
                   AND session.username = ?2
                   AND session.role = ?3
                   AND session.kind = ?4
                   AND session.role = 'admin'
                   AND session.username = admin.username
                   AND session.revoked_at IS NULL
                   AND session.absolute_expires_at > ?5
                   AND (session.idle_expires_at IS NULL OR session.idle_expires_at > ?5)
                   AND (?6 IS NULL OR admin.credential_version = ?6)
             )",
            params![
                creator_session_id,
                creator_username,
                creator_role,
                creator_kind,
                now,
                expected_credential_version,
            ],
            |row| row.get(0),
        )?;
        if !authorized {
            tx.rollback()?;
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO pairing_codes(
                id, code_hash, role, label, created_by_session_id, created_at, expires_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                pairing.id,
                code_hash,
                pairing.role,
                pairing.label,
                creator_session_id,
                now,
                pairing.expires_at,
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn consume_pairing_and_insert_session(
        &self,
        code_hash: &[u8],
        now: i64,
        session_id: &str,
        token_hash: &[u8],
        csrf_hash: &[u8],
        viewer_lifetime_secs: i64,
        admin_lifetime_secs: i64,
    ) -> Result<Option<AuthSessionRecord>, rusqlite::Error> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let pairing_and_username = tx
            .query_row(
                "SELECT pairing.id, pairing.role, pairing.label, pairing.expires_at,
                        admin.username
                 FROM pairing_codes AS pairing
                 JOIN auth_sessions AS creator
                   ON creator.id = pairing.created_by_session_id
                 JOIN admins AS admin ON admin.id = 1
                 WHERE pairing.code_hash = ?1
                   AND pairing.used_at IS NULL
                   AND pairing.expires_at > ?2
                   AND creator.username = admin.username
                   AND creator.role = 'admin'
                   AND creator.revoked_at IS NULL
                   AND creator.absolute_expires_at > ?2
                   AND (creator.idle_expires_at IS NULL OR creator.idle_expires_at > ?2)",
                params![code_hash, now],
                |row| {
                    Ok((
                        PairingRecord {
                            id: row.get(0)?,
                            role: row.get(1)?,
                            label: row.get(2)?,
                            expires_at: row.get(3)?,
                        },
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((pairing, username)) = pairing_and_username else {
            tx.rollback()?;
            return Ok(None);
        };
        let lifetime_secs = if pairing.role == "viewer" {
            viewer_lifetime_secs
        } else {
            admin_lifetime_secs
        };
        let session = AuthSessionRecord {
            id: session_id.to_string(),
            token_hash: token_hash.to_vec(),
            csrf_hash: csrf_hash.to_vec(),
            username,
            role: pairing.role,
            kind: "fixed".to_string(),
            label: Some(pairing.label),
            created_at: now,
            last_seen_at: now,
            idle_expires_at: None,
            absolute_expires_at: now.saturating_add(lifetime_secs),
            revoked_at: None,
        };
        insert_session_inner(&tx, &session)?;
        let consumed = tx.execute(
            "UPDATE pairing_codes SET used_at = ?1 WHERE id = ?2 AND used_at IS NULL",
            params![now, pairing.id],
        )?;
        if consumed != 1 {
            tx.rollback()?;
            return Ok(None);
        }
        tx.commit()?;
        Ok(Some(session))
    }
}

fn insert_session_inner(
    conn: &rusqlite::Connection,
    session: &AuthSessionRecord,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO auth_sessions(
            id, token_hash, csrf_hash, username, role, kind, label, created_at,
            last_seen_at, idle_expires_at, absolute_expires_at, revoked_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            session.id,
            session.token_hash,
            session.csrf_hash,
            session.username,
            session.role,
            session.kind,
            session.label,
            session.created_at,
            session.last_seen_at,
            session.idle_expires_at,
            session.absolute_expires_at,
            session.revoked_at,
        ],
    )?;
    Ok(())
}

fn session_is_active_inner(
    conn: &rusqlite::Connection,
    id: &str,
    username: &str,
    role: &str,
    kind: &str,
    now: i64,
) -> Result<bool, rusqlite::Error> {
    conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM auth_sessions
             WHERE id = ?1
               AND username = ?2
               AND role = ?3
               AND kind = ?4
               AND revoked_at IS NULL
               AND absolute_expires_at > ?5
               AND (idle_expires_at IS NULL OR idle_expires_at > ?5)
         )",
        params![id, username, role, kind, now],
        |row| row.get(0),
    )
}

fn map_session_row(row: &rusqlite::Row<'_>) -> Result<AuthSessionRecord, rusqlite::Error> {
    Ok(AuthSessionRecord {
        id: row.get(0)?,
        token_hash: row.get(1)?,
        csrf_hash: row.get(2)?,
        username: row.get(3)?,
        role: row.get(4)?,
        kind: row.get(5)?,
        label: row.get(6)?,
        created_at: row.get(7)?,
        last_seen_at: row.get(8)?,
        idle_expires_at: row.get(9)?,
        absolute_expires_at: row.get(10)?,
        revoked_at: row.get(11)?,
    })
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

// ═══════════════════════════════════════════════════════════════════
// Probe target seed data
// ═══════════════════════════════════════════════════════════════════

/// Seed default probe targets into the database.
/// Idempotent: does nothing if any rows already exist.
fn seed_default_probe_targets_inner(conn: &rusqlite::Connection) {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM probe_targets", [], |r| r.get(0))
        .unwrap_or(0);
    if count > 0 {
        return;
    }

    let defaults = crate::poller::transform::default_latency_probe_targets(&[]);
    let mut stmt = match conn.prepare(
        "INSERT INTO probe_targets (name, host, category, sort_order) VALUES (?1, ?2, ?3, ?4)",
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!("Seed probe_targets prepare failed: {e}");
            return;
        }
    };

    for (i, (name, host, category)) in defaults.iter().enumerate() {
        if let Err(e) = stmt.execute(params![name, host, category, i as i64]) {
            warn!("Seed probe_targets insert failed for {name}: {e}");
        }
    }
    info!("Seeded {} default probe targets", defaults.len());
}

#[cfg(test)]
mod security_tests {
    use super::*;

    fn memory_db() -> TrafficDb {
        TrafficDb::open(&PathBuf::from(":memory:")).unwrap()
    }

    fn standard_session(id: &str, token_byte: u8, absolute_expires_at: i64) -> AuthSessionRecord {
        AuthSessionRecord {
            id: id.into(),
            token_hash: vec![token_byte; 32],
            csrf_hash: vec![token_byte.saturating_add(1); 32],
            username: "admin".into(),
            role: "admin".into(),
            kind: "standard".into(),
            label: None,
            created_at: 100,
            last_seen_at: 100,
            idle_expires_at: Some(43_300),
            absolute_expires_at,
            revoked_at: None,
        }
    }

    fn pairing(id: &str, role: &str, expires_at: i64) -> PairingRecord {
        PairingRecord {
            id: id.into(),
            role: role.into(),
            label: format!("{role} display"),
            expires_at,
        }
    }

    fn insert_pairing(
        db: &TrafficDb,
        record: &PairingRecord,
        code_byte: u8,
        creator: &AuthSessionRecord,
    ) {
        assert!(db
            .insert_pairing_if_authorized(
                record,
                &[code_byte; 32],
                &creator.id,
                &creator.username,
                &creator.role,
                &creator.kind,
                100,
                Some(1),
            )
            .unwrap());
    }

    #[test]
    fn http_session_touch_is_throttled_to_five_minutes() {
        let db = memory_db();
        let session = standard_session("session-1", 1, 999_999);
        db.insert_session(&session).unwrap();

        assert!(db
            .touch_session_if_active_throttled("session-1", "admin", "admin", "standard", 399, 300,)
            .unwrap());
        let untouched = db.session_by_token_hash(&[1; 32]).unwrap().unwrap();
        assert_eq!(untouched.last_seen_at, 100);
        assert_eq!(untouched.idle_expires_at, Some(43_300));

        assert!(db
            .touch_session_if_active_throttled("session-1", "admin", "admin", "standard", 400, 300,)
            .unwrap());
        let updated = db.session_by_token_hash(&[1; 32]).unwrap().unwrap();
        assert_eq!(updated.last_seen_at, 400);
        assert_eq!(updated.idle_expires_at, Some(43_600));

        assert!(db
            .touch_session_if_active_throttled("session-1", "admin", "admin", "standard", 699, 300,)
            .unwrap());
        assert_eq!(
            db.session_by_token_hash(&[1; 32])
                .unwrap()
                .unwrap()
                .last_seen_at,
            400
        );
    }

    #[test]
    fn websocket_revalidation_is_read_only_and_rejects_revocation() {
        let db = memory_db();
        let session = standard_session("session-1", 1, 999_999);
        db.insert_session(&session).unwrap();
        assert!(db
            .session_is_active("session-1", "admin", "admin", "standard", 200)
            .unwrap());
        let unchanged = db.session_by_token_hash(&[1; 32]).unwrap().unwrap();
        assert_eq!(unchanged.last_seen_at, 100);
        assert_eq!(unchanged.idle_expires_at, Some(43_300));

        db.revoke_session("session-1", 150).unwrap();
        assert!(!db
            .session_is_active("session-1", "admin", "admin", "standard", 200)
            .unwrap());
    }

    #[test]
    fn standard_session_insert_rechecks_credential_version() {
        let db = memory_db();
        db.create_admin("admin", "hash-v1").unwrap();
        let first = standard_session("session-1", 1, 999_999);
        assert!(db
            .insert_standard_session_if_admin_version(&first, 1)
            .unwrap());

        db.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE admins SET credential_version = credential_version + 1",
                [],
            )
            .unwrap();
        let stale = standard_session("session-2", 3, 999_999);
        assert!(!db
            .insert_standard_session_if_admin_version(&stale, 1)
            .unwrap());
        assert!(db.session_by_token_hash(&[3; 32]).unwrap().is_none());
    }

    #[test]
    fn admin_pairing_insert_rechecks_credential_version() {
        let db = memory_db();
        db.create_admin("admin", "hash-v1").unwrap();
        let creator = standard_session("creator", 1, 999_999);
        db.insert_session(&creator).unwrap();
        db.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE admins SET credential_version = credential_version + 1",
                [],
            )
            .unwrap();

        assert!(!db
            .insert_pairing_if_authorized(
                &pairing("pairing-1", "admin", 1_000),
                &[9; 32],
                &creator.id,
                &creator.username,
                &creator.role,
                &creator.kind,
                100,
                Some(1),
            )
            .unwrap());
    }

    #[test]
    fn password_reset_revokes_sessions_and_invalidates_pairings() {
        let db = memory_db();
        db.create_admin("admin", "hash-v1").unwrap();
        let creator = standard_session("creator", 1, 999_999);
        db.insert_session(&creator).unwrap();
        insert_pairing(&db, &pairing("pairing-1", "viewer", 1_000), 9, &creator);

        db.replace_admin_password("admin", "hash-v2").unwrap();
        assert_eq!(db.admin().unwrap().unwrap().credential_version, 2);
        assert!(!db
            .session_is_active("creator", "admin", "admin", "standard", 200)
            .unwrap());
        assert!(db
            .consume_pairing_and_insert_session(
                &[9; 32], 200, "fixed", &[10; 32], &[11; 32], 1_000, 1_000,
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn pairing_consume_rejects_expired_and_revoked_creators() {
        let expired_db = memory_db();
        expired_db.create_admin("admin", "hash").unwrap();
        let expiring_creator = standard_session("expiring", 1, 150);
        expired_db.insert_session(&expiring_creator).unwrap();
        insert_pairing(
            &expired_db,
            &pairing("pairing-expired", "viewer", 1_000),
            9,
            &expiring_creator,
        );
        assert!(expired_db
            .consume_pairing_and_insert_session(
                &[9; 32],
                200,
                "fixed-expired",
                &[10; 32],
                &[11; 32],
                1_000,
                1_000,
            )
            .unwrap()
            .is_none());

        let revoked_db = memory_db();
        revoked_db.create_admin("admin", "hash").unwrap();
        let revoked_creator = standard_session("revoked", 1, 999_999);
        revoked_db.insert_session(&revoked_creator).unwrap();
        insert_pairing(
            &revoked_db,
            &pairing("pairing-revoked", "viewer", 1_000),
            9,
            &revoked_creator,
        );
        revoked_db.revoke_session("revoked", 150).unwrap();
        assert!(revoked_db
            .consume_pairing_and_insert_session(
                &[9; 32],
                200,
                "fixed-revoked",
                &[10; 32],
                &[11; 32],
                1_000,
                1_000,
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn pairing_consume_and_session_insert_rollback_together() {
        let db = memory_db();
        db.create_admin("admin", "hash").unwrap();
        let creator = standard_session("creator", 1, 999_999);
        db.insert_session(&creator).unwrap();
        insert_pairing(&db, &pairing("pairing-1", "viewer", 1_000), 9, &creator);

        assert!(db
            .consume_pairing_and_insert_session(
                &[9; 32], 200, "creator", &[10; 32], &[11; 32], 1_000, 1_000,
            )
            .is_err());
        let fixed = db
            .consume_pairing_and_insert_session(
                &[9; 32], 200, "fixed", &[10; 32], &[11; 32], 1_000, 1_000,
            )
            .unwrap()
            .unwrap();
        assert_eq!(fixed.role, "viewer");
        assert!(db
            .consume_pairing_and_insert_session(
                &[9; 32], 200, "fixed-2", &[12; 32], &[13; 32], 1_000, 1_000,
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn security_schema_migrates_existing_admin_credential_version() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE admins (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 username TEXT NOT NULL UNIQUE,
                 password_hash TEXT NOT NULL,
                 created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                 updated_at INTEGER NOT NULL DEFAULT (unixepoch())
             );
             INSERT INTO admins(id, username, password_hash) VALUES (1, 'admin', 'hash');",
        )
        .unwrap();

        schema::bootstrap_security_schema(&mut conn).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT credential_version FROM admins WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );
        assert!(conn
            .prepare("SELECT 1 FROM schema_migrations WHERE name = 'admin_credential_version_v1'",)
            .unwrap()
            .exists([])
            .unwrap());
    }

    #[test]
    fn config_revision_check_is_atomic() {
        let db = memory_db();
        assert!(db
            .save_config_transaction(&[("theme".into(), "dark".into())], None, None, Some(0),)
            .unwrap());
        assert!(!db
            .save_config_transaction(&[("theme".into(), "light".into())], None, None, Some(0),)
            .unwrap());
        let config = db.get_all_config().unwrap();
        assert_eq!(config.get("theme").map(String::as_str), Some("dark"));
        assert_eq!(config.get("config_revision").map(String::as_str), Some("1"));
    }

    #[test]
    fn plaintext_password_migration_scrubs_database_and_wal_bytes() {
        let path = std::env::temp_dir().join(format!(
            "routerview-secret-migration-{}.db",
            uuid::Uuid::new_v4()
        ));
        let plaintext = b"legacy-router-password-unique-fixture";
        let db = TrafficDb::open(&path).unwrap();
        db.set_config("routeros_password", std::str::from_utf8(plaintext).unwrap())
            .unwrap();

        let encrypted = EncryptedSecret {
            ciphertext: vec![7; 64],
            nonce: vec![8; 24],
            key_id: "fixture-key".into(),
        };
        db.migrate_plaintext_router_password(&encrypted).unwrap();
        assert!(!db
            .get_all_config()
            .unwrap()
            .contains_key("routeros_password"));
        drop(db);

        let paths = [
            path.clone(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
            PathBuf::from(format!("{}-journal", path.display())),
        ];
        for candidate in &paths {
            if let Ok(bytes) = std::fs::read(candidate) {
                assert!(
                    !bytes
                        .windows(plaintext.len())
                        .any(|window| window == plaintext),
                    "plaintext remained in {}",
                    candidate.display()
                );
            }
        }
        for candidate in &paths {
            let _ = std::fs::remove_file(candidate);
        }
    }
}
