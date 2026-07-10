use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::types::{BackupArtifact, DatabaseError, DatabaseResult, CURRENT_SCHEMA_VERSION};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LegacyCounts {
    pub traffic_points: u64,
    pub traffic_1m: u64,
}

pub fn user_version(conn: &Connection) -> DatabaseResult<i64> {
    Ok(conn.query_row("PRAGMA user_version", [], |row| row.get(0))?)
}

pub fn legacy_counts(conn: &Connection) -> DatabaseResult<LegacyCounts> {
    Ok(LegacyCounts {
        traffic_points: table_count_if_present(conn, "traffic_points")?,
        traffic_1m: table_count_if_present(conn, "traffic_1m")?,
    })
}

pub fn has_user_tables(conn: &Connection) -> DatabaseResult<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
         )",
        [],
        |row| row.get(0),
    )?)
}

pub fn bootstrap_security_schema(conn: &mut Connection) -> DatabaseResult<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS config (
             key   TEXT PRIMARY KEY,
             value TEXT NOT NULL
         );",
    )?;
    migrate_v3_security(&tx)?;
    tx.commit()?;
    Ok(())
}

pub fn apply_migrations(
    conn: &mut Connection,
    original_version: i64,
    backup: Option<&BackupArtifact>,
) -> DatabaseResult<()> {
    if original_version > CURRENT_SCHEMA_VERSION {
        return Err(DatabaseError::UnsupportedVersion {
            found: original_version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    if original_version == CURRENT_SCHEMA_VERSION {
        return Ok(());
    }

    let before = legacy_counts(conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = (|| -> DatabaseResult<()> {
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS database_migrations (
                 version                 INTEGER PRIMARY KEY,
                 name                    TEXT NOT NULL,
                 source_version          INTEGER NOT NULL,
                 applied_at              INTEGER NOT NULL DEFAULT (unixepoch()),
                 backup_path             TEXT,
                 backup_sha256           TEXT,
                 legacy_points_count     INTEGER NOT NULL,
                 legacy_rollups_count    INTEGER NOT NULL
             );",
        )?;
        if original_version < 1 {
            migrate_v1_core(&tx)?;
            record_migration(&tx, 1, "core_schema", original_version, backup, before)?;
        }
        if original_version < 2 {
            migrate_v2_legacy_composite_keys(&tx)?;
            record_migration(
                &tx,
                2,
                "legacy_traffic_composite_keys",
                original_version,
                backup,
                before,
            )?;
        }
        if original_version < 3 {
            migrate_v3_security(&tx)?;
            record_migration(
                &tx,
                3,
                "security_and_configuration",
                original_version,
                backup,
                before,
            )?;
        }
        if original_version < 4 {
            migrate_v4_exact_traffic(&tx, before)?;
            record_migration(
                &tx,
                4,
                "router_scoped_exact_traffic",
                original_version,
                backup,
                before,
            )?;
        }
        if original_version < 5 {
            migrate_v5_rollup_cutoff_index(&tx)?;
            record_migration(
                &tx,
                5,
                "traffic_rollup_cutoff_index",
                original_version,
                backup,
                before,
            )?;
        }

        let after = legacy_counts(&tx)?;
        if before != after {
            return Err(DatabaseError::Verification(format!(
                "legacy row counts changed during migration: before={before:?}, after={after:?}"
            )));
        }
        let foreign_key_violations: i64 =
            tx.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })?;
        if foreign_key_violations != 0 {
            return Err(DatabaseError::Verification(format!(
                "migration produced {foreign_key_violations} foreign-key violations"
            )));
        }
        tx.execute_batch(&format!("PRAGMA user_version = {CURRENT_SCHEMA_VERSION};"))?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            tx.commit()?;
            Ok(())
        }
        Err(error) => {
            let _ = tx.rollback();
            Err(error)
        }
    }
}

fn migrate_v1_core(conn: &Connection) -> DatabaseResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS traffic_points (
             ts           INTEGER NOT NULL,
             download_bps REAL NOT NULL,
             upload_bps   REAL NOT NULL,
             wan_name     TEXT NOT NULL DEFAULT '',
             PRIMARY KEY (ts, wan_name)
         );
         CREATE TABLE IF NOT EXISTS traffic_1m (
             bucket       INTEGER NOT NULL,
             download_avg REAL NOT NULL,
             upload_avg   REAL NOT NULL,
             wan_name     TEXT NOT NULL DEFAULT '',
             PRIMARY KEY (bucket, wan_name)
         );
         CREATE TABLE IF NOT EXISTS config (
             key   TEXT PRIMARY KEY,
             value TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS device_overrides (
             mac         TEXT PRIMARY KEY,
             custom_name TEXT,
             custom_type TEXT,
             updated_at  INTEGER NOT NULL DEFAULT (unixepoch())
         );
         CREATE TABLE IF NOT EXISTS probe_targets (
             id         INTEGER PRIMARY KEY AUTOINCREMENT,
             name       TEXT NOT NULL,
             host       TEXT NOT NULL,
             category   TEXT NOT NULL DEFAULT 'custom',
             sort_order INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS database_migrations (
             version                 INTEGER PRIMARY KEY,
             name                    TEXT NOT NULL,
             source_version          INTEGER NOT NULL,
             applied_at              INTEGER NOT NULL DEFAULT (unixepoch()),
             backup_path             TEXT,
             backup_sha256           TEXT,
             legacy_points_count     INTEGER NOT NULL,
             legacy_rollups_count    INTEGER NOT NULL
         );",
    )?;
    Ok(())
}

fn migrate_v2_legacy_composite_keys(conn: &Connection) -> DatabaseResult<()> {
    normalize_legacy_table(conn, LegacyTable::Points)?;
    normalize_legacy_table(conn, LegacyTable::MinuteRollups)?;
    Ok(())
}

fn migrate_v3_security(conn: &Connection) -> DatabaseResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             name       TEXT PRIMARY KEY,
             applied_at INTEGER NOT NULL DEFAULT (unixepoch())
         );
         CREATE TABLE IF NOT EXISTS encrypted_secrets (
             name       TEXT PRIMARY KEY,
             ciphertext BLOB NOT NULL,
             nonce      BLOB NOT NULL,
             key_id     TEXT NOT NULL,
             updated_at INTEGER NOT NULL DEFAULT (unixepoch())
         );
         CREATE TABLE IF NOT EXISTS admins (
             id                 INTEGER PRIMARY KEY CHECK (id = 1),
             username           TEXT NOT NULL UNIQUE,
             password_hash      TEXT NOT NULL,
             credential_version INTEGER NOT NULL DEFAULT 1 CHECK (credential_version > 0),
             created_at         INTEGER NOT NULL DEFAULT (unixepoch()),
             updated_at         INTEGER NOT NULL DEFAULT (unixepoch())
         );
         CREATE TABLE IF NOT EXISTS auth_sessions (
             id                  TEXT PRIMARY KEY,
             token_hash          BLOB NOT NULL UNIQUE,
             csrf_hash           BLOB NOT NULL,
             username            TEXT NOT NULL,
             role                TEXT NOT NULL CHECK (role IN ('viewer', 'admin')),
             kind                TEXT NOT NULL CHECK (kind IN ('standard', 'fixed')),
             label               TEXT,
             created_at          INTEGER NOT NULL,
             last_seen_at        INTEGER NOT NULL,
             idle_expires_at     INTEGER,
             absolute_expires_at INTEGER NOT NULL,
             revoked_at          INTEGER
         );
         CREATE INDEX IF NOT EXISTS idx_auth_sessions_token
             ON auth_sessions(token_hash);
         CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry
             ON auth_sessions(absolute_expires_at, revoked_at);
         CREATE TABLE IF NOT EXISTS pairing_codes (
             id                    TEXT PRIMARY KEY,
             code_hash             BLOB NOT NULL UNIQUE,
             role                  TEXT NOT NULL CHECK (role IN ('viewer', 'admin')),
             label                 TEXT NOT NULL,
             created_by_session_id TEXT NOT NULL,
             created_at            INTEGER NOT NULL,
             expires_at            INTEGER NOT NULL,
             used_at               INTEGER,
             FOREIGN KEY(created_by_session_id) REFERENCES auth_sessions(id)
         );
         CREATE TABLE IF NOT EXISTS setup_tokens (
             id         INTEGER PRIMARY KEY CHECK (id = 1),
             token_hash BLOB NOT NULL,
             expires_at INTEGER NOT NULL,
             used_at    INTEGER
         );
         INSERT OR IGNORE INTO schema_migrations(name)
             VALUES ('security_auth_secrets_v1');",
    )?;

    let has_credential_version = conn
        .prepare("SELECT 1 FROM pragma_table_info('admins') WHERE name = 'credential_version'")?
        .exists([])?;
    if !has_credential_version {
        conn.execute(
            "ALTER TABLE admins ADD COLUMN credential_version INTEGER NOT NULL DEFAULT 1
             CHECK (credential_version > 0)",
            [],
        )?;
    }
    conn.execute(
        "INSERT OR IGNORE INTO schema_migrations(name)
         VALUES ('admin_credential_version_v1')",
        [],
    )?;
    Ok(())
}

fn migrate_v4_exact_traffic(conn: &Connection, legacy: LegacyCounts) -> DatabaseResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS routers (
             id                INTEGER PRIMARY KEY AUTOINCREMENT,
             internal_uuid     TEXT NOT NULL UNIQUE,
             hardware_identity TEXT,
             fallback_target   TEXT NOT NULL,
             identity_source   TEXT NOT NULL DEFAULT 'fallback'
                 CHECK (identity_source IN ('hardware', 'fallback', 'legacy')),
             first_seen_at_ms  INTEGER NOT NULL,
             last_seen_at_ms   INTEGER NOT NULL
         );
         CREATE UNIQUE INDEX IF NOT EXISTS idx_routers_hardware_identity
             ON routers(hardware_identity) WHERE hardware_identity IS NOT NULL;
         CREATE INDEX IF NOT EXISTS idx_routers_fallback_target
             ON routers(fallback_target, hardware_identity);

         CREATE TABLE IF NOT EXISTS router_interfaces (
             id                INTEGER PRIMARY KEY AUTOINCREMENT,
             router_id         INTEGER NOT NULL,
             interface_key     TEXT NOT NULL,
             name              TEXT NOT NULL,
             kind              TEXT NOT NULL DEFAULT 'unknown',
             hardware_id       TEXT,
             first_seen_at_ms  INTEGER NOT NULL,
             last_seen_at_ms   INTEGER NOT NULL,
             UNIQUE(router_id, interface_key),
             FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
         );

         CREATE TABLE IF NOT EXISTS traffic_samples (
             id             INTEGER PRIMARY KEY AUTOINCREMENT,
             router_id      INTEGER NOT NULL,
             interface_id   INTEGER NOT NULL,
             started_at_ms  INTEGER NOT NULL,
             ended_at_ms    INTEGER NOT NULL,
             duration_ms    INTEGER NOT NULL CHECK (duration_ms > 0),
             download_bytes INTEGER NOT NULL CHECK (download_bytes >= 0),
             upload_bytes   INTEGER NOT NULL CHECK (upload_bytes >= 0),
             download_bps   REAL NOT NULL CHECK (download_bps >= 0),
             upload_bps     REAL NOT NULL CHECK (upload_bps >= 0),
             quality        TEXT NOT NULL CHECK (quality IN ('exact', 'estimated')),
             source         TEXT NOT NULL,
             created_at_ms  INTEGER NOT NULL,
             UNIQUE(router_id, interface_id, ended_at_ms, source),
             CHECK (ended_at_ms > started_at_ms),
             FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE,
             FOREIGN KEY(interface_id) REFERENCES router_interfaces(id) ON DELETE CASCADE
         );
         CREATE INDEX IF NOT EXISTS idx_traffic_samples_range
             ON traffic_samples(router_id, interface_id, ended_at_ms);

         CREATE TABLE IF NOT EXISTS traffic_rollups (
             id                       INTEGER PRIMARY KEY AUTOINCREMENT,
             router_id                INTEGER NOT NULL,
             interface_id             INTEGER NOT NULL,
             bucket_start_ms          INTEGER NOT NULL,
             bucket_end_ms            INTEGER NOT NULL,
             bucket_size_ms           INTEGER NOT NULL CHECK (bucket_size_ms > 0),
             exact_download_bytes     INTEGER NOT NULL DEFAULT 0 CHECK (exact_download_bytes >= 0),
             exact_upload_bytes       INTEGER NOT NULL DEFAULT 0 CHECK (exact_upload_bytes >= 0),
             estimated_download_bytes INTEGER NOT NULL DEFAULT 0 CHECK (estimated_download_bytes >= 0),
             estimated_upload_bytes   INTEGER NOT NULL DEFAULT 0 CHECK (estimated_upload_bytes >= 0),
             exact_duration_ms        INTEGER NOT NULL DEFAULT 0 CHECK (exact_duration_ms >= 0),
             estimated_duration_ms    INTEGER NOT NULL DEFAULT 0 CHECK (estimated_duration_ms >= 0),
             sample_count             INTEGER NOT NULL CHECK (sample_count > 0),
             download_avg_bps         REAL NOT NULL DEFAULT 0 CHECK (download_avg_bps >= 0),
             upload_avg_bps           REAL NOT NULL DEFAULT 0 CHECK (upload_avg_bps >= 0),
             source                   TEXT NOT NULL,
             created_at_ms            INTEGER NOT NULL,
             UNIQUE(router_id, interface_id, bucket_size_ms, bucket_start_ms, source),
             CHECK (bucket_end_ms > bucket_start_ms),
             FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE,
             FOREIGN KEY(interface_id) REFERENCES router_interfaces(id) ON DELETE CASCADE
         );
         CREATE INDEX IF NOT EXISTS idx_traffic_rollups_range
             ON traffic_rollups(router_id, interface_id, bucket_size_ms, bucket_start_ms);

         CREATE TABLE IF NOT EXISTS counter_checkpoints (
             router_id       INTEGER NOT NULL,
             interface_id    INTEGER NOT NULL,
             rx_counter      TEXT NOT NULL,
             tx_counter      TEXT NOT NULL,
             observed_at_ms  INTEGER NOT NULL,
             reboot_marker   TEXT,
             PRIMARY KEY(router_id, interface_id),
             FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE,
             FOREIGN KEY(interface_id) REFERENCES router_interfaces(id) ON DELETE CASCADE
         );

         CREATE TABLE IF NOT EXISTS traffic_gaps (
             id             INTEGER PRIMARY KEY AUTOINCREMENT,
             router_id      INTEGER NOT NULL,
             interface_id   INTEGER,
             started_at_ms  INTEGER NOT NULL,
             ended_at_ms    INTEGER NOT NULL,
             reason         TEXT NOT NULL,
             details        TEXT,
             created_at_ms  INTEGER NOT NULL,
             UNIQUE(router_id, interface_id, started_at_ms, ended_at_ms, reason),
             CHECK (ended_at_ms > started_at_ms),
             FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE,
             FOREIGN KEY(interface_id) REFERENCES router_interfaces(id) ON DELETE CASCADE
         );
         CREATE INDEX IF NOT EXISTS idx_traffic_gaps_range
             ON traffic_gaps(router_id, interface_id, started_at_ms, ended_at_ms);",
    )?;

    if legacy.traffic_points == 0 && legacy.traffic_1m == 0 {
        return Ok(());
    }

    let now_ms = chrono::Utc::now().timestamp_millis();
    let legacy_uuid = "routerview-legacy-unidentified";
    conn.execute(
        "INSERT OR IGNORE INTO routers(
             internal_uuid, hardware_identity, fallback_target, identity_source,
             first_seen_at_ms, last_seen_at_ms
         ) VALUES (?1, NULL, 'legacy://unidentified', 'legacy', ?2, ?2)",
        params![legacy_uuid, now_ms],
    )?;
    let router_id: i64 = conn.query_row(
        "SELECT id FROM routers WHERE internal_uuid = ?1",
        params![legacy_uuid],
        |row| row.get(0),
    )?;

    conn.execute(
        "INSERT OR IGNORE INTO router_interfaces(
             router_id, interface_key, name, kind, first_seen_at_ms, last_seen_at_ms
         )
         SELECT ?1,
                CASE WHEN wan_name = '' THEN '__aggregate__' ELSE 'legacy:' || wan_name END,
                CASE WHEN wan_name = '' THEN 'Aggregate' ELSE wan_name END,
                CASE WHEN wan_name = '' THEN 'aggregate' ELSE 'wan' END,
                ?2, ?2
         FROM (
             SELECT DISTINCT COALESCE(wan_name, '') AS wan_name FROM traffic_points
             UNION
             SELECT DISTINCT COALESCE(wan_name, '') AS wan_name FROM traffic_1m
         )",
        params![router_id, now_ms],
    )?;

    conn.execute(
        "WITH ordered_points AS (
             SELECT points.*,
                    LAG(points.ts) OVER (
                        PARTITION BY COALESCE(points.wan_name, '') ORDER BY points.ts
                    ) AS previous_ts
             FROM traffic_points AS points
         ), measured_points AS (
             SELECT ordered_points.*,
                    MIN(60000, MAX(1, ts - COALESCE(previous_ts, ts - 5000))) AS measured_ms
             FROM ordered_points
         )
         INSERT OR IGNORE INTO traffic_samples(
             router_id, interface_id, started_at_ms, ended_at_ms, duration_ms,
             download_bytes, upload_bytes, download_bps, upload_bps,
             quality, source, created_at_ms
         )
         SELECT ?1, interface.id, points.ts - points.measured_ms, points.ts, points.measured_ms,
                CAST(MAX(0, ROUND(points.download_bps * points.measured_ms / 8000.0)) AS INTEGER),
                CAST(MAX(0, ROUND(points.upload_bps * points.measured_ms / 8000.0)) AS INTEGER),
                MAX(0, points.download_bps), MAX(0, points.upload_bps),
                'estimated', 'legacy-traffic_points', ?2
         FROM measured_points AS points
         JOIN router_interfaces AS interface
           ON interface.router_id = ?1
          AND interface.interface_key = CASE
                WHEN COALESCE(points.wan_name, '') = '' THEN '__aggregate__'
                ELSE 'legacy:' || points.wan_name
              END",
        params![router_id, now_ms],
    )?;

    conn.execute(
        "INSERT OR IGNORE INTO traffic_rollups(
             router_id, interface_id, bucket_start_ms, bucket_end_ms, bucket_size_ms,
             exact_download_bytes, exact_upload_bytes,
             estimated_download_bytes, estimated_upload_bytes,
             exact_duration_ms, estimated_duration_ms, sample_count,
             download_avg_bps, upload_avg_bps, source, created_at_ms
         )
         SELECT ?1, interface.id, minute.bucket, minute.bucket + 60000, 60000,
                0, 0,
                CAST(MAX(0, ROUND(minute.download_avg * 60.0 / 8.0)) AS INTEGER),
                CAST(MAX(0, ROUND(minute.upload_avg * 60.0 / 8.0)) AS INTEGER),
                0, 60000, 1,
                MAX(0, minute.download_avg), MAX(0, minute.upload_avg),
                'legacy-traffic_1m', ?2
         FROM traffic_1m AS minute
         JOIN router_interfaces AS interface
           ON interface.router_id = ?1
          AND interface.interface_key = CASE
                WHEN COALESCE(minute.wan_name, '') = '' THEN '__aggregate__'
                ELSE 'legacy:' || minute.wan_name
              END
         WHERE NOT EXISTS (
             SELECT 1
             FROM traffic_samples AS sample
             WHERE sample.router_id = ?1
               AND sample.interface_id = interface.id
               AND sample.source = 'legacy-traffic_points'
               AND sample.ended_at_ms > minute.bucket
               AND sample.started_at_ms < minute.bucket + 60000
         )",
        params![router_id, now_ms],
    )?;

    let imported_points: u64 = conn.query_row(
        "SELECT COUNT(*) FROM traffic_samples WHERE source = 'legacy-traffic_points'",
        [],
        |row| row.get(0),
    )?;
    let imported_rollups: u64 = conn.query_row(
        "SELECT COUNT(*) FROM traffic_rollups WHERE source = 'legacy-traffic_1m'",
        [],
        |row| row.get(0),
    )?;
    let expected_rollups: u64 = conn.query_row(
        "SELECT COUNT(*)
         FROM traffic_1m AS minute
         JOIN router_interfaces AS interface
           ON interface.router_id = ?1
          AND interface.interface_key = CASE
                WHEN COALESCE(minute.wan_name, '') = '' THEN '__aggregate__'
                ELSE 'legacy:' || minute.wan_name
              END
         WHERE NOT EXISTS (
             SELECT 1
             FROM traffic_samples AS sample
             WHERE sample.router_id = ?1
               AND sample.interface_id = interface.id
               AND sample.source = 'legacy-traffic_points'
               AND sample.ended_at_ms > minute.bucket
               AND sample.started_at_ms < minute.bucket + 60000
         )",
        params![router_id],
        |row| row.get(0),
    )?;
    if imported_points != legacy.traffic_points || imported_rollups != expected_rollups {
        return Err(DatabaseError::Verification(format!(
            "legacy import count mismatch: expected points={}, eligible rollups={expected_rollups}; imported points={imported_points}, rollups={imported_rollups}",
            legacy.traffic_points,
        )));
    }
    Ok(())
}

fn migrate_v5_rollup_cutoff_index(conn: &Connection) -> DatabaseResult<()> {
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_traffic_samples_rollup_cutoff
             ON traffic_samples(started_at_ms, id);",
    )?;
    Ok(())
}

fn record_migration(
    conn: &Connection,
    version: i64,
    name: &str,
    source_version: i64,
    backup: Option<&BackupArtifact>,
    legacy: LegacyCounts,
) -> DatabaseResult<()> {
    conn.execute(
        "INSERT INTO database_migrations(
             version, name, source_version, backup_path, backup_sha256,
             legacy_points_count, legacy_rollups_count
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(version) DO NOTHING",
        params![
            version,
            name,
            source_version,
            backup.map(|item| item.path.to_string_lossy().into_owned()),
            backup.map(|item| item.sha256.as_str()),
            legacy.traffic_points,
            legacy.traffic_1m,
        ],
    )?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum LegacyTable {
    Points,
    MinuteRollups,
}

impl LegacyTable {
    fn name(self) -> &'static str {
        match self {
            Self::Points => "traffic_points",
            Self::MinuteRollups => "traffic_1m",
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::Points => "ts",
            Self::MinuteRollups => "bucket",
        }
    }

    fn create_sql(self) -> &'static str {
        match self {
            Self::Points => {
                "CREATE TABLE traffic_points (
                     ts           INTEGER NOT NULL,
                     download_bps REAL NOT NULL,
                     upload_bps   REAL NOT NULL,
                     wan_name     TEXT NOT NULL DEFAULT '',
                     PRIMARY KEY (ts, wan_name)
                 )"
            }
            Self::MinuteRollups => {
                "CREATE TABLE traffic_1m (
                     bucket       INTEGER NOT NULL,
                     download_avg REAL NOT NULL,
                     upload_avg   REAL NOT NULL,
                     wan_name     TEXT NOT NULL DEFAULT '',
                     PRIMARY KEY (bucket, wan_name)
                 )"
            }
        }
    }

    fn rate_columns(self) -> (&'static str, &'static str) {
        match self {
            Self::Points => ("download_bps", "upload_bps"),
            Self::MinuteRollups => ("download_avg", "upload_avg"),
        }
    }
}

fn normalize_legacy_table(conn: &Connection, table: LegacyTable) -> DatabaseResult<()> {
    let name = table.name();
    if !table_exists(conn, name)? {
        conn.execute_batch(table.create_sql())?;
        return Ok(());
    }

    let has_wan_name = conn
        .prepare(&format!(
            "SELECT 1 FROM pragma_table_info('{name}') WHERE name = 'wan_name'"
        ))?
        .exists([])?;
    let wan_in_primary_key = conn
        .prepare(&format!(
            "SELECT 1 FROM pragma_table_info('{name}') WHERE name = 'wan_name' AND pk > 0"
        ))?
        .exists([])?;
    let wan_not_null = conn
        .prepare(&format!(
            "SELECT 1 FROM pragma_table_info('{name}') WHERE name = 'wan_name' AND \"notnull\" = 1"
        ))?
        .exists([])?;
    if has_wan_name && wan_in_primary_key && wan_not_null {
        return Ok(());
    }

    let temporary = format!("__routerview_{name}_v1");
    if table_exists(conn, &temporary)? {
        return Err(DatabaseError::Verification(format!(
            "temporary migration table {temporary} already exists"
        )));
    }
    let before = table_count_if_present(conn, name)?;
    conn.execute_batch(&format!("ALTER TABLE {name} RENAME TO {temporary};"))?;
    conn.execute_batch(table.create_sql())?;

    let key = table.key();
    let (download, upload) = table.rate_columns();
    let wan_expression = if has_wan_name {
        "COALESCE(wan_name, '')"
    } else {
        "''"
    };
    conn.execute_batch(&format!(
        "INSERT INTO {name}({key}, {download}, {upload}, wan_name)
         SELECT {key}, {download}, {upload}, {wan_expression} FROM {temporary};"
    ))?;
    let after = table_count_if_present(conn, name)?;
    if before != after {
        return Err(DatabaseError::Verification(format!(
            "{name} row count changed while normalizing primary key: {before} -> {after}"
        )));
    }
    conn.execute_batch(&format!("DROP TABLE {temporary};"))?;
    Ok(())
}

fn table_exists(conn: &Connection, table: &str) -> DatabaseResult<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1",
            params![table],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn table_count_if_present(conn: &Connection, table: &str) -> DatabaseResult<u64> {
    if !table_exists(conn, table)? {
        return Ok(0);
    }
    let sql = match table {
        "traffic_points" => "SELECT COUNT(*) FROM traffic_points",
        "traffic_1m" => "SELECT COUNT(*) FROM traffic_1m",
        _ => {
            return Err(DatabaseError::Verification(format!(
                "unsupported legacy table {table}"
            )))
        }
    };
    Ok(conn.query_row(sql, [], |row| row.get(0))?)
}
