use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, MAIN_DB};
use sha2::{Digest, Sha256};

use super::schema;
use super::types::{
    BackupArtifact, DatabaseError, DatabaseReport, DatabaseResult, MigrationReport,
    QuarantineArtifact, RestoreReport, CURRENT_SCHEMA_VERSION,
};

const MIGRATION_SPACE_NUMERATOR: u64 = 22;
const MIGRATION_SPACE_DENOMINATOR: u64 = 10;

pub(crate) struct DatabaseLock {
    _file: File,
}

impl DatabaseLock {
    pub(crate) fn acquire(database_path: &Path) -> DatabaseResult<Self> {
        let path = lock_path(database_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error
                .raw_os_error()
                .is_some_and(|code| code == libc::EWOULDBLOCK || code == libc::EAGAIN)
            {
                return Err(DatabaseError::InUse(database_path.to_path_buf()));
            }
            return Err(DatabaseError::Io(error));
        }
        file.set_len(0)?;
        writeln!(&file, "{}", std::process::id())?;
        file.sync_all()?;
        Ok(Self { _file: file })
    }
}

impl Drop for DatabaseLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self._file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(test)]
pub(crate) fn open_runtime(
    path: &Path,
) -> DatabaseResult<(Connection, Option<DatabaseLock>, MigrationReport)> {
    if is_memory_path(path) {
        let mut conn = Connection::open_in_memory()?;
        configure_preflight(&conn)?;
        let from_version = schema::user_version(&conn)?;
        schema::apply_migrations(&mut conn, from_version, None)?;
        configure_runtime(&conn)?;
        return Ok((
            conn,
            None,
            MigrationReport {
                path: path.to_path_buf(),
                from_version,
                to_version: CURRENT_SCHEMA_VERSION,
                backup: None,
            },
        ));
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let lock = DatabaseLock::acquire(path)?;
    let mut conn = Connection::open(path)?;
    validate_bootstrap_source(path, &conn)?;
    set_private_permissions(path)?;
    configure_preflight(&conn)?;
    let report = migrate_connection(path, &mut conn, default_backup_dir(path))?;
    configure_runtime(&conn)?;
    Ok((conn, Some(lock), report))
}

pub(crate) fn open_bootstrap_runtime(
    path: &Path,
) -> DatabaseResult<(Connection, Option<DatabaseLock>)> {
    if is_memory_path(path) {
        let mut conn = Connection::open_in_memory()?;
        validate_bootstrap_source(path, &conn)?;
        configure_preflight(&conn)?;
        schema::bootstrap_security_schema(&mut conn)?;
        return Ok((conn, None));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let lock = DatabaseLock::acquire(path)?;
    let mut conn = Connection::open(path)?;
    validate_bootstrap_source(path, &conn)?;
    set_private_permissions(path)?;
    configure_preflight(&conn)?;
    schema::bootstrap_security_schema(&mut conn)?;
    Ok((conn, Some(lock)))
}

fn validate_bootstrap_source(path: &Path, conn: &Connection) -> DatabaseResult<()> {
    let version = schema::user_version(conn)?;
    if version > CURRENT_SCHEMA_VERSION {
        return Err(DatabaseError::UnsupportedVersion {
            found: version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    check_connection(path, conn)?;
    Ok(())
}

pub(crate) fn finish_runtime_migration(
    path: &Path,
    conn: &mut Connection,
) -> DatabaseResult<MigrationReport> {
    let report = migrate_connection(path, conn, default_backup_dir(path))?;
    configure_runtime(conn)?;
    Ok(report)
}

pub fn check_database(path: &Path) -> DatabaseResult<DatabaseReport> {
    let conn = open_read_only(path)?;
    check_connection(path, &conn)
}

pub fn migrate_database(path: &Path, backup_dir: Option<&Path>) -> DatabaseResult<MigrationReport> {
    if is_memory_path(path) {
        return Err(DatabaseError::InvalidCommand(
            "db migrate requires a filesystem database".into(),
        ));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _lock = DatabaseLock::acquire(path)?;
    let mut conn = Connection::open(path)?;
    validate_bootstrap_source(path, &conn)?;
    set_private_permissions(path)?;
    configure_preflight(&conn)?;
    migrate_connection(
        path,
        &mut conn,
        backup_dir
            .map(Path::to_path_buf)
            .unwrap_or_else(|| default_backup_dir(path)),
    )
}

pub fn backup_database(path: &Path, destination: &Path) -> DatabaseResult<BackupArtifact> {
    let source = open_read_only(path)?;
    create_verified_backup(path, &source, destination)
}

pub fn restore_database(
    target: &Path,
    source: &Path,
    backup_dir: Option<&Path>,
) -> DatabaseResult<RestoreReport> {
    if is_memory_path(target) {
        return Err(DatabaseError::InvalidCommand(
            "db restore requires a filesystem target".into(),
        ));
    }
    verify_manifest(source)?;
    let source_conn = open_read_only(source)?;
    let source_report = check_connection(source, &source_conn)?;
    if source_report.user_version > CURRENT_SCHEMA_VERSION {
        return Err(DatabaseError::UnsupportedVersion {
            found: source_report.user_version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }

    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let _lock = DatabaseLock::acquire(target)?;
    let target_parent = target.parent().unwrap_or_else(|| Path::new("."));
    let preservation_dir = backup_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_backup_dir(target));
    let (recovery_backup, quarantine) = preserve_target_before_restore(target, &preservation_dir)?;
    ensure_available_space(target_parent, database_footprint(source)?.saturating_mul(2))?;

    let temporary = temporary_path(target, "restore");
    create_private_empty_file(&temporary)?;
    let restore_result = (|| -> DatabaseResult<()> {
        source_conn.backup(MAIN_DB, &temporary, None)?;
        let restored = open_read_only(&temporary)?;
        let restored_report = check_connection(&temporary, &restored)?;
        if restored_report.table_counts != source_report.table_counts
            || restored_report.user_version != source_report.user_version
        {
            return Err(DatabaseError::Verification(
                "restored database metadata does not match the source backup".into(),
            ));
        }
        drop(restored);
        sync_file(&temporary)?;
        set_private_permissions(&temporary)?;
        remove_sqlite_sidecars(target)?;
        fs::rename(&temporary, target)?;
        sync_directory(target_parent)?;
        Ok(())
    })();
    if restore_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    restore_result?;

    Ok(RestoreReport {
        path: target.to_path_buf(),
        restored_from: source.to_path_buf(),
        recovery_backup,
        quarantine,
    })
}

fn preserve_target_before_restore(
    target: &Path,
    backup_dir: &Path,
) -> DatabaseResult<(Option<BackupArtifact>, Option<QuarantineArtifact>)> {
    if !database_files_have_content(target)? {
        return Ok((None, None));
    }

    // SQLite may update shared-memory bookkeeping even through a read-only
    // connection. Preserve every source byte before asking SQLite to inspect
    // the target so a corrupt database remains useful for recovery analysis.
    let quarantine = quarantine_database_files(target, backup_dir)?;
    if !target.exists() || target.metadata()?.len() == 0 {
        return Ok((None, Some(quarantine)));
    }

    let recovery_result = (|| -> DatabaseResult<BackupArtifact> {
        let current = open_read_only(target)?;
        let recovery_path =
            generated_backup_path(backup_dir, "pre-restore", schema::user_version(&current)?)?;
        create_verified_backup(target, &current, &recovery_path)
    })();

    match recovery_result {
        Ok(backup) => {
            discard_quarantine(&quarantine)?;
            Ok((Some(backup), None))
        }
        Err(error) if is_corrupt_database_error(&error) => Ok((None, Some(quarantine))),
        Err(error) => {
            if let Err(cleanup_error) = discard_quarantine(&quarantine) {
                return Err(DatabaseError::Verification(format!(
                    "target validation failed ({error}); temporary quarantine {} could not be removed: {cleanup_error}",
                    quarantine.directory.display()
                )));
            }
            Err(error)
        }
    }
}

fn discard_quarantine(quarantine: &QuarantineArtifact) -> DatabaseResult<()> {
    fs::remove_dir_all(&quarantine.directory)?;
    sync_directory(
        quarantine
            .directory
            .parent()
            .unwrap_or_else(|| Path::new(".")),
    )?;
    Ok(())
}

fn is_corrupt_database_error(error: &DatabaseError) -> bool {
    match error {
        DatabaseError::Integrity(_) => true,
        DatabaseError::Sqlite(rusqlite::Error::SqliteFailure(failure, _)) => matches!(
            failure.code,
            rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
        ),
        _ => false,
    }
}

fn quarantine_database_files(
    database_path: &Path,
    backup_dir: &Path,
) -> DatabaseResult<QuarantineArtifact> {
    fs::create_dir_all(backup_dir)?;
    ensure_available_space(backup_dir, database_footprint(database_path)?)?;
    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ");
    let directory = backup_dir.join(format!(
        "routerview-pre-restore-quarantine-{timestamp}-{}",
        uuid::Uuid::new_v4().simple()
    ));
    fs::DirBuilder::new().mode(0o700).create(&directory)?;

    let result = (|| -> DatabaseResult<QuarantineArtifact> {
        let mut file_checksums = BTreeMap::new();
        for (suffix, stored_name) in [
            ("", "database.db"),
            ("-wal", "database.db-wal"),
            ("-shm", "database.db-shm"),
            ("-journal", "database.db-journal"),
        ] {
            let source = sqlite_related_path(database_path, suffix);
            if !source.exists() {
                continue;
            }
            let destination = directory.join(stored_name);
            copy_private_file(&source, &destination)?;
            file_checksums.insert(stored_name.to_string(), sha256_file(&destination)?);
        }
        if file_checksums.is_empty() {
            return Err(DatabaseError::Verification(
                "database quarantine contained no files".into(),
            ));
        }

        let manifest_path = directory.join("SHA256SUMS");
        let mut manifest = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&manifest_path)?;
        for (name, checksum) in &file_checksums {
            writeln!(manifest, "{checksum}  {name}")?;
        }
        manifest.sync_all()?;
        sync_directory(&directory)?;
        sync_directory(backup_dir)?;
        Ok(QuarantineArtifact {
            directory: directory.clone(),
            manifest_path,
            file_checksums,
        })
    })();

    if result.is_err() {
        let _ = fs::remove_dir_all(&directory);
    }
    result
}

fn copy_private_file(source: &Path, destination: &Path) -> DatabaseResult<()> {
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

pub fn export_legacy(path: &Path, destination: &Path) -> DatabaseResult<BackupArtifact> {
    let source_report = check_database(path)?;
    if destination.exists() {
        return Err(DatabaseError::InvalidCommand(format!(
            "export destination already exists: {}",
            destination.display()
        )));
    }
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    ensure_available_space(parent, database_footprint(path)?.saturating_mul(2))?;
    let temporary = temporary_path(destination, "legacy-export");
    create_private_empty_file(&temporary)?;

    let result = (|| -> DatabaseResult<()> {
        let mut output = Connection::open(&temporary)?;
        output.execute_batch(
            "PRAGMA journal_mode=DELETE;
             PRAGMA synchronous=FULL;
             CREATE TABLE traffic_points (
                 ts INTEGER NOT NULL,
                 download_bps REAL NOT NULL,
                 upload_bps REAL NOT NULL,
                 wan_name TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY(ts, wan_name)
             );
             CREATE TABLE traffic_1m (
                 bucket INTEGER NOT NULL,
                 download_avg REAL NOT NULL,
                 upload_avg REAL NOT NULL,
                 wan_name TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY(bucket, wan_name)
             );
             CREATE TABLE config(key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE device_overrides(
                 mac TEXT PRIMARY KEY, custom_name TEXT, custom_type TEXT,
                 updated_at INTEGER NOT NULL DEFAULT (unixepoch())
             );
             CREATE TABLE probe_targets(
                 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                 host TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'custom',
                 sort_order INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE routerview_export_metadata(
                 key TEXT PRIMARY KEY, value TEXT NOT NULL
             );
             CREATE TABLE routerview_traffic_quality(
                 table_name TEXT NOT NULL,
                 timestamp_ms INTEGER NOT NULL,
                 wan_name TEXT NOT NULL,
                 quality TEXT NOT NULL CHECK(quality IN ('exact', 'estimated', 'mixed')),
                 source TEXT NOT NULL,
                 PRIMARY KEY(table_name, timestamp_ms, wan_name)
             );",
        )?;
        output.execute("ATTACH DATABASE ?1 AS source", [path.to_string_lossy()])?;
        let tx = output.transaction()?;
        tx.execute_batch(
            "INSERT INTO traffic_points
                 SELECT ts, download_bps, upload_bps, COALESCE(wan_name, '')
                 FROM source.traffic_points;
             INSERT INTO traffic_1m
                 SELECT bucket, download_avg, upload_avg, COALESCE(wan_name, '')
                 FROM source.traffic_1m;
             INSERT INTO routerview_traffic_quality
                 SELECT 'traffic_points', ts, COALESCE(wan_name, ''), 'estimated',
                        'legacy-rate-history'
                 FROM source.traffic_points;
             INSERT INTO routerview_traffic_quality
                 SELECT 'traffic_1m', bucket, COALESCE(wan_name, ''), 'estimated',
                        'legacy-rate-history'
                 FROM source.traffic_1m;
             INSERT INTO config
                 SELECT key, value FROM source.config
                 WHERE lower(key) NOT LIKE '%password%'
                   AND lower(key) NOT LIKE '%secret%'
                   AND lower(key) NOT LIKE '%token%';
             INSERT INTO device_overrides
                 SELECT mac, custom_name, custom_type, updated_at
                 FROM source.device_overrides;
             INSERT INTO probe_targets(id, name, host, category, sort_order)
                 SELECT id, name, host, category, sort_order FROM source.probe_targets;

             INSERT OR IGNORE INTO traffic_points(ts, download_bps, upload_bps, wan_name)
                 SELECT sample.ended_at_ms,
                        sample.download_bytes * 8000.0 / sample.duration_ms,
                        sample.upload_bytes * 8000.0 / sample.duration_ms,
                        CASE WHEN interface.kind = 'aggregate' THEN '' ELSE interface.name END
                 FROM source.traffic_samples AS sample
                 JOIN source.router_interfaces AS interface ON interface.id = sample.interface_id;
             INSERT OR REPLACE INTO routerview_traffic_quality
                 SELECT 'traffic_points', sample.ended_at_ms,
                        CASE WHEN interface.kind = 'aggregate' THEN '' ELSE interface.name END,
                        sample.quality, sample.source
                 FROM source.traffic_samples AS sample
                 JOIN source.router_interfaces AS interface ON interface.id = sample.interface_id;

             INSERT OR IGNORE INTO traffic_1m(bucket, download_avg, upload_avg, wan_name)
                 SELECT rollup.bucket_start_ms,
                        (rollup.exact_download_bytes + rollup.estimated_download_bytes) * 8000.0 /
                            MAX(1, rollup.exact_duration_ms + rollup.estimated_duration_ms),
                        (rollup.exact_upload_bytes + rollup.estimated_upload_bytes) * 8000.0 /
                            MAX(1, rollup.exact_duration_ms + rollup.estimated_duration_ms),
                        CASE WHEN interface.kind = 'aggregate' THEN '' ELSE interface.name END
                 FROM source.traffic_rollups AS rollup
                 JOIN source.router_interfaces AS interface ON interface.id = rollup.interface_id
                 WHERE rollup.bucket_size_ms = 60000;
             INSERT OR REPLACE INTO routerview_traffic_quality
                 SELECT 'traffic_1m', rollup.bucket_start_ms,
                        CASE WHEN interface.kind = 'aggregate' THEN '' ELSE interface.name END,
                        CASE
                          WHEN rollup.exact_duration_ms > 0 AND rollup.estimated_duration_ms > 0
                            THEN 'mixed'
                          WHEN rollup.exact_duration_ms > 0 THEN 'exact'
                          ELSE 'estimated'
                        END,
                        rollup.source
                 FROM source.traffic_rollups AS rollup
                 JOIN source.router_interfaces AS interface ON interface.id = rollup.interface_id
                 WHERE rollup.bucket_size_ms = 60000;

             INSERT INTO routerview_export_metadata(key, value) VALUES
                 ('format', 'routerview-legacy-v2'),
                 ('traffic_notice',
                  'Legacy rate rows are estimated unless routerview_traffic_quality says exact.');
             PRAGMA user_version = 0;",
        )?;
        tx.execute(
            "INSERT INTO routerview_export_metadata(key, value)
                 VALUES ('source_user_version', ?1)",
            [source_report.user_version.to_string()],
        )?;
        tx.commit()?;
        output.execute_batch("DETACH DATABASE source; PRAGMA optimize;")?;
        drop(output);
        let report = check_database(&temporary)?;
        if report.integrity != "ok" {
            return Err(DatabaseError::Integrity(report.integrity));
        }
        sync_file(&temporary)?;
        set_private_permissions(&temporary)?;
        fs::rename(&temporary, destination)?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;

    let sha256 = sha256_file(destination)?;
    let manifest_path = write_manifest(destination, &sha256)?;
    let exported = check_database(destination)?;
    Ok(BackupArtifact {
        path: destination.to_path_buf(),
        manifest_path,
        sha256,
        user_version: exported.user_version,
        table_counts: exported.table_counts,
    })
}

fn migrate_connection(
    path: &Path,
    conn: &mut Connection,
    backup_dir: PathBuf,
) -> DatabaseResult<MigrationReport> {
    let from_version = schema::user_version(conn)?;
    if from_version > CURRENT_SCHEMA_VERSION {
        return Err(DatabaseError::UnsupportedVersion {
            found: from_version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    check_connection(path, conn)?;
    if from_version == CURRENT_SCHEMA_VERSION {
        return Ok(MigrationReport {
            path: path.to_path_buf(),
            from_version,
            to_version: CURRENT_SCHEMA_VERSION,
            backup: None,
        });
    }

    refuse_plaintext_secret_backup(conn)?;

    let has_existing_data = schema::has_user_tables(conn)?;
    let backup = if has_existing_data {
        let footprint = database_footprint(path)?;
        let required = footprint
            .saturating_mul(MIGRATION_SPACE_NUMERATOR)
            .div_ceil(MIGRATION_SPACE_DENOMINATOR);
        ensure_available_space(path.parent().unwrap_or_else(|| Path::new(".")), required)?;
        let destination = generated_backup_path(&backup_dir, "pre-migration", from_version)?;
        Some(create_verified_backup(path, conn, &destination)?)
    } else {
        None
    };

    schema::apply_migrations(conn, from_version, backup.as_ref())?;
    let after = check_connection(path, conn)?;
    if after.user_version != CURRENT_SCHEMA_VERSION {
        return Err(DatabaseError::Verification(format!(
            "migration committed user_version {}, expected {CURRENT_SCHEMA_VERSION}",
            after.user_version
        )));
    }
    Ok(MigrationReport {
        path: path.to_path_buf(),
        from_version,
        to_version: CURRENT_SCHEMA_VERSION,
        backup,
    })
}

fn contains_plaintext_router_secret(conn: &Connection) -> DatabaseResult<bool> {
    let config_exists: bool = conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'config'
         )",
        [],
        |row| row.get(0),
    )?;
    if !config_exists {
        return Ok(false);
    }
    Ok(conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM config
             WHERE key IN ('router_password', 'routeros_password') AND value <> ''
         )",
        [],
        |row| row.get(0),
    )?)
}

fn refuse_plaintext_secret_backup(conn: &Connection) -> DatabaseResult<()> {
    if contains_plaintext_router_secret(conn)? {
        return Err(DatabaseError::Verification(
            "refusing to create a database backup while config contains a plaintext router password; start the service with ROUTERVIEW_MASTER_KEY_FILE so the bootstrap encryption step can complete first"
                .into(),
        ));
    }
    Ok(())
}

fn create_verified_backup(
    source_path: &Path,
    source: &Connection,
    destination: &Path,
) -> DatabaseResult<BackupArtifact> {
    create_verified_backup_inner(source_path, source, destination, || {})
}

fn create_verified_backup_inner<F>(
    source_path: &Path,
    source: &Connection,
    destination: &Path,
    before_snapshot: F,
) -> DatabaseResult<BackupArtifact>
where
    F: FnOnce(),
{
    if destination.exists() || manifest_path(destination).exists() {
        return Err(DatabaseError::InvalidCommand(format!(
            "backup destination already exists: {}",
            destination.display()
        )));
    }
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    ensure_available_space(parent, database_footprint(source_path)?.max(4096))?;
    let temporary = temporary_path(destination, "backup");
    create_private_empty_file(&temporary)?;

    let result = (|| -> DatabaseResult<DatabaseReport> {
        before_snapshot();
        source.backup(MAIN_DB, &temporary, None)?;
        let backup_conn = open_read_only(&temporary)?;
        // The live source may advance during an online backup. Security and
        // consistency guarantees therefore come exclusively from the snapshot.
        refuse_plaintext_secret_backup(&backup_conn)?;
        let backup_report = check_connection(&temporary, &backup_conn)?;
        drop(backup_conn);
        sync_file(&temporary)?;
        set_private_permissions(&temporary)?;
        fs::rename(&temporary, destination)?;
        sync_directory(parent)?;
        Ok(backup_report)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    let backup_report = result?;
    let sha256 = sha256_file(destination)?;
    let manifest_path = write_manifest(destination, &sha256)?;
    Ok(BackupArtifact {
        path: destination.to_path_buf(),
        manifest_path,
        sha256,
        user_version: backup_report.user_version,
        table_counts: backup_report.table_counts,
    })
}

fn check_connection(path: &Path, conn: &Connection) -> DatabaseResult<DatabaseReport> {
    conn.busy_timeout(Duration::from_secs(5))?;
    let mut statement = conn.prepare("PRAGMA integrity_check")?;
    let messages: Vec<String> = statement
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    let integrity = messages.join("; ");
    if messages.as_slice() != ["ok"] {
        return Err(DatabaseError::Integrity(integrity));
    }
    let foreign_key_violations: u64 =
        conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if foreign_key_violations != 0 {
        return Err(DatabaseError::Integrity(format!(
            "{foreign_key_violations} foreign-key violations"
        )));
    }
    Ok(DatabaseReport {
        path: path.to_path_buf(),
        user_version: schema::user_version(conn)?,
        integrity,
        foreign_key_violations,
        table_counts: table_counts(conn)?,
    })
}

fn table_counts(conn: &Connection) -> DatabaseResult<BTreeMap<String, u64>> {
    let mut statement = conn.prepare(
        "SELECT name FROM sqlite_schema
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
         ORDER BY name",
    )?;
    let names: Vec<String> = statement
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    let mut result = BTreeMap::new();
    for name in names {
        let quoted = name.replace('"', "\"\"");
        let count = conn.query_row(&format!("SELECT COUNT(*) FROM \"{quoted}\""), [], |row| {
            row.get(0)
        })?;
        result.insert(name, count);
    }
    Ok(result)
}

fn open_read_only(path: &Path) -> DatabaseResult<Connection> {
    if !path.exists() {
        return Err(DatabaseError::InvalidCommand(format!(
            "database does not exist: {}",
            path.display()
        )));
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    Ok(conn)
}

fn configure_preflight(conn: &Connection) -> DatabaseResult<()> {
    conn.busy_timeout(Duration::from_secs(10))?;
    conn.execute_batch(
        "PRAGMA foreign_keys=ON;
         PRAGMA secure_delete=ON;",
    )?;
    Ok(())
}

fn configure_runtime(conn: &Connection) -> DatabaseResult<()> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA secure_delete=ON;
         PRAGMA foreign_keys=ON;",
    )?;
    Ok(())
}

fn verify_manifest(path: &Path) -> DatabaseResult<()> {
    let manifest = manifest_path(path);
    let contents = fs::read_to_string(&manifest).map_err(|error| {
        DatabaseError::InvalidCommand(format!(
            "restore requires checksum manifest {}: {error}",
            manifest.display()
        ))
    })?;
    let expected = contents
        .split_whitespace()
        .next()
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| DatabaseError::Verification("invalid SHA-256 manifest".into()))?
        .to_ascii_lowercase();
    let actual = sha256_file(path)?;
    if expected != actual {
        return Err(DatabaseError::ChecksumMismatch { expected, actual });
    }
    Ok(())
}

fn write_manifest(path: &Path, sha256: &str) -> DatabaseResult<PathBuf> {
    let destination = manifest_path(path);
    let temporary = temporary_path(&destination, "manifest");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("database.db");
    writeln!(file, "{sha256}  {name}")?;
    file.sync_all()?;
    fs::rename(&temporary, &destination)?;
    sync_directory(destination.parent().unwrap_or_else(|| Path::new(".")))?;
    Ok(destination)
}

fn sha256_file(path: &Path) -> DatabaseResult<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn generated_backup_path(directory: &Path, purpose: &str, version: i64) -> DatabaseResult<PathBuf> {
    fs::create_dir_all(directory)?;
    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ");
    Ok(directory.join(format!(
        "routerview-{purpose}-v{version}-{timestamp}-{}.db",
        uuid::Uuid::new_v4().simple()
    )))
}

fn default_backup_dir(database_path: &Path) -> PathBuf {
    std::env::var_os("DB_BACKUP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            database_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("backups")
        })
}

fn database_footprint(path: &Path) -> DatabaseResult<u64> {
    let mut total = if path.exists() {
        path.metadata()?.len()
    } else {
        0
    };
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = sqlite_related_path(path, suffix);
        if sidecar.exists() {
            total = total.saturating_add(sidecar.metadata()?.len());
        }
    }
    Ok(total.max(4096))
}

fn database_files_have_content(path: &Path) -> DatabaseResult<bool> {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let candidate = sqlite_related_path(path, suffix);
        if candidate.exists() && candidate.metadata()?.len() > 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ensure_available_space(path: &Path, required_bytes: u64) -> DatabaseResult<()> {
    let path = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| DatabaseError::Verification("filesystem path contains NUL".into()))?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let result = unsafe { libc::statvfs(c_path.as_ptr(), stats.as_mut_ptr()) };
    if result != 0 {
        return Err(DatabaseError::Io(std::io::Error::last_os_error()));
    }
    let stats = unsafe { stats.assume_init() };
    let available_bytes = (stats.f_bavail as u64).saturating_mul(stats.f_frsize);
    if available_bytes < required_bytes {
        return Err(DatabaseError::InsufficientSpace {
            path: path.to_path_buf(),
            required_bytes,
            available_bytes,
        });
    }
    Ok(())
}

fn create_private_empty_file(path: &Path) -> DatabaseResult<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .sync_all()?;
    Ok(())
}

fn set_private_permissions(path: &Path) -> DatabaseResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn sync_file(path: &Path) -> DatabaseResult<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> DatabaseResult<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn remove_sqlite_sidecars(path: &Path) -> DatabaseResult<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = sqlite_related_path(path, suffix);
        match fs::remove_file(sidecar) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(DatabaseError::Io(error)),
        }
    }
    Ok(())
}

fn sqlite_related_path(database_path: &Path, suffix: &str) -> PathBuf {
    let mut value = database_path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn lock_path(database_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.lock", database_path.to_string_lossy()))
}

fn manifest_path(database_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sha256", database_path.to_string_lossy()))
}

fn temporary_path(path: &Path, purpose: &str) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("routerview.db");
    parent.join(format!(
        ".{name}.{purpose}.{}.partial",
        uuid::Uuid::new_v4().simple()
    ))
}

fn is_memory_path(path: &Path) -> bool {
    path == Path::new(":memory:")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "routerview-{name}-{}",
                uuid::Uuid::new_v4().simple()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn create_single_key_legacy_fixture(path: &Path, wal: bool) -> Connection {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE traffic_points(
                 ts INTEGER PRIMARY KEY,
                 download_bps REAL NOT NULL,
                 upload_bps REAL NOT NULL,
                 wan_name TEXT
             );
             CREATE TABLE traffic_1m(
                 bucket INTEGER PRIMARY KEY,
                 download_avg REAL NOT NULL,
                 upload_avg REAL NOT NULL,
                 wan_name TEXT
             );
             CREATE TABLE config(key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        )
        .unwrap();
        if wal {
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
                .unwrap();
        }
        conn.execute(
            "INSERT INTO traffic_points VALUES (10000, 8000, 4000, NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO traffic_points VALUES (17000, 8000, 4000, NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO traffic_1m VALUES (60000, 16000, 8000, 'wan1')",
            [],
        )
        .unwrap();
        conn
    }

    fn create_current_database(path: &Path, backup_dir: &Path) {
        let report = migrate_database(path, Some(backup_dir)).unwrap();
        assert_eq!(report.from_version, 0);
        assert_eq!(report.to_version, CURRENT_SCHEMA_VERSION);
        assert!(report.backup.is_none());
    }

    fn assert_index_exists(conn: &Connection, name: &str) {
        assert!(conn
            .prepare(
                "SELECT 1 FROM sqlite_schema
                 WHERE type = 'index' AND name = ?1",
            )
            .unwrap()
            .exists([name])
            .unwrap());
    }

    #[test]
    fn migrates_empty_database_to_current_schema_without_a_backup() {
        let directory = TestDirectory::new("empty-migration");
        let database = directory.join("empty.db");
        let report = migrate_database(&database, Some(&directory.0)).unwrap();
        assert_eq!(report.from_version, 0);
        assert_eq!(report.to_version, CURRENT_SCHEMA_VERSION);
        assert!(report.backup.is_none());

        let checked = check_database(&database).unwrap();
        assert_eq!(checked.user_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(
            database.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        for table in [
            "routers",
            "router_interfaces",
            "traffic_samples",
            "traffic_rollups",
            "counter_checkpoints",
            "traffic_gaps",
            "database_migrations",
        ] {
            assert!(checked.table_counts.contains_key(table), "missing {table}");
        }
        let conn = Connection::open(&database).unwrap();
        for index in [
            "idx_traffic_samples_rollup_cutoff",
            "idx_traffic_samples_retention",
            "idx_traffic_rollups_retention",
            "idx_traffic_gaps_retention",
        ] {
            assert_index_exists(&conn, index);
        }
    }

    #[test]
    fn migrates_v4_rollup_index_with_a_verified_backup() {
        let directory = TestDirectory::new("v4-rollup-index-migration");
        let database = directory.join("v4.db");
        create_current_database(&database, &directory.0);
        let conn = Connection::open(&database).unwrap();
        conn.execute_batch(
            "INSERT INTO routers(
                 id, internal_uuid, fallback_target, first_seen_at_ms, last_seen_at_ms
             ) VALUES (1, 'migration-router', '192.0.2.1', 0, 10000);
             INSERT INTO router_interfaces(
                 id, router_id, interface_key, name, kind, first_seen_at_ms, last_seen_at_ms
             ) VALUES (1, 1, 'ether1', 'WAN', 'wan', 0, 10000);
             INSERT INTO traffic_samples(
                 router_id, interface_id, started_at_ms, ended_at_ms, duration_ms,
                 download_bytes, upload_bytes, download_bps, upload_bps,
                 quality, source, created_at_ms
             ) VALUES
                 (1, 1, 0, 5000, 5000, 100, 50, 160, 80, 'exact', 'fixture', 5000),
                 (1, 1, 5000, 10000, 5000, 200, 100, 320, 160, 'exact', 'fixture', 10000);
             DROP INDEX idx_traffic_samples_rollup_cutoff;
             DROP INDEX idx_traffic_samples_retention;
             DROP INDEX idx_traffic_rollups_retention;
             DROP INDEX idx_traffic_gaps_retention;
             DELETE FROM database_migrations WHERE version >= 5;
             PRAGMA user_version = 4;",
        )
        .unwrap();
        drop(conn);

        let report = migrate_database(&database, Some(&directory.join("backups"))).unwrap();
        assert_eq!(report.from_version, 4);
        assert_eq!(report.to_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(report.backup.as_ref().unwrap().user_version, 4);
        let conn = Connection::open(&database).unwrap();
        let preserved: (i64, i64, i64, i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), SUM(download_bytes), SUM(upload_bytes),
                        MIN(started_at_ms), MAX(ended_at_ms)
                 FROM traffic_samples",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(preserved, (2, 300, 150, 0, 10_000));
        assert_index_exists(&conn, "idx_traffic_samples_rollup_cutoff");
        assert_eq!(
            conn.query_row(
                "SELECT name, source_version FROM database_migrations WHERE version = 5",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap(),
            ("traffic_rollup_cutoff_index".to_string(), 4)
        );
    }

    #[test]
    fn migrates_v5_retention_indexes_with_a_verified_backup() {
        let directory = TestDirectory::new("v5-retention-index-migration");
        let database = directory.join("v5.db");
        create_current_database(&database, &directory.0);
        let conn = Connection::open(&database).unwrap();
        conn.execute_batch(
            "INSERT INTO routers(
                 id, internal_uuid, fallback_target, first_seen_at_ms, last_seen_at_ms
             ) VALUES (1, 'retention-migration-router', '192.0.2.1', 0, 10000);
             INSERT INTO router_interfaces(
                 id, router_id, interface_key, name, kind, first_seen_at_ms, last_seen_at_ms
             ) VALUES (1, 1, 'ether1', 'WAN', 'wan', 0, 10000);
             INSERT INTO traffic_samples(
                 router_id, interface_id, started_at_ms, ended_at_ms, duration_ms,
                 download_bytes, upload_bytes, download_bps, upload_bps,
                 quality, source, created_at_ms
             ) VALUES
                 (1, 1, 0, 5000, 5000, 100, 50, 160, 80, 'exact', 'fixture', 5000);
             INSERT INTO traffic_rollups(
                 router_id, interface_id, bucket_start_ms, bucket_end_ms, bucket_size_ms,
                 exact_download_bytes, exact_upload_bytes, exact_duration_ms, sample_count,
                 download_avg_bps, upload_avg_bps, source, created_at_ms
             ) VALUES
                 (1, 1, 0, 5000, 5000, 100, 50, 5000, 1, 160, 80, 'fixture', 5000);
             INSERT INTO traffic_gaps(
                 router_id, interface_id, started_at_ms, ended_at_ms,
                 reason, details, created_at_ms
             ) VALUES
                 (1, 1, 5000, 10000, 'fixture-gap', 'preserve-me', 10000);
             DROP INDEX idx_traffic_samples_retention;
             DROP INDEX idx_traffic_rollups_retention;
             DROP INDEX idx_traffic_gaps_retention;
             DELETE FROM database_migrations WHERE version = 6;
             PRAGMA user_version = 5;",
        )
        .unwrap();
        drop(conn);

        let report = migrate_database(&database, Some(&directory.join("backups"))).unwrap();
        assert_eq!(report.from_version, 5);
        assert_eq!(report.to_version, CURRENT_SCHEMA_VERSION);
        let backup = report.backup.as_ref().unwrap();
        assert_eq!(backup.user_version, 5);
        verify_manifest(&backup.path).unwrap();

        let conn = Connection::open(&database).unwrap();
        let preserved: (i64, i64, String) = conn
            .query_row(
                "SELECT
                     (SELECT download_bytes FROM traffic_samples),
                     (SELECT exact_download_bytes FROM traffic_rollups),
                     (SELECT details FROM traffic_gaps)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(preserved, (100, 100, "preserve-me".to_string()));
        for index in [
            "idx_traffic_samples_rollup_cutoff",
            "idx_traffic_samples_retention",
            "idx_traffic_rollups_retention",
            "idx_traffic_gaps_retention",
        ] {
            assert_index_exists(&conn, index);
        }
        assert_eq!(
            conn.query_row(
                "SELECT name, source_version FROM database_migrations WHERE version = 6",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap(),
            ("traffic_retention_cutoff_indexes".to_string(), 5)
        );
    }

    #[test]
    fn bootstrap_rejects_newer_database_without_modifying_it() {
        let directory = TestDirectory::new("newer-bootstrap");
        let database = directory.join("newer.db");
        let conn = Connection::open(&database).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=DELETE;
             CREATE TABLE future_data(value TEXT NOT NULL);
             INSERT INTO future_data VALUES ('preserve-me');",
        )
        .unwrap();
        let future_version = CURRENT_SCHEMA_VERSION + 1;
        conn.pragma_update(None, "user_version", future_version)
            .unwrap();
        drop(conn);
        let before = fs::read(&database).unwrap();

        let error = match open_bootstrap_runtime(&database) {
            Err(error) => error,
            Ok(_) => panic!("newer database was unexpectedly accepted"),
        };

        match error {
            DatabaseError::UnsupportedVersion { found, supported } => {
                assert_eq!(found, future_version);
                assert_eq!(supported, CURRENT_SCHEMA_VERSION);
            }
            error => panic!("unexpected error: {error}"),
        }
        assert_eq!(fs::read(&database).unwrap(), before);
        let conn = Connection::open(&database).unwrap();
        assert!(!conn
            .prepare("SELECT 1 FROM sqlite_schema WHERE name = 'admins'")
            .unwrap()
            .exists([])
            .unwrap());
    }

    #[test]
    fn bootstrap_rejects_corrupt_database_without_modifying_it() {
        let directory = TestDirectory::new("corrupt-bootstrap");
        let database = directory.join("corrupt.db");
        fs::write(&database, b"not a sqlite database").unwrap();
        let before = fs::read(&database).unwrap();

        assert!(open_bootstrap_runtime(&database).is_err());
        assert_eq!(fs::read(&database).unwrap(), before);
    }

    #[test]
    fn migrates_single_key_and_wal_history_losslessly_as_estimated() {
        let directory = TestDirectory::new("legacy-wal-migration");
        let database = directory.join("legacy.db");
        let writer = create_single_key_legacy_fixture(&database, true);
        let report = migrate_database(&database, Some(&directory.join("backups"))).unwrap();
        let backup = report.backup.expect("legacy database must be backed up");
        assert!(backup.path.exists());
        assert!(backup.manifest_path.exists());
        verify_manifest(&backup.path).unwrap();

        let conn = Connection::open(&database).unwrap();
        assert_eq!(schema::user_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM traffic_points", [], |row| row
                .get::<_, u64>(0))
                .unwrap(),
            2
        );
        let imported: Vec<(String, i64, i64)> = conn
            .prepare(
                "SELECT quality, duration_ms, download_bytes
                 FROM traffic_samples ORDER BY ended_at_ms",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            imported,
            vec![
                ("estimated".into(), 5000, 5000),
                ("estimated".into(), 7000, 7000)
            ]
        );
        assert_eq!(
            conn.query_row(
                "SELECT estimated_download_bytes FROM traffic_rollups
                 WHERE source = 'legacy-traffic_1m'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            120_000
        );
        drop(conn);
        drop(writer);
    }

    #[test]
    fn migration_prefers_raw_points_over_overlapping_legacy_rollups() {
        let directory = TestDirectory::new("legacy-overlap-migration");
        let database = directory.join("legacy.db");
        let conn = create_single_key_legacy_fixture(&database, false);
        conn.execute("INSERT INTO traffic_1m VALUES (0, 8000, 4000, NULL)", [])
            .unwrap();
        drop(conn);

        migrate_database(&database, Some(&directory.join("backups"))).unwrap();
        let conn = Connection::open(&database).unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM traffic_1m", [], |row| row
                .get::<_, u64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM traffic_rollups WHERE source = 'legacy-traffic_1m'",
                [],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT legacy_rollups_count FROM database_migrations WHERE version = 4",
                [],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
            2
        );
    }

    #[test]
    fn migrates_versioned_composite_fixture_and_records_source_version() {
        let directory = TestDirectory::new("v2-migration");
        let database = directory.join("v2.db");
        let conn = Connection::open(&database).unwrap();
        conn.execute_batch(
            "CREATE TABLE traffic_points(
                 ts INTEGER NOT NULL, download_bps REAL NOT NULL, upload_bps REAL NOT NULL,
                 wan_name TEXT NOT NULL DEFAULT '', PRIMARY KEY(ts, wan_name)
             );
             CREATE TABLE traffic_1m(
                 bucket INTEGER NOT NULL, download_avg REAL NOT NULL, upload_avg REAL NOT NULL,
                 wan_name TEXT NOT NULL DEFAULT '', PRIMARY KEY(bucket, wan_name)
             );
             CREATE TABLE config(key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE device_overrides(
                 mac TEXT PRIMARY KEY, custom_name TEXT, custom_type TEXT, updated_at INTEGER NOT NULL
             );
             CREATE TABLE probe_targets(
                 id INTEGER PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL,
                 category TEXT NOT NULL, sort_order INTEGER NOT NULL
             );
             INSERT INTO traffic_points VALUES (5000, 1000, 2000, ''), (5000, 3000, 4000, 'wan2');
             PRAGMA user_version=2;",
        )
        .unwrap();
        drop(conn);

        let report = migrate_database(&database, Some(&directory.join("backups"))).unwrap();
        assert_eq!(report.from_version, 2);
        let conn = Connection::open(&database).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT source_version FROM database_migrations WHERE version = 4",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM traffic_samples", [], |row| row
                .get::<_, u64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn migrates_current_security_schema_without_losing_admin_data() {
        let directory = TestDirectory::new("v3-security-migration");
        let database = directory.join("v3.db");
        create_current_database(&database, &directory.0);
        let conn = Connection::open(&database).unwrap();
        conn.execute_batch(
            "DELETE FROM database_migrations WHERE version >= 4;
             DROP TABLE traffic_gaps;
             DROP TABLE counter_checkpoints;
             DROP TABLE traffic_rollups;
             DROP TABLE traffic_samples;
             DROP TABLE router_interfaces;
             DROP TABLE routers;
             INSERT INTO admins(id, username, password_hash)
                 VALUES (1, 'existing-admin', 'argon2-fixture');
             PRAGMA user_version=3;",
        )
        .unwrap();
        drop(conn);

        let report = migrate_database(&database, Some(&directory.join("backups"))).unwrap();
        assert_eq!(report.from_version, 3);
        assert!(report.backup.is_some());
        let conn = Connection::open(&database).unwrap();
        assert_eq!(
            conn.query_row("SELECT username FROM admins WHERE id = 1", [], |row| row
                .get::<_, String>(
                0
            ))
            .unwrap(),
            "existing-admin"
        );
        assert_eq!(schema::user_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn failed_migration_rolls_back_all_schema_changes_and_preserves_backup() {
        let directory = TestDirectory::new("failed-migration");
        let database = directory.join("malformed.db");
        let conn = Connection::open(&database).unwrap();
        conn.execute_batch(
            "CREATE TABLE traffic_points(
                 ts INTEGER PRIMARY KEY, download_bps REAL NOT NULL
             );
             INSERT INTO traffic_points VALUES (1000, 1.0);",
        )
        .unwrap();
        drop(conn);

        let backup_dir = directory.join("backups");
        let error = migrate_database(&database, Some(&backup_dir)).unwrap_err();
        assert!(error.to_string().contains("upload_bps"));
        let conn = Connection::open(&database).unwrap();
        assert_eq!(schema::user_version(&conn).unwrap(), 0);
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM traffic_points", [], |row| row
                .get::<_, u64>(0))
                .unwrap(),
            1
        );
        assert!(!conn
            .prepare("SELECT 1 FROM pragma_table_info('traffic_points') WHERE name = 'wan_name'")
            .unwrap()
            .exists([])
            .unwrap());
        let backups = fs::read_dir(backup_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|value| value == "db"))
            .count();
        assert_eq!(backups, 1);
    }

    #[test]
    fn plaintext_secret_blocks_migration_backup() {
        let directory = TestDirectory::new("plaintext-refusal");
        let database = directory.join("plaintext.db");
        let conn = create_single_key_legacy_fixture(&database, false);
        conn.execute(
            "INSERT INTO config VALUES ('routeros_password', 'do-not-back-up-me')",
            [],
        )
        .unwrap();
        drop(conn);
        let backup_dir = directory.join("backups");

        let error = migrate_database(&database, Some(&backup_dir)).unwrap_err();
        assert!(error.to_string().contains("plaintext router password"));
        assert!(!backup_dir.exists());
        assert_eq!(check_database(&database).unwrap().user_version, 0);
    }

    #[test]
    fn plaintext_secret_blocks_manual_backup() {
        let directory = TestDirectory::new("plaintext-manual-backup-refusal");
        let database = directory.join("plaintext.db");
        let conn = create_single_key_legacy_fixture(&database, false);
        conn.execute(
            "INSERT INTO config VALUES ('router_password', 'do-not-back-up-me')",
            [],
        )
        .unwrap();
        drop(conn);
        let destination = directory.join("unsafe-backup.db");

        let error = backup_database(&database, &destination).unwrap_err();
        assert!(error.to_string().contains("plaintext router password"));
        assert!(!destination.exists());
    }

    #[test]
    fn backup_has_private_permissions_checksum_and_exact_counts() {
        let directory = TestDirectory::new("backup");
        let database = directory.join("source.db");
        create_current_database(&database, &directory.0);
        let conn = Connection::open(&database).unwrap();
        conn.execute("INSERT INTO config VALUES ('theme', 'dark')", [])
            .unwrap();
        drop(conn);

        let destination = directory.join("verified.db");
        let backup = backup_database(&database, &destination).unwrap();
        assert_eq!(backup.sha256, sha256_file(&destination).unwrap());
        verify_manifest(&destination).unwrap();
        assert_eq!(
            destination.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(backup.table_counts.get("config"), Some(&1));
    }

    #[test]
    fn backup_succeeds_while_traffic_db_holds_lifetime_lock() {
        let directory = TestDirectory::new("backup-with-runtime-lock");
        let database = directory.join("source.db");
        let db = crate::db::TrafficDb::open(&database).unwrap();
        db.set_config("theme", "dark").unwrap();
        assert!(matches!(
            DatabaseLock::acquire(&database),
            Err(DatabaseError::InUse(_))
        ));

        let destination = directory.join("verified.db");
        let backup = backup_database(&database, &destination).unwrap();

        assert_eq!(backup.table_counts.get("config"), Some(&1));
        verify_manifest(&destination).unwrap();
        assert!(matches!(
            DatabaseLock::acquire(&database),
            Err(DatabaseError::InUse(_))
        ));
    }

    #[test]
    fn backup_report_comes_from_snapshot_during_concurrent_runtime_write() {
        let directory = TestDirectory::new("backup-with-concurrent-writer");
        let database = directory.join("source.db");
        let db = std::sync::Arc::new(crate::db::TrafficDb::open(&database).unwrap());
        db.set_config("before_backup", "present").unwrap();

        let (start_write_tx, start_write_rx) = std::sync::mpsc::sync_channel(0);
        let (write_finished_tx, write_finished_rx) = std::sync::mpsc::sync_channel(0);
        let writer_db = std::sync::Arc::clone(&db);
        let writer = std::thread::spawn(move || {
            start_write_rx.recv().unwrap();
            writer_db.set_config("during_backup", "committed").unwrap();
            write_finished_tx.send(()).unwrap();
        });

        let source = open_read_only(&database).unwrap();
        let destination = directory.join("verified.db");
        let backup = create_verified_backup_inner(&database, &source, &destination, || {
            start_write_tx.send(()).unwrap();
            write_finished_rx.recv().unwrap();
        })
        .unwrap();
        writer.join().unwrap();

        assert_eq!(backup.table_counts.get("config"), Some(&2));
        let backup_conn = open_read_only(&destination).unwrap();
        let written_value: String = backup_conn
            .query_row(
                "SELECT value FROM config WHERE key = 'during_backup'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(written_value, "committed");
        let checked = check_connection(&destination, &backup_conn).unwrap();
        assert_eq!(checked.user_version, backup.user_version);
        assert_eq!(checked.table_counts, backup.table_counts);
    }

    #[test]
    fn restore_verifies_checksum_preserves_current_database_and_requires_exclusive_lock() {
        let directory = TestDirectory::new("restore");
        let source = directory.join("source.db");
        let target = directory.join("target.db");
        let backups = directory.join("backups");
        create_current_database(&source, &backups);
        create_current_database(&target, &backups);
        Connection::open(&source)
            .unwrap()
            .execute("INSERT INTO config VALUES ('marker', 'source')", [])
            .unwrap();
        Connection::open(&target)
            .unwrap()
            .execute("INSERT INTO config VALUES ('marker', 'target')", [])
            .unwrap();
        let source_backup = directory.join("source-backup.db");
        backup_database(&source, &source_backup).unwrap();

        let lock = DatabaseLock::acquire(&target).unwrap();
        assert!(matches!(
            restore_database(&target, &source_backup, Some(&backups)),
            Err(DatabaseError::InUse(_))
        ));
        drop(lock);

        let restored = restore_database(&target, &source_backup, Some(&backups)).unwrap();
        assert!(restored.recovery_backup.unwrap().path.exists());
        let marker: String = Connection::open(&target)
            .unwrap()
            .query_row("SELECT value FROM config WHERE key = 'marker'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(marker, "source");
    }

    #[test]
    fn restore_rejects_tampered_backup_before_replacing_target() {
        let directory = TestDirectory::new("restore-tamper");
        let source = directory.join("source.db");
        let target = directory.join("target.db");
        create_current_database(&source, &directory.0);
        create_current_database(&target, &directory.0);
        Connection::open(&target)
            .unwrap()
            .execute("INSERT INTO config VALUES ('marker', 'untouched')", [])
            .unwrap();
        let backup = directory.join("backup.db");
        backup_database(&source, &backup).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&backup)
            .unwrap()
            .write_all(b"tamper")
            .unwrap();

        assert!(matches!(
            restore_database(&target, &backup, Some(&directory.0)),
            Err(DatabaseError::ChecksumMismatch { .. })
        ));
        let marker: String = Connection::open(&target)
            .unwrap()
            .query_row("SELECT value FROM config WHERE key = 'marker'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(marker, "untouched");
    }

    #[test]
    fn restore_quarantines_corrupt_database_and_sidecars_before_replacement() {
        let directory = TestDirectory::new("restore-corrupt-target");
        let source = directory.join("source.db");
        let target = directory.join("target.db");
        let backups = directory.join("backups");
        create_current_database(&source, &backups);
        Connection::open(&source)
            .unwrap()
            .execute("INSERT INTO config VALUES ('marker', 'source')", [])
            .unwrap();
        let source_backup = directory.join("source-backup.db");
        backup_database(&source, &source_backup).unwrap();

        let original_main = b"this is not a SQLite database";
        let original_wal = b"corrupt wal evidence";
        let original_shm = b"corrupt shm evidence";
        fs::write(&target, original_main).unwrap();
        fs::write(sqlite_related_path(&target, "-wal"), original_wal).unwrap();
        fs::write(sqlite_related_path(&target, "-shm"), original_shm).unwrap();

        let report = restore_database(&target, &source_backup, Some(&backups)).unwrap();
        assert!(report.recovery_backup.is_none());
        let quarantine = report
            .quarantine
            .expect("corrupt target must be quarantined");
        assert_eq!(
            quarantine
                .directory
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::read(quarantine.directory.join("database.db")).unwrap(),
            original_main
        );
        assert_eq!(
            fs::read(quarantine.directory.join("database.db-wal")).unwrap(),
            original_wal
        );
        assert_eq!(
            fs::read(quarantine.directory.join("database.db-shm")).unwrap(),
            original_shm
        );
        assert_eq!(
            quarantine
                .manifest_path
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let manifest = fs::read_to_string(&quarantine.manifest_path).unwrap();
        for (name, checksum) in &quarantine.file_checksums {
            assert_eq!(
                checksum,
                &sha256_file(&quarantine.directory.join(name)).unwrap()
            );
            assert!(manifest.contains(&format!("{checksum}  {name}")));
            assert_eq!(
                quarantine
                    .directory
                    .join(name)
                    .metadata()
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        assert!(!sqlite_related_path(&target, "-wal").exists());
        assert!(!sqlite_related_path(&target, "-shm").exists());
        let marker: String = Connection::open(&target)
            .unwrap()
            .query_row("SELECT value FROM config WHERE key = 'marker'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(marker, "source");
    }

    #[test]
    fn legacy_export_filters_sensitive_config_and_writes_verified_manifest() {
        let directory = TestDirectory::new("legacy-export");
        let database = directory.join("source.db");
        create_current_database(&database, &directory.0);
        let conn = Connection::open(&database).unwrap();
        conn.execute(
            "INSERT INTO config(key, value) VALUES ('theme', 'dark'), ('api_token', 'secret')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO device_overrides(mac, custom_name) VALUES ('AA:BB:CC:DD:EE:FF', 'NAS')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO probe_targets(name, host) VALUES ('Gateway', '192.0.2.1')",
            [],
        )
        .unwrap();
        drop(conn);

        let destination = directory.join("legacy.db");
        let artifact = export_legacy(&database, &destination).unwrap();
        verify_manifest(&destination).unwrap();
        assert_eq!(artifact.sha256, sha256_file(&destination).unwrap());
        let exported = Connection::open(&destination).unwrap();
        assert_eq!(schema::user_version(&exported).unwrap(), 0);
        assert_eq!(
            exported
                .query_row("SELECT value FROM config WHERE key = 'theme'", [], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap(),
            "dark"
        );
        assert!(!exported
            .prepare("SELECT 1 FROM config WHERE key = 'api_token'")
            .unwrap()
            .exists([])
            .unwrap());
        assert_eq!(
            exported
                .query_row("SELECT COUNT(*) FROM device_overrides", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn legacy_export_records_the_actual_source_schema_version() {
        let directory = TestDirectory::new("legacy-export-source-version");
        let database = directory.join("source.db");
        create_current_database(&database, &directory.0);
        let conn = Connection::open(&database).unwrap();
        conn.execute_batch(
            "DROP INDEX idx_traffic_samples_rollup_cutoff;
             DROP INDEX idx_traffic_samples_retention;
             DROP INDEX idx_traffic_rollups_retention;
             DROP INDEX idx_traffic_gaps_retention;
             DELETE FROM database_migrations WHERE version >= 5;
             PRAGMA user_version = 4;",
        )
        .unwrap();
        drop(conn);

        let destination = directory.join("legacy.db");
        export_legacy(&database, &destination).unwrap();
        let exported = Connection::open(&destination).unwrap();
        let source_version: String = exported
            .query_row(
                "SELECT value FROM routerview_export_metadata
                 WHERE key = 'source_user_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(source_version, "4");
    }
}
