use std::collections::BTreeMap;
use std::path::PathBuf;

pub const CURRENT_SCHEMA_VERSION: i64 = 6;

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database is already in use: {0}")]
    InUse(PathBuf),
    #[error("database integrity check failed: {0}")]
    Integrity(String),
    #[error("database schema version {found} is newer than supported version {supported}")]
    UnsupportedVersion { found: i64, supported: i64 },
    #[error(
        "insufficient free space at {path}: need {required_bytes} bytes, have {available_bytes} bytes"
    )]
    InsufficientSpace {
        path: PathBuf,
        required_bytes: u64,
        available_bytes: u64,
    },
    #[error("backup checksum mismatch: expected {expected}, calculated {actual}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("database verification failed: {0}")]
    Verification(String),
    #[error("invalid database command: {0}")]
    InvalidCommand(String),
    #[error("traffic query exceeds the {max_source_rows} source-row limit")]
    TrafficQueryTooLarge { max_source_rows: usize },
    #[error("traffic query was cancelled")]
    TrafficQueryCancelled,
    #[error("traffic query exceeded its processing deadline")]
    TrafficQueryTimedOut,
}

pub type DatabaseResult<T> = Result<T, DatabaseError>;

#[derive(Debug, Clone)]
pub struct DatabaseReport {
    pub path: PathBuf,
    pub user_version: i64,
    pub integrity: String,
    pub foreign_key_violations: u64,
    pub table_counts: BTreeMap<String, u64>,
}

#[derive(Debug, Clone)]
pub struct BackupArtifact {
    pub path: PathBuf,
    pub manifest_path: PathBuf,
    pub sha256: String,
    pub user_version: i64,
    pub table_counts: BTreeMap<String, u64>,
}

#[derive(Debug, Clone)]
pub struct QuarantineArtifact {
    pub directory: PathBuf,
    pub manifest_path: PathBuf,
    pub file_checksums: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct MigrationReport {
    pub path: PathBuf,
    pub from_version: i64,
    pub to_version: i64,
    pub backup: Option<BackupArtifact>,
}

#[derive(Debug, Clone)]
pub struct RestoreReport {
    pub path: PathBuf,
    pub restored_from: PathBuf,
    pub recovery_backup: Option<BackupArtifact>,
    pub quarantine: Option<QuarantineArtifact>,
}
