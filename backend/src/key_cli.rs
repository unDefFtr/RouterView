use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::db::{
    self, DatabaseError, KeyManagementError, KeyRotationReport, KeyVerificationReport, TrafficDb,
};
use crate::secrets::{SecretCipher, SecretError};

const KEY_CLI_USAGE: &str = "usage: routerview-backend keys verify\n       routerview-backend keys rotate --new-key-file PATH";

#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyCommand {
    Verify,
    Rotate { new_key_file: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyCliEnvironment {
    database_path: PathBuf,
    current_key_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyCommandReport {
    Verified(KeyVerificationReport),
    Rotated(KeyRotationReport),
}

#[derive(Debug, thiserror::Error)]
pub enum KeyCliError {
    #[error("{0}")]
    Usage(String),
    #[error("required environment variable ROUTERVIEW_MASTER_KEY_FILE is not set")]
    MissingCurrentKeyFile,
    #[error("environment variable {0} must not be empty")]
    EmptyPath(&'static str),
    #[error("database does not exist: {0}")]
    DatabaseNotFound(PathBuf),
    #[error("database path is not a regular file: {0}")]
    DatabaseNotFile(PathBuf),
    #[error("failed to inspect database path {path}: {source}")]
    DatabaseMetadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to load the current master key: {0}")]
    CurrentKey(#[source] SecretError),
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error(transparent)]
    KeyManagement(#[from] KeyManagementError),
}

pub fn run_if_requested() -> Result<bool, KeyCliError> {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let Some(command) = parse_key_cli(&args)? else {
        return Ok(false);
    };

    // Key maintenance intentionally does not load normal server configuration.
    // Only these two paths are needed for the offline operation.
    let _ = dotenvy::dotenv();
    let environment = read_environment_with(|name| std::env::var_os(name))?;
    let report = execute(command, environment)?;
    print_report(&report);
    Ok(true)
}

fn parse_key_cli(args: &[OsString]) -> Result<Option<KeyCommand>, KeyCliError> {
    if args.first().map(OsString::as_os_str) != Some(OsStr::new("keys")) {
        return Ok(None);
    }

    match args.get(1).map(OsString::as_os_str) {
        Some(command) if command == OsStr::new("verify") => {
            if args.len() != 2 {
                return Err(usage("keys verify does not accept arguments"));
            }
            Ok(Some(KeyCommand::Verify))
        }
        Some(command) if command == OsStr::new("rotate") => {
            let new_key_file = parse_rotate_options(&args[2..])?;
            Ok(Some(KeyCommand::Rotate { new_key_file }))
        }
        Some(command) => Err(usage(format!(
            "unknown keys command: {}",
            command.to_string_lossy()
        ))),
        None => Err(usage("a keys command is required")),
    }
}

fn parse_rotate_options(args: &[OsString]) -> Result<PathBuf, KeyCliError> {
    let mut new_key_file = None;
    let mut index = 0;
    while index < args.len() {
        if args[index] != OsStr::new("--new-key-file") {
            return Err(usage(format!(
                "unknown keys rotate option: {}",
                args[index].to_string_lossy()
            )));
        }
        index += 1;
        let value = args
            .get(index)
            .ok_or_else(|| usage("--new-key-file requires a path"))?;
        if value.is_empty() {
            return Err(usage("--new-key-file requires a non-empty path"));
        }
        if new_key_file.replace(PathBuf::from(value)).is_some() {
            return Err(usage("--new-key-file may only be specified once"));
        }
        index += 1;
    }

    new_key_file.ok_or_else(|| usage("keys rotate requires --new-key-file PATH"))
}

fn read_environment_with(
    mut get: impl FnMut(&str) -> Option<OsString>,
) -> Result<KeyCliEnvironment, KeyCliError> {
    let database_path = match get("DB_PATH") {
        Some(value) if value.is_empty() => return Err(KeyCliError::EmptyPath("DB_PATH")),
        Some(value) => PathBuf::from(value),
        None => PathBuf::from("traffic.db"),
    };
    let current_key_file = match get("ROUTERVIEW_MASTER_KEY_FILE") {
        Some(value) if value.is_empty() => {
            return Err(KeyCliError::EmptyPath("ROUTERVIEW_MASTER_KEY_FILE"));
        }
        Some(value) => PathBuf::from(value),
        None => return Err(KeyCliError::MissingCurrentKeyFile),
    };

    Ok(KeyCliEnvironment {
        database_path,
        current_key_file,
    })
}

fn execute(
    command: KeyCommand,
    environment: KeyCliEnvironment,
) -> Result<KeyCommandReport, KeyCliError> {
    require_existing_database(&environment.database_path)?;
    let current_cipher =
        SecretCipher::from_file(&environment.current_key_file).map_err(KeyCliError::CurrentKey)?;
    let database = TrafficDb::open_for_bootstrap(&environment.database_path)?;

    match command {
        KeyCommand::Verify => Ok(KeyCommandReport::Verified(db::verify_key(
            &database,
            &current_cipher,
        )?)),
        KeyCommand::Rotate { new_key_file } => Ok(KeyCommandReport::Rotated(db::rotate_key(
            &database,
            &current_cipher,
            new_key_file,
        )?)),
    }
}

fn require_existing_database(path: &Path) -> Result<(), KeyCliError> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(KeyCliError::DatabaseNotFound(path.to_path_buf()));
        }
        Err(source) => {
            return Err(KeyCliError::DatabaseMetadata {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.is_file() {
        return Err(KeyCliError::DatabaseNotFile(path.to_path_buf()));
    }
    Ok(())
}

fn print_report(report: &KeyCommandReport) {
    match report {
        KeyCommandReport::Verified(report) => println!(
            "master_key_verified key_id={} secrets_verified={}",
            report.key_id, report.secrets_verified
        ),
        KeyCommandReport::Rotated(report) => println!(
            "master_key_rotated previous_key_id={} new_key_id={} secrets_rotated={}",
            report.previous_key_id, report.new_key_id, report.secrets_rotated
        ),
    }
}

fn usage(message: impl Into<String>) -> KeyCliError {
    KeyCliError::Usage(format!("{}\n{KEY_CLI_USAGE}", message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "routerview-key-cli-{name}-{}",
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn create_fixture(name: &str) -> (TestDirectory, KeyCliEnvironment, Vec<u8>) {
        let directory = TestDirectory::new(name);
        let database_path = directory.path("routerview.db");
        let current_key_file = directory.path("current.key");
        std::fs::write(&current_key_file, [17; 32]).unwrap();

        let database = TrafficDb::open(&database_path).unwrap();
        let instance_id = database.instance_id().unwrap();
        let cipher = SecretCipher::from_file(&current_key_file).unwrap();
        let plaintext = b"fixture-router-password".to_vec();
        let encrypted = cipher
            .encrypt(&instance_id, "router_password", &plaintext)
            .unwrap();
        database
            .save_config_transaction(&[], Some(("router_password", &encrypted)), None, None)
            .unwrap();
        drop(database);

        (
            directory,
            KeyCliEnvironment {
                database_path,
                current_key_file,
            },
            plaintext,
        )
    }

    #[test]
    fn parses_only_the_supported_key_commands() {
        assert_eq!(
            parse_key_cli(&args(&["keys", "verify"])).unwrap(),
            Some(KeyCommand::Verify)
        );
        assert_eq!(
            parse_key_cli(&args(&[
                "keys",
                "rotate",
                "--new-key-file",
                "/run/secrets/next"
            ]))
            .unwrap(),
            Some(KeyCommand::Rotate {
                new_key_file: PathBuf::from("/run/secrets/next")
            })
        );
        assert_eq!(parse_key_cli(&args(&["db", "check"])).unwrap(), None);
    }

    #[test]
    fn rejects_key_material_and_current_key_options() {
        for invalid in [
            args(&["keys", "rotate", "new-key-material"]),
            args(&["keys", "rotate", "--new-key", "new-key-material"]),
            args(&["keys", "rotate", "--new-key-file"]),
            args(&["keys", "verify", "--current-key-file", "current.key"]),
        ] {
            assert!(matches!(
                parse_key_cli(&invalid),
                Err(KeyCliError::Usage(_))
            ));
        }
    }

    #[test]
    fn environment_reads_only_database_and_current_key_paths() {
        let mut requested = Vec::new();
        let environment = read_environment_with(|name| {
            requested.push(name.to_string());
            match name {
                "DB_PATH" => Some(OsString::from("database.sqlite")),
                "ROUTERVIEW_MASTER_KEY_FILE" => Some(OsString::from("current.key")),
                _ => panic!("unexpected environment lookup: {name}"),
            }
        })
        .unwrap();

        assert_eq!(requested, ["DB_PATH", "ROUTERVIEW_MASTER_KEY_FILE"]);
        assert_eq!(environment.database_path, PathBuf::from("database.sqlite"));
        assert_eq!(environment.current_key_file, PathBuf::from("current.key"));
    }

    #[test]
    fn verifies_the_current_key_and_rejects_a_wrong_key() {
        let (directory, environment, _) = create_fixture("verify");
        let report = execute(KeyCommand::Verify, environment.clone()).unwrap();
        assert!(matches!(
            report,
            KeyCommandReport::Verified(KeyVerificationReport {
                secrets_verified: 1,
                ..
            })
        ));

        let wrong_key_file = directory.path("wrong.key");
        std::fs::write(&wrong_key_file, [18; 32]).unwrap();
        let error = execute(
            KeyCommand::Verify,
            KeyCliEnvironment {
                current_key_file: wrong_key_file,
                ..environment
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            KeyCliError::KeyManagement(KeyManagementError::CurrentKey { .. })
        ));
    }

    #[test]
    fn rotates_to_the_staged_file_and_invalidates_the_old_key() {
        let (directory, environment, expected_plaintext) = create_fixture("rotate");
        let new_key_file = directory.path("next.key");
        std::fs::write(&new_key_file, [19; 32]).unwrap();

        let report = execute(
            KeyCommand::Rotate {
                new_key_file: new_key_file.clone(),
            },
            environment.clone(),
        )
        .unwrap();
        assert!(matches!(
            report,
            KeyCommandReport::Rotated(KeyRotationReport {
                secrets_rotated: 1,
                ..
            })
        ));
        assert!(matches!(
            execute(KeyCommand::Verify, environment.clone()),
            Err(KeyCliError::KeyManagement(
                KeyManagementError::CurrentKey { .. }
            ))
        ));

        let new_environment = KeyCliEnvironment {
            current_key_file: new_key_file.clone(),
            ..environment
        };
        assert!(matches!(
            execute(KeyCommand::Verify, new_environment.clone()).unwrap(),
            KeyCommandReport::Verified(KeyVerificationReport {
                secrets_verified: 1,
                ..
            })
        ));

        let database = TrafficDb::open_for_bootstrap(&new_environment.database_path).unwrap();
        let instance_id = database.instance_id().unwrap();
        let encrypted = database.load_secret("router_password").unwrap().unwrap();
        let new_cipher = SecretCipher::from_file(new_key_file).unwrap();
        assert_eq!(
            new_cipher
                .decrypt(&instance_id, "router_password", &encrypted)
                .unwrap(),
            expected_plaintext
        );
    }

    #[test]
    fn refuses_to_create_a_database_for_a_misspelled_path() {
        let directory = TestDirectory::new("missing-database");
        let current_key_file = directory.path("current.key");
        let database_path = directory.path("missing.db");
        std::fs::write(&current_key_file, [20; 32]).unwrap();

        let error = execute(
            KeyCommand::Verify,
            KeyCliEnvironment {
                database_path: database_path.clone(),
                current_key_file,
            },
        )
        .unwrap_err();
        assert!(matches!(error, KeyCliError::DatabaseNotFound(path) if path == database_path));
        assert!(!database_path.exists());
    }

    #[test]
    fn refuses_key_maintenance_while_the_database_is_locked() {
        let (_directory, environment, _) = create_fixture("locked");
        let held_database = TrafficDb::open_for_bootstrap(&environment.database_path).unwrap();

        let error = execute(KeyCommand::Verify, environment).unwrap_err();
        assert!(matches!(
            error,
            KeyCliError::Database(DatabaseError::InUse(_))
        ));
        drop(held_database);
    }
}
