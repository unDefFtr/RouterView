use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use zeroize::Zeroizing;

use super::TrafficDb;
use crate::secrets::{EncryptedSecret, SecretCipher, SecretError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyVerificationReport {
    pub key_id: String,
    pub secrets_verified: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRotationReport {
    pub previous_key_id: String,
    pub new_key_id: String,
    pub secrets_rotated: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum KeyManagementError {
    #[error("database access failed: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("database lock is poisoned")]
    LockPoisoned,
    #[error("encrypted secrets exist but the database instance_id is missing")]
    MissingInstanceId,
    #[error("current master key could not decrypt secret {name}: {source}")]
    CurrentKey {
        name: String,
        #[source]
        source: SecretError,
    },
    #[error("failed to load the staged new master key: {0}")]
    NewKey(#[source] SecretError),
    #[error("failed to re-encrypt secret {name}: {source}")]
    Encrypt {
        name: String,
        #[source]
        source: SecretError,
    },
    #[error("staged secret {name} could not be decrypted during read-back: {source}")]
    ReadBack {
        name: String,
        #[source]
        source: SecretError,
    },
    #[error("staged secret {name} did not match its pre-rotation plaintext")]
    PlaintextMismatch { name: String },
    #[error("staged secret {name} did not match the ciphertext written by the rotation")]
    CiphertextMismatch { name: String },
    #[error("secret set changed while the key rotation transaction was active")]
    SecretSetChanged,
    #[error("key rotation failed ({operation}) and the database rollback also failed: {source}")]
    RollbackFailed {
        operation: String,
        #[source]
        source: rusqlite::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredSecret {
    name: String,
    encrypted: EncryptedSecret,
}

struct RotatedSecret {
    name: String,
    plaintext: Zeroizing<Vec<u8>>,
    encrypted: EncryptedSecret,
}

/// Verify that `current_cipher` can decrypt every encrypted secret in the database.
///
/// The check runs against one SQLite snapshot. An empty secret table is valid and
/// does not require an instance identifier.
pub fn verify_key(
    db: &TrafficDb,
    current_cipher: &SecretCipher,
) -> Result<KeyVerificationReport, KeyManagementError> {
    let mut conn = db
        .conn
        .lock()
        .map_err(|_| KeyManagementError::LockPoisoned)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let result = verify_transaction(&tx, current_cipher);

    match result {
        Ok(report) => {
            tx.commit()?;
            Ok(report)
        }
        Err(error) => rollback_error(tx, error),
    }
}

/// Re-encrypt every database secret using a staged key read exclusively from a file.
///
/// All current-key verification happens before the first update. The newly written
/// rows are read back, decrypted, and compared inside the same immediate transaction
/// before it is committed.
pub fn rotate_key(
    db: &TrafficDb,
    current_cipher: &SecretCipher,
    new_key_file: impl AsRef<Path>,
) -> Result<KeyRotationReport, KeyManagementError> {
    let new_cipher = SecretCipher::from_file(new_key_file).map_err(KeyManagementError::NewKey)?;
    rotate_with_cipher(db, current_cipher, &new_cipher)
}

fn verify_transaction(
    tx: &Transaction<'_>,
    current_cipher: &SecretCipher,
) -> Result<KeyVerificationReport, KeyManagementError> {
    let secrets = load_secrets(tx)?;
    if let Some(instance_id) = instance_id_for(tx, &secrets)? {
        for secret in &secrets {
            let _plaintext = Zeroizing::new(
                current_cipher
                    .decrypt(&instance_id, &secret.name, &secret.encrypted)
                    .map_err(|source| KeyManagementError::CurrentKey {
                        name: secret.name.clone(),
                        source,
                    })?,
            );
        }
    }

    Ok(KeyVerificationReport {
        key_id: current_cipher.key_id().to_string(),
        secrets_verified: secrets.len(),
    })
}

fn rotate_with_cipher(
    db: &TrafficDb,
    current_cipher: &SecretCipher,
    new_cipher: &SecretCipher,
) -> Result<KeyRotationReport, KeyManagementError> {
    let mut conn = db
        .conn
        .lock()
        .map_err(|_| KeyManagementError::LockPoisoned)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = rotate_transaction(&tx, current_cipher, new_cipher);

    match result {
        Ok(report) => {
            tx.commit()?;
            Ok(report)
        }
        Err(error) => rollback_error(tx, error),
    }
}

fn rotate_transaction(
    tx: &Transaction<'_>,
    current_cipher: &SecretCipher,
    new_cipher: &SecretCipher,
) -> Result<KeyRotationReport, KeyManagementError> {
    let stored = load_secrets(tx)?;
    let Some(instance_id) = instance_id_for(tx, &stored)? else {
        return Ok(KeyRotationReport {
            previous_key_id: current_cipher.key_id().to_string(),
            new_key_id: new_cipher.key_id().to_string(),
            secrets_rotated: 0,
        });
    };

    // Verify and prepare the complete replacement set before mutating any row.
    let mut replacements = Vec::with_capacity(stored.len());
    for secret in &stored {
        let plaintext = Zeroizing::new(
            current_cipher
                .decrypt(&instance_id, &secret.name, &secret.encrypted)
                .map_err(|source| KeyManagementError::CurrentKey {
                    name: secret.name.clone(),
                    source,
                })?,
        );
        let encrypted = new_cipher
            .encrypt(&instance_id, &secret.name, plaintext.as_slice())
            .map_err(|source| KeyManagementError::Encrypt {
                name: secret.name.clone(),
                source,
            })?;
        replacements.push(RotatedSecret {
            name: secret.name.clone(),
            plaintext,
            encrypted,
        });
    }

    for replacement in &replacements {
        let changed = tx.execute(
            "UPDATE encrypted_secrets
             SET ciphertext = ?1, nonce = ?2, key_id = ?3, updated_at = unixepoch()
             WHERE name = ?4",
            params![
                replacement.encrypted.ciphertext,
                replacement.encrypted.nonce,
                replacement.encrypted.key_id,
                replacement.name,
            ],
        )?;
        if changed != 1 {
            return Err(KeyManagementError::SecretSetChanged);
        }
    }

    let read_back = load_secrets(tx)?;
    if read_back.len() != replacements.len() {
        return Err(KeyManagementError::SecretSetChanged);
    }

    for (actual, expected) in read_back.iter().zip(&replacements) {
        if actual.name != expected.name {
            return Err(KeyManagementError::SecretSetChanged);
        }
        let plaintext = Zeroizing::new(
            new_cipher
                .decrypt(&instance_id, &actual.name, &actual.encrypted)
                .map_err(|source| KeyManagementError::ReadBack {
                    name: actual.name.clone(),
                    source,
                })?,
        );
        if plaintext.as_slice() != expected.plaintext.as_slice() {
            return Err(KeyManagementError::PlaintextMismatch {
                name: actual.name.clone(),
            });
        }
        if actual.encrypted != expected.encrypted {
            return Err(KeyManagementError::CiphertextMismatch {
                name: actual.name.clone(),
            });
        }
    }

    Ok(KeyRotationReport {
        previous_key_id: current_cipher.key_id().to_string(),
        new_key_id: new_cipher.key_id().to_string(),
        secrets_rotated: replacements.len(),
    })
}

fn rollback_error<T>(
    tx: Transaction<'_>,
    operation_error: KeyManagementError,
) -> Result<T, KeyManagementError> {
    match tx.rollback() {
        Ok(()) => Err(operation_error),
        Err(source) => Err(KeyManagementError::RollbackFailed {
            operation: operation_error.to_string(),
            source,
        }),
    }
}

fn instance_id_for(
    conn: &Connection,
    secrets: &[StoredSecret],
) -> Result<Option<String>, KeyManagementError> {
    if secrets.is_empty() {
        return Ok(None);
    }
    conn.query_row(
        "SELECT value FROM config WHERE key = 'instance_id'",
        [],
        |row| row.get::<_, String>(0),
    )
    .optional()?
    .filter(|value| !value.is_empty())
    .map(Some)
    .ok_or(KeyManagementError::MissingInstanceId)
}

fn load_secrets(conn: &Connection) -> Result<Vec<StoredSecret>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT name, ciphertext, nonce, key_id
         FROM encrypted_secrets
         ORDER BY name",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(StoredSecret {
            name: row.get(0)?,
            encrypted: EncryptedSecret {
                ciphertext: row.get(1)?,
                nonce: row.get(2)?,
                key_id: row.get(3)?,
            },
        })
    })?;
    rows.collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn memory_db() -> TrafficDb {
        TrafficDb::open(&PathBuf::from(":memory:")).unwrap()
    }

    fn store_secret(
        db: &TrafficDb,
        instance_id: &str,
        name: &str,
        plaintext: &[u8],
        cipher: &SecretCipher,
    ) {
        let encrypted = cipher.encrypt(instance_id, name, plaintext).unwrap();
        db.save_config_transaction(&[], Some((name, &encrypted)), None, None)
            .unwrap();
    }

    fn snapshot(db: &TrafficDb) -> Vec<StoredSecret> {
        let conn = db.conn.lock().unwrap();
        load_secrets(&conn).unwrap()
    }

    #[test]
    fn verifies_every_secret_and_rejects_a_wrong_key() {
        let db = memory_db();
        let instance_id = db.instance_id().unwrap();
        let current = SecretCipher::from_bytes([1; 32]);
        let wrong = SecretCipher::from_bytes([2; 32]);
        store_secret(&db, &instance_id, "api_token", b"token", &current);
        store_secret(&db, &instance_id, "router_password", b"password", &current);

        let report = verify_key(&db, &current).unwrap();
        assert_eq!(report.secrets_verified, 2);
        assert_eq!(report.key_id, current.key_id());

        assert!(matches!(
            verify_key(&db, &wrong),
            Err(KeyManagementError::CurrentKey {
                source: SecretError::WrongKey { .. },
                ..
            })
        ));
    }

    #[test]
    fn mixed_keys_are_rejected_before_any_row_is_changed() {
        let db = memory_db();
        let instance_id = db.instance_id().unwrap();
        let current = SecretCipher::from_bytes([3; 32]);
        let other = SecretCipher::from_bytes([4; 32]);
        let next = SecretCipher::from_bytes([5; 32]);
        store_secret(&db, &instance_id, "first", b"one", &current);
        store_secret(&db, &instance_id, "second", b"two", &other);
        let before = snapshot(&db);

        assert!(matches!(
            rotate_with_cipher(&db, &current, &next),
            Err(KeyManagementError::CurrentKey {
                source: SecretError::WrongKey { .. },
                ..
            })
        ));
        assert_eq!(snapshot(&db), before);
        assert_eq!(
            current
                .decrypt(&instance_id, "first", &before[0].encrypted)
                .unwrap(),
            b"one"
        );
        assert_eq!(
            other
                .decrypt(&instance_id, "second", &before[1].encrypted)
                .unwrap(),
            b"two"
        );
    }

    #[test]
    fn rotates_to_a_key_loaded_from_a_file() {
        let db = memory_db();
        let instance_id = db.instance_id().unwrap();
        let current = SecretCipher::from_bytes([6; 32]);
        store_secret(
            &db,
            &instance_id,
            "router_password",
            b"new-password",
            &current,
        );

        let key_path =
            std::env::temp_dir().join(format!("routerview-staged-key-{}", uuid::Uuid::new_v4()));
        std::fs::write(&key_path, [7; 32]).unwrap();
        let expected_next = SecretCipher::from_bytes([7; 32]);
        let report = rotate_key(&db, &current, &key_path).unwrap();
        std::fs::remove_file(&key_path).unwrap();

        assert_eq!(report.previous_key_id, current.key_id());
        assert_eq!(report.new_key_id, expected_next.key_id());
        assert_eq!(report.secrets_rotated, 1);
        assert!(verify_key(&db, &current).is_err());
        assert_eq!(verify_key(&db, &expected_next).unwrap().secrets_verified, 1);
    }

    #[test]
    fn read_back_failure_rolls_back_every_updated_row() {
        let db = memory_db();
        let instance_id = db.instance_id().unwrap();
        let current = SecretCipher::from_bytes([8; 32]);
        let next = SecretCipher::from_bytes([9; 32]);
        store_secret(&db, &instance_id, "first", b"one", &current);
        store_secret(&db, &instance_id, "second", b"two", &current);
        let before = snapshot(&db);

        {
            let conn = db.conn.lock().unwrap();
            conn.execute_batch(
                "CREATE TRIGGER corrupt_rotated_secret
                 AFTER UPDATE ON encrypted_secrets
                 WHEN NEW.name = 'second'
                 BEGIN
                     UPDATE encrypted_secrets SET ciphertext = X'00' WHERE name = NEW.name;
                 END;",
            )
            .unwrap();
        }

        assert!(matches!(
            rotate_with_cipher(&db, &current, &next),
            Err(KeyManagementError::ReadBack { .. })
        ));
        assert_eq!(snapshot(&db), before);
        assert_eq!(verify_key(&db, &current).unwrap().secrets_verified, 2);
        assert!(verify_key(&db, &next).is_err());
    }
}
