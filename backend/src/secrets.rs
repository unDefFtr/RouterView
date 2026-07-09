use std::path::Path;

use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct EncryptedSecret {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_id: String,
}

#[derive(Clone)]
pub struct SecretCipher {
    master_key: [u8; 32],
    key_id: String,
}

impl std::fmt::Debug for SecretCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretCipher")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl SecretCipher {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, SecretError> {
        let path = path.as_ref();
        let raw = std::fs::read(path).map_err(|source| SecretError::ReadKey {
            path: path.display().to_string(),
            source,
        })?;
        let master_key = decode_master_key(&raw)?;
        let digest = Sha256::digest(master_key);
        let key_id = hex::encode(&digest[..8]);
        Ok(Self { master_key, key_id })
    }

    #[cfg(test)]
    pub fn from_bytes(master_key: [u8; 32]) -> Self {
        let digest = Sha256::digest(master_key);
        let key_id = hex::encode(&digest[..8]);
        Self { master_key, key_id }
    }

    pub fn encrypt(
        &self,
        instance_id: &str,
        field: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedSecret, SecretError> {
        let key = self.derive_field_key(instance_id, field)?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let aad = self.aad(instance_id, field);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| SecretError::Encrypt)?;
        Ok(EncryptedSecret {
            ciphertext,
            nonce: nonce.to_vec(),
            key_id: self.key_id.clone(),
        })
    }

    pub fn decrypt(
        &self,
        instance_id: &str,
        field: &str,
        secret: &EncryptedSecret,
    ) -> Result<Vec<u8>, SecretError> {
        if secret.key_id != self.key_id {
            return Err(SecretError::WrongKey {
                expected: secret.key_id.clone(),
                actual: self.key_id.clone(),
            });
        }
        if secret.nonce.len() != 24 {
            return Err(SecretError::InvalidNonce);
        }
        let key = self.derive_field_key(instance_id, field)?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        let aad = self.aad(instance_id, field);
        cipher
            .decrypt(
                XNonce::from_slice(&secret.nonce),
                Payload {
                    msg: &secret.ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| SecretError::Decrypt)
    }

    fn derive_field_key(&self, instance_id: &str, field: &str) -> Result<[u8; 32], SecretError> {
        let hkdf = Hkdf::<Sha256>::new(Some(instance_id.as_bytes()), &self.master_key);
        let mut key = [0u8; 32];
        let info = format!("routerview/{field}/v1");
        hkdf.expand(info.as_bytes(), &mut key)
            .map_err(|_| SecretError::Derive)?;
        Ok(key)
    }

    fn aad(&self, instance_id: &str, field: &str) -> String {
        format!("routerview:{instance_id}:{field}:{}", self.key_id)
    }
}

fn decode_master_key(raw: &[u8]) -> Result<[u8; 32], SecretError> {
    if raw.len() == 32 {
        return raw.try_into().map_err(|_| SecretError::InvalidKey);
    }

    let text = std::str::from_utf8(raw)
        .map_err(|_| SecretError::InvalidKey)?
        .trim();
    let decoded = if text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(text).map_err(|_| SecretError::InvalidKey)?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(|_| SecretError::InvalidKey)?
    };
    decoded.try_into().map_err(|_| SecretError::InvalidKey)
}

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("failed to read master key file {path}: {source}")]
    ReadKey {
        path: String,
        source: std::io::Error,
    },
    #[error(
        "master key must contain exactly 32 raw bytes, 64 hex characters, or base64 for 32 bytes"
    )]
    InvalidKey,
    #[error("failed to derive the field encryption key")]
    Derive,
    #[error("failed to encrypt secret")]
    Encrypt,
    #[error("failed to decrypt secret; the database or associated metadata may be corrupt")]
    Decrypt,
    #[error("encrypted secret has an invalid nonce")]
    InvalidNonce,
    #[error("master key mismatch (database key id {expected}, supplied key id {actual})")]
    WrongKey { expected: String, actual: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_binds_ciphertext_to_instance_and_field() {
        let cipher = SecretCipher::from_bytes([7; 32]);
        let encrypted = cipher
            .encrypt("instance-a", "router_password", b"secret")
            .unwrap();
        assert_eq!(
            cipher
                .decrypt("instance-a", "router_password", &encrypted)
                .unwrap(),
            b"secret"
        );
        assert!(cipher
            .decrypt("instance-b", "router_password", &encrypted)
            .is_err());
        assert!(cipher
            .decrypt("instance-a", "another_field", &encrypted)
            .is_err());
    }

    #[test]
    fn rejects_wrong_master_key() {
        let one = SecretCipher::from_bytes([1; 32]);
        let two = SecretCipher::from_bytes([2; 32]);
        let encrypted = one
            .encrypt("instance", "router_password", b"secret")
            .unwrap();
        assert!(matches!(
            two.decrypt("instance", "router_password", &encrypted),
            Err(SecretError::WrongKey { .. })
        ));
    }
}
