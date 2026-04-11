use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::crypto::{decrypt_data, encrypt_data};

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    #[error("Signing failed: {0}")]
    Signing(String),
    #[error("Verification failed: {0}")]
    Verification(String),
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Encryption error: {0}")]
    Encryption(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    #[serde(with = "serde_base64")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_base64")]
    pub private_key: Vec<u8>,
}

/// Wrapper for encrypted key storage on disk.
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedKeyFile {
    /// If true, `data` is AES-encrypted with a passphrase.
    encrypted: bool,
    #[serde(with = "serde_base64")]
    data: Vec<u8>,
}

impl KeyPair {
    pub fn new() -> Result<Self, SignatureError> {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        Ok(KeyPair {
            public_key: signing_key.verifying_key().to_bytes().to_vec(),
            private_key: signing_key.to_bytes().to_vec(),
        })
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignatureError> {
        let secret_bytes: [u8; 32] =
            self.private_key.as_slice().try_into().map_err(|_| {
                SignatureError::InvalidKeyFormat("Invalid private key length".into())
            })?;
        let signing_key = SigningKey::from_bytes(&secret_bytes);

        let signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<bool, SignatureError> {
        let pub_bytes: [u8; 32] =
            self.public_key.as_slice().try_into().map_err(|_| {
                SignatureError::InvalidKeyFormat("Invalid public key length".into())
            })?;
        let verifying_key = VerifyingKey::from_bytes(&pub_bytes)
            .map_err(|e| SignatureError::InvalidKeyFormat(e.to_string()))?;
        let signature = Signature::try_from(signature_bytes)
            .map_err(|e| SignatureError::InvalidKeyFormat(e.to_string()))?;

        match verifying_key.verify(message, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn public_key_only(&self) -> PublicKeyOnly {
        PublicKeyOnly {
            public_key: self.public_key.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyOnly {
    #[serde(with = "serde_base64")]
    pub public_key: Vec<u8>,
}

impl PublicKeyOnly {
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<bool, SignatureError> {
        let pub_bytes: [u8; 32] =
            self.public_key.as_slice().try_into().map_err(|_| {
                SignatureError::InvalidKeyFormat("Invalid public key length".into())
            })?;
        let verifying_key = VerifyingKey::from_bytes(&pub_bytes)
            .map_err(|e| SignatureError::InvalidKeyFormat(e.to_string()))?;
        let signature = Signature::try_from(signature_bytes)
            .map_err(|e| SignatureError::InvalidKeyFormat(e.to_string()))?;

        match verifying_key.verify(message, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

mod serde_base64 {
    use base64::{engine::general_purpose, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}

pub fn generate_keypair() -> Result<KeyPair, SignatureError> {
    KeyPair::new()
}

/// Save a keypair to disk. If `passphrase` is provided, the key JSON is
/// encrypted with AES-256-GCM before writing.
pub fn save_keypair_encrypted<P: AsRef<Path>>(
    keypair: &KeyPair,
    path: P,
    passphrase: Option<&str>,
) -> Result<(), SignatureError> {
    let plain_json = serde_json::to_vec(keypair)?;

    let file_data = if let Some(pass) = passphrase {
        let encrypted = encrypt_data(&plain_json, pass, None)
            .map_err(|e| SignatureError::Encryption(e.to_string()))?;
        EncryptedKeyFile {
            encrypted: true,
            data: encrypted,
        }
    } else {
        EncryptedKeyFile {
            encrypted: false,
            data: plain_json,
        }
    };

    let json = serde_json::to_string_pretty(&file_data)?;
    std::fs::write(&path, &json)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&path, perms)?;
    }

    Ok(())
}

/// Save keypair without encryption (backward compatible).
pub fn save_keypair<P: AsRef<Path>>(keypair: &KeyPair, path: P) -> Result<(), SignatureError> {
    save_keypair_encrypted(keypair, path, None)
}

/// Load a keypair from disk. If the file is encrypted, `passphrase` is required.
pub fn load_keypair_encrypted<P: AsRef<Path>>(
    path: P,
    passphrase: Option<&str>,
) -> Result<KeyPair, SignatureError> {
    let json = std::fs::read_to_string(&path)?;

    // Try new encrypted format first
    if let Ok(key_file) = serde_json::from_str::<EncryptedKeyFile>(&json) {
        if key_file.encrypted {
            let pass = passphrase.ok_or_else(|| {
                SignatureError::Encryption(
                    "Key file is encrypted — passphrase required".to_string(),
                )
            })?;
            let decrypted = decrypt_data(&key_file.data, pass, None)
                .map_err(|e| SignatureError::Encryption(e.to_string()))?;
            let keypair: KeyPair = serde_json::from_slice(&decrypted)?;
            return Ok(keypair);
        } else {
            let keypair: KeyPair = serde_json::from_slice(&key_file.data)?;
            return Ok(keypair);
        }
    }

    // Fallback: try plain KeyPair JSON (old format)
    let keypair: KeyPair = serde_json::from_str(&json)?;
    Ok(keypair)
}

/// Load keypair without passphrase (backward compatible).
pub fn load_keypair<P: AsRef<Path>>(path: P) -> Result<KeyPair, SignatureError> {
    load_keypair_encrypted(path, None)
}

pub fn save_public_key<P: AsRef<Path>>(
    public_key: &PublicKeyOnly,
    path: P,
) -> Result<(), SignatureError> {
    let json = serde_json::to_string_pretty(public_key)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn load_public_key<P: AsRef<Path>>(path: P) -> Result<PublicKeyOnly, SignatureError> {
    let json = std::fs::read_to_string(path)?;
    let public_key = serde_json::from_str(&json)?;
    Ok(public_key)
}

pub fn sign_file<P: AsRef<Path>>(
    file_path: P,
    keypair: &KeyPair,
) -> Result<Vec<u8>, SignatureError> {
    let data = std::fs::read(file_path)?;
    keypair.sign(&data)
}

pub fn verify_file<P: AsRef<Path>>(
    file_path: P,
    public_key: &PublicKeyOnly,
    signature: &[u8],
) -> Result<bool, SignatureError> {
    let data = std::fs::read(file_path)?;
    public_key.verify(&data, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair().unwrap();
        assert_eq!(keypair.public_key.len(), 32);
        assert_eq!(keypair.private_key.len(), 32);
    }

    #[test]
    fn test_sign_verify() {
        let keypair = generate_keypair().unwrap();
        let message = b"Hello, World!";

        let signature = keypair.sign(message).unwrap();
        assert_eq!(signature.len(), 64);

        let is_valid = keypair.verify(message, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_signature() {
        let keypair = generate_keypair().unwrap();

        let signature = keypair.sign(b"Message 1").unwrap();
        let is_valid = keypair.verify(b"Message 2", &signature).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_key_serialization_plain() {
        let keypair = generate_keypair().unwrap();
        let temp_file = NamedTempFile::new().unwrap();

        save_keypair(&keypair, temp_file.path()).unwrap();
        let loaded = load_keypair(temp_file.path()).unwrap();

        assert_eq!(keypair.public_key, loaded.public_key);
        assert_eq!(keypair.private_key, loaded.private_key);
    }

    #[test]
    fn test_key_serialization_encrypted() {
        let keypair = generate_keypair().unwrap();
        let temp_file = NamedTempFile::new().unwrap();
        let passphrase = "keyfile_secret";

        save_keypair_encrypted(&keypair, temp_file.path(), Some(passphrase)).unwrap();

        // Should fail without passphrase
        let fail = load_keypair_encrypted(temp_file.path(), None);
        assert!(fail.is_err());

        // Should succeed with correct passphrase
        let loaded = load_keypair_encrypted(temp_file.path(), Some(passphrase)).unwrap();
        assert_eq!(keypair.public_key, loaded.public_key);
        assert_eq!(keypair.private_key, loaded.private_key);

        // Should fail with wrong passphrase
        let wrong = load_keypair_encrypted(temp_file.path(), Some("wrong"));
        assert!(wrong.is_err());
    }

    #[test]
    fn test_public_key_only() {
        let keypair = generate_keypair().unwrap();
        let public_key_only = keypair.public_key_only();
        let message = b"Test message";

        let signature = keypair.sign(message).unwrap();
        let is_valid = public_key_only.verify(message, &signature).unwrap();
        assert!(is_valid);
    }
}
