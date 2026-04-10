use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroize;

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    #[serde(with = "serde_base64")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_base64")]
    pub private_key: Vec<u8>,
}

impl KeyPair {
    pub fn new() -> Result<Self, SignatureError> {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);

        Ok(KeyPair {
            public_key: keypair.public.to_bytes().to_vec(),
            private_key: keypair.secret.to_bytes().to_vec(),
        })
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignatureError> {
        let secret_key = SecretKey::from_bytes(&self.private_key)
            .map_err(|e| SignatureError::InvalidKeyFormat(e.to_string()))?;
        let public_key = PublicKey::from_bytes(&self.public_key)
            .map_err(|e| SignatureError::InvalidKeyFormat(e.to_string()))?;
        let keypair = Keypair { secret: secret_key, public: public_key };

        let signature = keypair.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<bool, SignatureError> {
        let public_key = PublicKey::from_bytes(&self.public_key)
            .map_err(|e| SignatureError::InvalidKeyFormat(e.to_string()))?;
        let signature = Signature::try_from(signature_bytes)
            .map_err(|e| SignatureError::InvalidKeyFormat(e.to_string()))?;

        match public_key.verify(message, &signature) {
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
        let public_key = PublicKey::from_bytes(&self.public_key)
            .map_err(|e| SignatureError::InvalidKeyFormat(e.to_string()))?;
        let signature = Signature::try_from(signature_bytes)
            .map_err(|e| SignatureError::InvalidKeyFormat(e.to_string()))?;

        match public_key.verify(message, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

// Helper module for base64 serialization
mod serde_base64 {
    use serde::{Deserialize, Deserializer, Serializer};
    use base64::{Engine as _, engine::general_purpose};

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

pub fn save_keypair<P: AsRef<Path>>(keypair: &KeyPair, path: P) -> Result<(), SignatureError> {
    let json = serde_json::to_string_pretty(keypair)?;
    std::fs::write(&path, &json)?;

    // Set restrictive file permissions on Unix (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&path, perms)?;
    }

    // On Windows, mark file as hidden via attribute
    #[cfg(windows)]
    {
        // Windows doesn't have Unix-style permissions, but we can
        // warn the user to protect the file manually
        eprintln!("Warning: Protect your private key file. Consider storing it in a secure location.");
    }

    Ok(())
}

pub fn load_keypair<P: AsRef<Path>>(path: P) -> Result<KeyPair, SignatureError> {
    let json = std::fs::read_to_string(path)?;
    let keypair = serde_json::from_str(&json)?;
    Ok(keypair)
}

pub fn save_public_key<P: AsRef<Path>>(public_key: &PublicKeyOnly, path: P) -> Result<(), SignatureError> {
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
        let message1 = b"Message 1";
        let message2 = b"Message 2";

        let signature = keypair.sign(message1).unwrap();
        let is_valid = keypair.verify(message2, &signature).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_key_serialization() {
        let keypair = generate_keypair().unwrap();
        let temp_file = NamedTempFile::new().unwrap();

        save_keypair(&keypair, temp_file.path()).unwrap();
        let loaded_keypair = load_keypair(temp_file.path()).unwrap();

        assert_eq!(keypair.public_key, loaded_keypair.public_key);
        assert_eq!(keypair.private_key, loaded_keypair.private_key);
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
