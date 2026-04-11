use aes_gcm::{
    aead::{Aead, Key},
    Aes256Gcm, KeyInit, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::crypto::key_derivation::{
    derive_key_from_password, derive_key_with_salt, KeyDerivationError,
};

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("Key derivation error: {0}")]
    KeyDerivation(#[from] KeyDerivationError),
    #[error("Encryption failed: {0}")]
    Encryption(String),
    #[error("Decryption failed: {0}")]
    Decryption(String),
    #[error("Invalid nonce length")]
    InvalidNonce,
    #[error("Invalid data format")]
    InvalidFormat,
}

// File format constants
const MAGIC_BYTES: &[u8] = b"ENCRYPT\0";
const VERSION: u8 = 1;
const NONCE_LENGTH: usize = 12;
const SALT_LENGTH: usize = 16;
const TAG_LENGTH: usize = 16;
const HEADER_LENGTH: usize = MAGIC_BYTES.len() + 1 + SALT_LENGTH + NONCE_LENGTH;

pub struct EncryptedData {
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}

pub fn encrypt_data(
    plaintext: &[u8],
    password: &str,
    device_id: Option<&str>,
) -> Result<Vec<u8>, EncryptionError> {
    // Derive key
    let derived_key = derive_key_from_password(password, device_id)?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Create cipher
    let key = Key::<Aes256Gcm>::from_slice(&derived_key.key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt data
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| EncryptionError::Encryption(e.to_string()))?;

    // Extract tag from ciphertext (last 16 bytes)
    if ciphertext.len() < TAG_LENGTH {
        return Err(EncryptionError::Encryption(
            "Ciphertext too short".to_string(),
        ));
    }

    let (data, tag_bytes) = ciphertext.split_at(ciphertext.len() - TAG_LENGTH);
    let tag: [u8; 16] = tag_bytes
        .try_into()
        .map_err(|_| EncryptionError::Encryption("Invalid tag length".to_string()))?;

    // Build output
    let mut output = Vec::with_capacity(HEADER_LENGTH + data.len());

    // Header: magic bytes + version + salt + nonce
    output.extend_from_slice(MAGIC_BYTES);
    output.push(VERSION);
    output.extend_from_slice(&derived_key.salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(data);
    output.extend_from_slice(&tag);

    Ok(output)
}

pub fn decrypt_data(
    encrypted_data: &[u8],
    password: &str,
    device_id: Option<&str>,
) -> Result<Vec<u8>, EncryptionError> {
    // Verify minimum length
    if encrypted_data.len() < HEADER_LENGTH + TAG_LENGTH {
        return Err(EncryptionError::InvalidFormat);
    }

    // Verify magic bytes and version
    if !encrypted_data.starts_with(MAGIC_BYTES) {
        return Err(EncryptionError::InvalidFormat);
    }

    let version = encrypted_data[MAGIC_BYTES.len()];
    if version != VERSION {
        return Err(EncryptionError::InvalidFormat);
    }

    // Extract components
    let salt_start = MAGIC_BYTES.len() + 1;
    let nonce_start = salt_start + SALT_LENGTH;
    let data_start = nonce_start + NONCE_LENGTH;

    let salt: [u8; 16] = encrypted_data[salt_start..salt_start + SALT_LENGTH]
        .try_into()
        .map_err(|_| EncryptionError::InvalidFormat)?;

    let nonce: [u8; 12] = encrypted_data[nonce_start..nonce_start + NONCE_LENGTH]
        .try_into()
        .map_err(|_| EncryptionError::InvalidFormat)?;

    let data_and_tag = &encrypted_data[data_start..];
    if data_and_tag.len() < TAG_LENGTH {
        return Err(EncryptionError::InvalidFormat);
    }

    let (data, tag_bytes) = data_and_tag.split_at(data_and_tag.len() - TAG_LENGTH);
    let tag: [u8; 16] = tag_bytes
        .try_into()
        .map_err(|_| EncryptionError::InvalidFormat)?;

    // Derive key with the same salt
    let key_bytes = derive_key_with_salt(password, &salt, device_id)?;

    // Create cipher
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce);

    // Prepare data with tag
    let mut ciphertext = data.to_vec();
    ciphertext.extend_from_slice(&tag);

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| EncryptionError::Decryption(e.to_string()))?;

    Ok(plaintext)
}

pub fn calculate_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = b"Hello, World! This is a test message.";
        let password = "test_password_123";
        let device_id = "test_device";

        let encrypted = encrypt_data(plaintext, password, Some(device_id)).unwrap();
        let decrypted = decrypt_data(&encrypted, password, Some(device_id)).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_wrong_password() {
        let plaintext = b"Secret message";
        let password = "correct_password";
        let wrong_password = "wrong_password";

        let encrypted = encrypt_data(plaintext, password, None).unwrap();
        let result = decrypt_data(&encrypted, wrong_password, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_device_id() {
        let plaintext = b"Device-bound message";
        let password = "password";
        let device_id = "device1";
        let wrong_device_id = "device2";

        let encrypted = encrypt_data(plaintext, password, Some(device_id)).unwrap();
        let result = decrypt_data(&encrypted, password, Some(wrong_device_id));

        assert!(result.is_err());
    }

    #[test]
    fn test_hash_calculation() {
        let data = b"test data";
        let hash = calculate_hash(data);
        assert_eq!(hash.len(), 32);

        // Same input should produce same hash
        let hash2 = calculate_hash(data);
        assert_eq!(hash, hash2);
    }
}
