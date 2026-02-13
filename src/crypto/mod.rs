pub mod key_derivation;
pub mod encryption;

pub use key_derivation::{derive_key_from_password, KeyDerivationError};
pub use encryption::{encrypt_data, decrypt_data, EncryptionError};

use argon2::{Argon2, Params, Algorithm, Version};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, Key};
use rand::RngCore;
use sha2::{Sha256, Digest};
use zeroize::Zeroize;
use std::path::Path;

pub const KEY_LENGTH: usize = 32; // 256 bits
pub const NONCE_LENGTH: usize = 12; // 96 bits for AES-GCM
pub const SALT_LENGTH: usize = 16; // 128 bits

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Key derivation error: {0}")]
    KeyDerivation(#[from] KeyDerivationError),
    #[error("Encryption error: {0}")]
    Encryption(#[from] EncryptionError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid file format")]
    InvalidFormat,
}

pub fn encrypt_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    password: &str,
    device_id: Option<&str>,
) -> Result<(), CryptoError> {
    let data = std::fs::read(input_path)?;
    let encrypted_data = encrypt_data(&data, password, device_id)?;
    std::fs::write(output_path, encrypted_data)?;
    Ok(())
}

pub fn decrypt_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    password: &str,
    device_id: Option<&str>,
) -> Result<(), CryptoError> {
    let encrypted_data = std::fs::read(input_path)?;
    let decrypted_data = decrypt_data(&encrypted_data, password, device_id)?;
    std::fs::write(output_path, decrypted_data)?;
    Ok(())
}