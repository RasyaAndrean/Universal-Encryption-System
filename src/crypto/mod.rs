pub mod key_derivation;
pub mod encryption;

pub use key_derivation::{derive_key_from_password, derive_key_with_salt, KeyDerivationError};
pub use encryption::{encrypt_data, decrypt_data, calculate_hash, EncryptionError};

use std::path::Path;
use std::io::{Read, Write};
use flate2::Compression;
use flate2::write::GzEncoder;
use flate2::read::GzDecoder;

pub const KEY_LENGTH: usize = 32; // 256 bits
pub const NONCE_LENGTH: usize = 12; // 96 bits for AES-GCM
pub const SALT_LENGTH: usize = 16; // 128 bits

/// Maximum file size: 2 GiB by default
pub const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024;

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
    #[error("File too large: {0} bytes (max: {1} bytes)")]
    FileTooLarge(u64, u64),
    #[error("Compression error: {0}")]
    Compression(String),
}

/// Compress data using gzip before encryption
pub fn compress_data(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(data)
        .map_err(|e| CryptoError::Compression(e.to_string()))?;
    encoder.finish()
        .map_err(|e| CryptoError::Compression(e.to_string()))
}

/// Decompress gzip data after decryption
pub fn decompress_data(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)
        .map_err(|e| CryptoError::Compression(e.to_string()))?;
    Ok(decompressed)
}

fn check_file_size(path: &Path, max_size: u64) -> Result<(), CryptoError> {
    let metadata = std::fs::metadata(path)?;
    let size = metadata.len();
    if size > max_size {
        return Err(CryptoError::FileTooLarge(size, max_size));
    }
    Ok(())
}

pub fn encrypt_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    password: &str,
    device_id: Option<&str>,
) -> Result<(), CryptoError> {
    check_file_size(input_path.as_ref(), MAX_FILE_SIZE)?;

    let data = std::fs::read(&input_path)?;

    // Compress before encryption
    let compressed = compress_data(&data)?;

    // Prepend a 1-byte flag: 0x01 = compressed
    let mut payload = Vec::with_capacity(1 + compressed.len());
    payload.push(0x01); // compression flag
    payload.extend_from_slice(&compressed);

    let encrypted_data = encrypt_data(&payload, password, device_id)?;
    std::fs::write(output_path, encrypted_data)?;
    Ok(())
}

pub fn decrypt_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    password: &str,
    device_id: Option<&str>,
) -> Result<(), CryptoError> {
    check_file_size(input_path.as_ref(), MAX_FILE_SIZE)?;

    let encrypted_data = std::fs::read(&input_path)?;
    let decrypted_data = decrypt_data(&encrypted_data, password, device_id)?;

    // Check compression flag
    if decrypted_data.is_empty() {
        return Err(CryptoError::InvalidFormat);
    }

    let output_data = if decrypted_data[0] == 0x01 {
        // Data is compressed, decompress
        decompress_data(&decrypted_data[1..])?
    } else {
        // Legacy uncompressed data (no flag or flag == 0x00)
        decrypted_data[1..].to_vec()
    };

    std::fs::write(output_path, output_data)?;
    Ok(())
}
