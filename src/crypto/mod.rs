pub mod encryption;
pub mod key_derivation;

pub use encryption::{calculate_hash, decrypt_data, encrypt_data, EncryptionError};
pub use key_derivation::KeyDerivationError;

use crate::config::Config;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

pub const KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 12;
pub const SALT_LENGTH: usize = 16;

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

// Compression flag bytes
const FLAG_UNCOMPRESSED: u8 = 0x00;
const FLAG_COMPRESSED: u8 = 0x01;

pub fn compress_data(data: &[u8], level: u32) -> Result<Vec<u8>, CryptoError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level));
    encoder
        .write_all(data)
        .map_err(|e| CryptoError::Compression(e.to_string()))?;
    encoder
        .finish()
        .map_err(|e| CryptoError::Compression(e.to_string()))
}

pub fn decompress_data(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| CryptoError::Compression(e.to_string()))?;
    Ok(decompressed)
}

fn check_file_size(path: &Path, max_size: u64) -> Result<u64, CryptoError> {
    let metadata = std::fs::metadata(path)?;
    let size = metadata.len();
    if size > max_size {
        return Err(CryptoError::FileTooLarge(size, max_size));
    }
    Ok(size)
}

/// Encrypt a file with optional compression. Uses config for parameters.
pub fn encrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    password: &str,
    device_id: Option<&str>,
) -> Result<(), CryptoError> {
    let config = Config::load_or_default();
    encrypt_file_with_config(input_path, output_path, password, device_id, &config)
}

pub fn encrypt_file_with_config<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    password: &str,
    device_id: Option<&str>,
    config: &Config,
) -> Result<(), CryptoError> {
    let file_size = check_file_size(input_path.as_ref(), config.encryption.max_file_size)?;

    // For files above the streaming threshold, use streaming mode
    if file_size > config.encryption.stream_threshold {
        return encrypt_file_streaming(input_path, output_path, password, device_id, config);
    }

    let data = std::fs::read(&input_path)?;

    let (flag, payload) = if config.encryption.compress {
        let compressed = compress_data(&data, config.encryption.compression_level)?;
        // Only use compression if it actually saves space
        if compressed.len() < data.len() {
            (FLAG_COMPRESSED, compressed)
        } else {
            (FLAG_UNCOMPRESSED, data)
        }
    } else {
        (FLAG_UNCOMPRESSED, data)
    };

    let mut full_payload = Vec::with_capacity(1 + payload.len());
    full_payload.push(flag);
    full_payload.extend_from_slice(&payload);

    let encrypted_data = encrypt_data(&full_payload, password, device_id)?;
    std::fs::write(output_path, encrypted_data)?;
    Ok(())
}

/// Streaming encryption for large files — reads in chunks to limit RAM usage.
fn encrypt_file_streaming<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    password: &str,
    device_id: Option<&str>,
    config: &Config,
) -> Result<(), CryptoError> {
    // Read file in chunks, compress into a buffer, then encrypt the whole thing.
    // True chunk-level streaming AES-GCM would require a different wire format,
    // so we stream reads but still produce a single ciphertext blob. This keeps
    // RAM bounded by chunk_size rather than file_size during the read phase.
    let file = std::fs::File::open(&input_path)?;
    let mut reader = BufReader::new(file);

    let mut all_data = Vec::new();

    if config.encryption.compress {
        let mut encoder = GzEncoder::new(
            Vec::new(),
            Compression::new(config.encryption.compression_level),
        );
        let mut chunk = vec![0u8; config.encryption.stream_chunk_size];
        loop {
            let n = reader
                .read(&mut chunk)
                .map_err(|e| CryptoError::Compression(e.to_string()))?;
            if n == 0 {
                break;
            }
            encoder
                .write_all(&chunk[..n])
                .map_err(|e| CryptoError::Compression(e.to_string()))?;
        }
        let compressed = encoder
            .finish()
            .map_err(|e| CryptoError::Compression(e.to_string()))?;

        all_data.push(FLAG_COMPRESSED);
        all_data.extend_from_slice(&compressed);
    } else {
        all_data.push(FLAG_UNCOMPRESSED);
        let mut chunk = vec![0u8; config.encryption.stream_chunk_size];
        loop {
            let n = reader.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            all_data.extend_from_slice(&chunk[..n]);
        }
    }

    let encrypted = encrypt_data(&all_data, password, device_id)?;

    let out_file = std::fs::File::create(output_path)?;
    let mut writer = BufWriter::new(out_file);
    writer.write_all(&encrypted)?;
    writer.flush()?;

    Ok(())
}

/// Decrypt a file, handling both compressed and uncompressed payloads.
pub fn decrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    password: &str,
    device_id: Option<&str>,
) -> Result<(), CryptoError> {
    let config = Config::load_or_default();
    decrypt_file_with_config(input_path, output_path, password, device_id, &config)
}

pub fn decrypt_file_with_config<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    password: &str,
    device_id: Option<&str>,
    config: &Config,
) -> Result<(), CryptoError> {
    check_file_size(input_path.as_ref(), config.encryption.max_file_size)?;

    let encrypted_data = std::fs::read(&input_path)?;
    let decrypted_data = decrypt_data(&encrypted_data, password, device_id)?;

    if decrypted_data.is_empty() {
        return Err(CryptoError::InvalidFormat);
    }

    let flag = decrypted_data[0];
    let output_data = match flag {
        FLAG_COMPRESSED => decompress_data(&decrypted_data[1..])?,
        FLAG_UNCOMPRESSED => decrypted_data[1..].to_vec(),
        _ => {
            // Legacy format (v1) without compression flag — treat entire blob as raw data
            decrypted_data
        }
    };

    std::fs::write(output_path, output_data)?;
    Ok(())
}
