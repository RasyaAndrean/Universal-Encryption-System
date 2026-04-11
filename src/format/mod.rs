use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{Config, FORMAT_VERSION, SUPPORTED_FORMAT_VERSIONS};
use crate::crypto::{
    calculate_hash, compress_data, decompress_data, decrypt_data, encrypt_data, EncryptionError,
};
use crate::hardware::{get_device_fingerprint, HardwareError};
use crate::signature::{KeyPair, PublicKeyOnly, SignatureError};

#[derive(Debug, thiserror::Error)]
pub enum FileFormatError {
    #[error("Encryption error: {0}")]
    Encryption(#[from] EncryptionError),
    #[error("Signature error: {0}")]
    Signature(#[from] SignatureError),
    #[error("Hardware error: {0}")]
    Hardware(#[from] HardwareError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("File integrity check failed")]
    IntegrityCheckFailed,
    #[error("Device binding validation failed")]
    DeviceBindingFailed,
    #[error("Invalid file format")]
    InvalidFormat,
    #[error("Unsupported format version: {0} (supported: {1:?})")]
    UnsupportedVersion(u32, Vec<u32>),
    #[error("Compression error: {0}")]
    Compression(#[from] crate::crypto::CryptoError),
    #[error("File too large: {0} bytes (max: {1} bytes)")]
    FileTooLarge(u64, u64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub original_filename: String,
    pub file_size: u64,
    pub creation_time: u64,
    pub modification_time: u64,
    pub device_fingerprint: String,
    pub version: u32,
}

impl FileMetadata {
    pub fn new<P: AsRef<Path>>(file_path: P) -> Result<Self, FileFormatError> {
        let path = file_path.as_ref();
        let metadata = std::fs::metadata(path)?;

        let filename = path
            .file_name()
            .ok_or(FileFormatError::InvalidFormat)?
            .to_string_lossy()
            .to_string();

        let creation_time = metadata
            .created()
            .unwrap_or(SystemTime::UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let modification_time = metadata
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let device_fingerprint = get_device_fingerprint()?;

        Ok(FileMetadata {
            original_filename: filename,
            file_size: metadata.len(),
            creation_time,
            modification_time,
            device_fingerprint,
            version: FORMAT_VERSION,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedFileHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub metadata: FileMetadata,
    pub data_hash: [u8; 32],
    /// Whether the plaintext was compressed before encryption (v2+)
    #[serde(default)]
    pub compressed: bool,
}

impl EncryptedFileHeader {
    pub fn new(metadata: FileMetadata, data_hash: [u8; 32], compressed: bool) -> Self {
        EncryptedFileHeader {
            magic: *b"SECURE\0\0",
            version: FORMAT_VERSION,
            metadata,
            data_hash,
            compressed,
        }
    }

    pub fn validate_magic(&self) -> bool {
        self.magic == *b"SECURE\0\0"
    }

    pub fn validate_version(&self) -> Result<(), FileFormatError> {
        if SUPPORTED_FORMAT_VERSIONS.contains(&self.version) {
            Ok(())
        } else {
            Err(FileFormatError::UnsupportedVersion(
                self.version,
                SUPPORTED_FORMAT_VERSIONS.to_vec(),
            ))
        }
    }
}

pub struct EncryptedFile {
    pub header: EncryptedFileHeader,
    pub encrypted_data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl EncryptedFile {
    pub fn encrypt_and_sign<P: AsRef<Path>, Q: AsRef<Path>>(
        input_path: P,
        output_path: Q,
        password: &str,
        keypair: &KeyPair,
        bind_to_device: bool,
    ) -> Result<Self, FileFormatError> {
        let config = Config::load_or_default();

        // Check file size
        let meta = std::fs::metadata(input_path.as_ref())?;
        if meta.len() > config.encryption.max_file_size {
            return Err(FileFormatError::FileTooLarge(
                meta.len(),
                config.encryption.max_file_size,
            ));
        }

        let plaintext = std::fs::read(&input_path)?;
        let metadata = FileMetadata::new(&input_path)?;

        // Calculate hash of original data (before compression)
        let data_hash = calculate_hash(&plaintext);

        // Compress if enabled and beneficial
        let (content, compressed) = if config.encryption.compress {
            let c = compress_data(&plaintext, config.encryption.compression_level)?;
            if c.len() < plaintext.len() {
                (c, true)
            } else {
                (plaintext, false)
            }
        } else {
            (plaintext, false)
        };

        let header = EncryptedFileHeader::new(metadata, data_hash, compressed);

        let device_id = if bind_to_device {
            Some(header.metadata.device_fingerprint.as_str())
        } else {
            None
        };

        // Length-prefixed header + content
        let header_json = serde_json::to_vec(&header)?;
        let header_len = (header_json.len() as u32).to_le_bytes();
        let mut data_to_encrypt = Vec::with_capacity(4 + header_json.len() + content.len());
        data_to_encrypt.extend_from_slice(&header_len);
        data_to_encrypt.extend_from_slice(&header_json);
        data_to_encrypt.extend_from_slice(&content);

        let encrypted_data = encrypt_data(&data_to_encrypt, password, device_id)?;

        let signature = keypair.sign(&encrypted_data)?;

        let file_structure = EncryptedFileStructure {
            header: header.clone(),
            encrypted_data: encrypted_data.clone(),
            signature: signature.clone(),
        };

        let file_bytes = serde_json::to_vec(&file_structure)?;
        std::fs::write(output_path, file_bytes)?;

        Ok(EncryptedFile {
            header,
            encrypted_data,
            signature,
        })
    }

    pub fn decrypt_and_verify<P: AsRef<Path>, Q: AsRef<Path>>(
        input_path: P,
        output_path: Q,
        password: &str,
        public_key: &PublicKeyOnly,
        validate_device: bool,
    ) -> Result<FileMetadata, FileFormatError> {
        let file_bytes = std::fs::read(&input_path)?;
        let file_structure: EncryptedFileStructure = serde_json::from_slice(&file_bytes)?;

        // Validate format version
        file_structure.header.validate_version()?;

        // Verify signature
        let is_valid =
            public_key.verify(&file_structure.encrypted_data, &file_structure.signature)?;
        if !is_valid {
            return Err(FileFormatError::IntegrityCheckFailed);
        }

        let device_id = if validate_device {
            Some(file_structure.header.metadata.device_fingerprint.as_str())
        } else {
            None
        };

        let decrypted_data = decrypt_data(&file_structure.encrypted_data, password, device_id)?;

        // Parse header from decrypted data using length prefix
        if decrypted_data.len() < 4 {
            return Err(FileFormatError::InvalidFormat);
        }
        let header_len = u32::from_le_bytes(
            decrypted_data[..4]
                .try_into()
                .map_err(|_| FileFormatError::InvalidFormat)?,
        ) as usize;
        if decrypted_data.len() < 4 + header_len {
            return Err(FileFormatError::InvalidFormat);
        }
        let header_bytes = &decrypted_data[4..4 + header_len];
        let raw_content = &decrypted_data[4 + header_len..];
        let decrypted_header: EncryptedFileHeader = serde_json::from_slice(header_bytes)?;

        // Decompress if the header says content was compressed (v2+)
        let file_content = if decrypted_header.compressed {
            decompress_data(raw_content)?
        } else {
            raw_content.to_vec()
        };

        // Verify data integrity (hash is always of the original uncompressed data)
        let calculated_hash = calculate_hash(&file_content);
        if calculated_hash != decrypted_header.data_hash {
            return Err(FileFormatError::IntegrityCheckFailed);
        }

        // Validate device binding
        if validate_device {
            let current_fingerprint = get_device_fingerprint()?;
            if current_fingerprint != decrypted_header.metadata.device_fingerprint {
                return Err(FileFormatError::DeviceBindingFailed);
            }
        }

        std::fs::write(output_path, &file_content)?;

        Ok(decrypted_header.metadata)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedFileStructure {
    pub header: EncryptedFileHeader,
    #[serde(with = "serde_base64")]
    pub encrypted_data: Vec<u8>,
    #[serde(with = "serde_base64")]
    pub signature: Vec<u8>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_encrypt_decrypt_file() {
        let keypair = crate::signature::generate_keypair().unwrap();
        let public_key = keypair.public_key_only();
        let password = "test_password";

        let input_file = NamedTempFile::new().unwrap();
        std::fs::write(input_file.path(), b"Hello, World!").unwrap();

        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();

        let result = EncryptedFile::encrypt_and_sign(
            input_file.path(),
            encrypted_file.path(),
            password,
            &keypair,
            false,
        );
        assert!(result.is_ok());

        let metadata = EncryptedFile::decrypt_and_verify(
            encrypted_file.path(),
            decrypted_file.path(),
            password,
            &public_key,
            false,
        );
        assert!(metadata.is_ok());

        let decrypted_content = std::fs::read(decrypted_file.path()).unwrap();
        assert_eq!(decrypted_content, b"Hello, World!");
    }

    #[test]
    fn test_wrong_password() {
        let keypair = crate::signature::generate_keypair().unwrap();
        let public_key = keypair.public_key_only();

        let input_file = NamedTempFile::new().unwrap();
        std::fs::write(input_file.path(), b"Secret data").unwrap();

        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();

        EncryptedFile::encrypt_and_sign(
            input_file.path(),
            encrypted_file.path(),
            "correct_password",
            &keypair,
            false,
        )
        .unwrap();

        let result = EncryptedFile::decrypt_and_verify(
            encrypted_file.path(),
            decrypted_file.path(),
            "wrong_password",
            &public_key,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_compression_in_signed_path() {
        let keypair = crate::signature::generate_keypair().unwrap();
        let public_key = keypair.public_key_only();

        let content = "Repetitive data! ".repeat(500);
        let input_file = NamedTempFile::new().unwrap();
        std::fs::write(input_file.path(), content.as_bytes()).unwrap();

        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();

        EncryptedFile::encrypt_and_sign(
            input_file.path(),
            encrypted_file.path(),
            "test_password",
            &keypair,
            false,
        )
        .unwrap();

        let metadata = EncryptedFile::decrypt_and_verify(
            encrypted_file.path(),
            decrypted_file.path(),
            "test_password",
            &public_key,
            false,
        )
        .unwrap();

        let decrypted = std::fs::read(decrypted_file.path()).unwrap();
        assert_eq!(decrypted, content.as_bytes());
        assert_eq!(metadata.version, FORMAT_VERSION);
    }
}
