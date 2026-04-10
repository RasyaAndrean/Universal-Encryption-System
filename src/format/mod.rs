use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{encrypt_data, decrypt_data, calculate_hash, EncryptionError};
use crate::signature::{KeyPair, PublicKeyOnly, SignatureError};
use crate::hardware::{get_device_fingerprint, HardwareError};

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
            version: 1,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedFileHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub metadata: FileMetadata,
    pub data_hash: [u8; 32],
}

impl EncryptedFileHeader {
    pub fn new(metadata: FileMetadata, data_hash: [u8; 32]) -> Self {
        EncryptedFileHeader {
            magic: *b"SECURE\0\0",
            version: 1,
            metadata,
            data_hash,
        }
    }
    
    pub fn validate_magic(&self) -> bool {
        self.magic == *b"SECURE\0\0"
    }
}

pub struct EncryptedFile {
    pub header: EncryptedFileHeader,
    pub encrypted_data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl EncryptedFile {
    pub fn encrypt_and_sign<P: AsRef<Path>>(
        input_path: P,
        output_path: P,
        password: &str,
        keypair: &KeyPair,
        bind_to_device: bool,
    ) -> Result<Self, FileFormatError> {
        // Read input file
        let plaintext = std::fs::read(&input_path)?;
        
        // Create metadata
        let metadata = FileMetadata::new(&input_path)?;
        
        // Calculate hash of original data
        let data_hash = calculate_hash(&plaintext);
        
        // Create header
        let header = EncryptedFileHeader::new(metadata, data_hash);
        
        // Get device ID if binding is required
        let device_id = if bind_to_device {
            Some(header.metadata.device_fingerprint.as_str())
        } else {
            None
        };
        
        // Encrypt data: prefix header with its length (4 bytes LE) so we can
        // split header from file content reliably during decryption.
        let header_json = serde_json::to_vec(&header)?;
        let header_len = (header_json.len() as u32).to_le_bytes();
        let mut data_to_encrypt = Vec::with_capacity(4 + header_json.len() + plaintext.len());
        data_to_encrypt.extend_from_slice(&header_len);
        data_to_encrypt.extend_from_slice(&header_json);
        data_to_encrypt.extend_from_slice(&plaintext);
        
        let encrypted_data = encrypt_data(&data_to_encrypt, password, device_id)?;
        
        // Sign the encrypted data
        let signature = keypair.sign(&encrypted_data)?;
        
        // Write to output file
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
    
    pub fn decrypt_and_verify<P: AsRef<Path>>(
        input_path: P,
        output_path: P,
        password: &str,
        public_key: &PublicKeyOnly,
        validate_device: bool,
    ) -> Result<FileMetadata, FileFormatError> {
        // Read encrypted file
        let file_bytes = std::fs::read(&input_path)?;
        let file_structure: EncryptedFileStructure = serde_json::from_slice(&file_bytes)?;
        
        // Verify signature
        let is_valid = public_key.verify(&file_structure.encrypted_data, &file_structure.signature)?;
        if !is_valid {
            return Err(FileFormatError::IntegrityCheckFailed);
        }
        
        // Get device ID if validation is required
        let device_id = if validate_device {
            Some(file_structure.header.metadata.device_fingerprint.as_str())
        } else {
            None
        };
        
        // Decrypt data
        let decrypted_data = decrypt_data(&file_structure.encrypted_data, password, device_id)?;
        
        // Parse header from decrypted data using length prefix
        if decrypted_data.len() < 4 {
            return Err(FileFormatError::InvalidFormat);
        }
        let header_len = u32::from_le_bytes(
            decrypted_data[..4].try_into().map_err(|_| FileFormatError::InvalidFormat)?
        ) as usize;
        if decrypted_data.len() < 4 + header_len {
            return Err(FileFormatError::InvalidFormat);
        }
        let header_bytes = &decrypted_data[4..4 + header_len];
        let file_content = &decrypted_data[4 + header_len..];
        let decrypted_header: EncryptedFileHeader = serde_json::from_slice(header_bytes)?;
        
        // Verify data integrity
        let calculated_hash = calculate_hash(file_content);
        if calculated_hash != decrypted_header.data_hash {
            return Err(FileFormatError::IntegrityCheckFailed);
        }
        
        // Validate device binding if required
        if validate_device {
            let current_fingerprint = get_device_fingerprint()?;
            if current_fingerprint != decrypted_header.metadata.device_fingerprint {
                return Err(FileFormatError::DeviceBindingFailed);
            }
        }
        
        // Write decrypted file
        std::fs::write(output_path, file_content)?;
        
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_encrypt_decrypt_file() {
        let keypair = crate::signature::generate_keypair().unwrap();
        let public_key = keypair.public_key_only();
        let password = "test_password";
        
        // Create test file
        let input_file = NamedTempFile::new().unwrap();
        std::fs::write(input_file.path(), b"Hello, World!").unwrap();
        
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();
        
        // Encrypt
        let result = EncryptedFile::encrypt_and_sign(
            input_file.path(),
            encrypted_file.path(),
            password,
            &keypair,
            false,
        );
        assert!(result.is_ok());
        
        // Decrypt
        let metadata = EncryptedFile::decrypt_and_verify(
            encrypted_file.path(),
            decrypted_file.path(),
            password,
            &public_key,
            false,
        );
        assert!(metadata.is_ok());
        
        // Verify content
        let decrypted_content = std::fs::read(decrypted_file.path()).unwrap();
        assert_eq!(decrypted_content, b"Hello, World!");
    }
    
    #[test]
    fn test_wrong_password() {
        let keypair = crate::signature::generate_keypair().unwrap();
        let public_key = keypair.public_key_only();
        let password = "correct_password";
        let wrong_password = "wrong_password";
        
        let input_file = NamedTempFile::new().unwrap();
        std::fs::write(input_file.path(), b"Secret data").unwrap();
        
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();
        
        // Encrypt with correct password
        EncryptedFile::encrypt_and_sign(
            input_file.path(),
            encrypted_file.path(),
            password,
            &keypair,
            false,
        ).unwrap();
        
        // Try to decrypt with wrong password
        let result = EncryptedFile::decrypt_and_verify(
            encrypted_file.path(),
            decrypted_file.path(),
            wrong_password,
            &public_key,
            false,
        );
        assert!(result.is_err());
    }
}