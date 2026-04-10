pub mod crypto;
pub mod signature;
pub mod hardware;
pub mod format;
pub mod security;
pub mod config;

// Re-export key types for easier access
pub use crypto::{encrypt_file, decrypt_file, CryptoError};
pub use crypto::encryption::EncryptionError;
pub use signature::{generate_keypair, sign_file, verify_file, SignatureError};
pub use hardware::{get_device_fingerprint, HardwareError};
pub use format::{EncryptedFile, FileFormatError};

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_basic_encryption_decryption() {
        let password = "TestP@ss123!";
        let content = b"Hello, World!";

        let input_file = NamedTempFile::new().unwrap();
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();

        input_file.as_file().write_all(content).unwrap();

        let encrypt_result = encrypt_file(
            input_file.path(),
            encrypted_file.path(),
            password,
            None
        );
        assert!(encrypt_result.is_ok());

        let decrypt_result = decrypt_file(
            encrypted_file.path(),
            decrypted_file.path(),
            password,
            None
        );
        assert!(decrypt_result.is_ok());

        let decrypted_content = std::fs::read(decrypted_file.path()).unwrap();
        assert_eq!(content, decrypted_content.as_slice());
    }

    #[test]
    fn test_keypair_generation_and_signing() {
        let keypair = generate_keypair().unwrap();
        let message = b"Test message";

        let signature = keypair.sign(message).unwrap();
        let is_valid = keypair.verify(message, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_compression_reduces_size() {
        // Repetitive data compresses well
        let content = "AAAA".repeat(10000);
        let input_file = NamedTempFile::new().unwrap();
        let encrypted_file = NamedTempFile::new().unwrap();

        input_file.as_file().write_all(content.as_bytes()).unwrap();

        encrypt_file(
            input_file.path(),
            encrypted_file.path(),
            "TestP@ss123!",
            None,
        ).unwrap();

        let encrypted_size = std::fs::metadata(encrypted_file.path()).unwrap().len();
        // Encrypted+compressed should be much smaller than 40000 bytes of "AAAA"
        assert!(encrypted_size < content.len() as u64);
    }
}
