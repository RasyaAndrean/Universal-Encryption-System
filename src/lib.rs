pub mod crypto;
pub mod signature;
pub mod hardware;
pub mod format;
pub mod security;

// Re-export key types for easier access
pub use crypto::{encrypt_file, decrypt_file, EncryptionError};
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
        
        // Encrypt
        let encrypt_result = encrypt_file(
            input_file.path(),
            encrypted_file.path(),
            password,
            None
        );
        assert!(encrypt_result.is_ok());
        
        // Decrypt
        let decrypt_result = decrypt_file(
            encrypted_file.path(),
            decrypted_file.path(),
            password,
            None
        );
        assert!(decrypt_result.is_ok());
        
        // Verify content
        let decrypted_content = std::fs::read(decrypted_file.path()).unwrap();
        assert_eq!(content, decrypted_content.as_slice());
    }

    #[test]
    fn test_keypair_generation_and_signing() {
        let keypair_result = generate_keypair();
        assert!(keypair_result.is_ok());
        
        let keypair = keypair_result.unwrap();
        let message = b"Test message";
        
        let signature_result = keypair.sign(message);
        assert!(signature_result.is_ok());
        
        let signature = signature_result.unwrap();
        let verify_result = keypair.verify(message, &signature);
        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());
    }
}