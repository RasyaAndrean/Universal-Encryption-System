#[cfg(test)]
mod integration_tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[tokio::test]
    async fn test_full_encryption_decryption_flow() {
        let password = "Str0ngP@ssw0rd123!";
        let original_content = b"Hello, World! This is a secret message.";
        
        // Create test files
        let input_file = NamedTempFile::new().unwrap();
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();
        
        input_file.as_file().write_all(original_content).unwrap();
        
        // Generate keypair
        let keypair = crate::signature::generate_keypair().unwrap();
        let public_key = keypair.public_key_only();
        
        // Encrypt with signing
        let result = crate::format::EncryptedFile::encrypt_and_sign(
            input_file.path(),
            encrypted_file.path(),
            password,
            &keypair,
            false, // No device binding for this test
        );
        assert!(result.is_ok());
        
        // Decrypt with verification
        let metadata = crate::format::EncryptedFile::decrypt_and_verify(
            encrypted_file.path(),
            decrypted_file.path(),
            password,
            &public_key,
            false, // No device validation for this test
        );
        assert!(metadata.is_ok());
        
        // Verify content
        let decrypted_content = std::fs::read(decrypted_file.path()).unwrap();
        assert_eq!(original_content, decrypted_content.as_slice());
    }
    
    #[tokio::test]
    async fn test_device_binding() {
        let password = "DeviceBoundP@ss123!";
        let content = b"Device-specific content";
        
        let input_file = NamedTempFile::new().unwrap();
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();
        
        input_file.as_file().write_all(content).unwrap();
        
        let keypair = crate::signature::generate_keypair().unwrap();
        
        // Encrypt with device binding
        let result = crate::format::EncryptedFile::encrypt_and_sign(
            input_file.path(),
            encrypted_file.path(),
            password,
            &keypair,
            true, // Enable device binding
        );
        assert!(result.is_ok());
        
        // Try to decrypt on same device (should work)
        let public_key = keypair.public_key_only();
        let metadata = crate::format::EncryptedFile::decrypt_and_verify(
            encrypted_file.path(),
            decrypted_file.path(),
            password,
            &public_key,
            true, // Validate device binding
        );
        assert!(metadata.is_ok());
    }
    
    #[tokio::test]
    async fn test_signature_verification() {
        let content = b"Content to sign";
        let input_file = NamedTempFile::new().unwrap();
        input_file.as_file().write_all(content).unwrap();
        
        // Generate keys
        let keypair = crate::signature::generate_keypair().unwrap();
        let public_key = keypair.public_key_only();
        
        // Sign file
        let signature = crate::signature::sign_file(input_file.path(), &keypair).unwrap();
        
        // Verify signature
        let is_valid = crate::signature::verify_file(input_file.path(), &public_key, &signature).unwrap();
        assert!(is_valid);
        
        // Test with tampered content
        let tampered_file = NamedTempFile::new().unwrap();
        tampered_file.as_file().write_all(b"Tampered content").unwrap();
        
        let is_valid_tampered = crate::signature::verify_file(tampered_file.path(), &public_key, &signature).unwrap();
        assert!(!is_valid_tampered);
    }
    
    #[test]
    fn test_password_strength_enforcement() {
        use crate::security::validate_password_strength;
        
        // Test weak passwords are rejected
        assert!(validate_password_strength("weak").is_err());
        assert!(validate_password_strength("nouppercase123!").is_err());
        assert!(validate_password_strength("NOLOWERCASE123!").is_err());
        
        // Test strong passwords are accepted
        assert!(validate_password_strength("Str0ngP@ssw0rd123!").is_ok());
        assert!(validate_password_strength("MySecureP@ss2023!").is_ok());
    }
    
    #[test]
    fn test_hardware_fingerprint_consistency() {
        let fingerprint1 = crate::hardware::get_device_fingerprint().unwrap();
        let fingerprint2 = crate::hardware::get_device_fingerprint().unwrap();
        
        // Same device should produce same fingerprint
        assert_eq!(fingerprint1, fingerprint2);
    }
    
    #[tokio::test]
    async fn test_wrong_password_rejection() {
        let correct_password = "CorrectP@ss123!";
        let wrong_password = "WrongP@ss123!";
        let content = b"Secret content";
        
        let input_file = NamedTempFile::new().unwrap();
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();
        
        input_file.as_file().write_all(content).unwrap();
        
        let keypair = crate::signature::generate_keypair().unwrap();
        
        // Encrypt
        crate::format::EncryptedFile::encrypt_and_sign(
            input_file.path(),
            encrypted_file.path(),
            correct_password,
            &keypair,
            false,
        ).unwrap();
        
        // Try to decrypt with wrong password
        let public_key = keypair.public_key_only();
        let result = crate::format::EncryptedFile::decrypt_and_verify(
            encrypted_file.path(),
            decrypted_file.path(),
            wrong_password,
            &public_key,
            false,
        );
        
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_file_integrity_protection() {
        let password = "IntegrityP@ss123!";
        let content = b"Original content";
        
        let input_file = NamedTempFile::new().unwrap();
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();
        let tampered_file = NamedTempFile::new().unwrap();
        
        input_file.as_file().write_all(content).unwrap();
        
        let keypair = crate::signature::generate_keypair().unwrap();
        let public_key = keypair.public_key_only();
        
        // Encrypt
        crate::format::EncryptedFile::encrypt_and_sign(
            input_file.path(),
            encrypted_file.path(),
            password,
            &keypair,
            false,
        ).unwrap();
        
        // Tamper with encrypted file
        let mut encrypted_data = std::fs::read(encrypted_file.path()).unwrap();
        if encrypted_data.len() > 50 {
            encrypted_data[50] ^= 0xFF; // Flip some bits
            std::fs::write(tampered_file.path(), encrypted_data).unwrap();
        }
        
        // Try to decrypt tampered file
        let result = crate::format::EncryptedFile::decrypt_and_verify(
            tampered_file.path(),
            decrypted_file.path(),
            password,
            &public_key,
            false,
        );
        
        assert!(result.is_err());
    }
}

// Module tests
#[cfg(test)]
mod module_tests {
    #[test]
    fn test_crypto_modules() {
        // Test that all crypto modules compile and can be imported
        use crate::crypto::*;
        use crate::crypto::key_derivation::*;
        use crate::crypto::encryption::*;
        
        // These should compile without errors
        let _ = KEY_LENGTH;
        let _ = NONCE_LENGTH;
        let _ = SALT_LENGTH;
    }
    
    #[test]
    fn test_signature_modules() {
        use crate::signature::*;
        
        // Test key generation works
        let keypair = generate_keypair();
        assert!(keypair.is_ok());
    }
    
    #[test]
    fn test_hardware_modules() {
        use crate::hardware::*;
        
        // Test device fingerprint generation
        let fingerprint = get_device_fingerprint();
        assert!(fingerprint.is_ok());
        assert!(!fingerprint.unwrap().is_empty());
    }
    
    #[test]
    fn test_format_modules() {
        use crate::format::*;
        
        // Test that format structures can be created
        let metadata = FileMetadata {
            original_filename: "test.txt".to_string(),
            file_size: 100,
            creation_time: 1234567890,
            modification_time: 1234567890,
            device_fingerprint: "test_fingerprint".to_string(),
            version: 1,
        };
        
        let hash = [0u8; 32];
        let header = EncryptedFileHeader::new(metadata, hash);
        assert!(header.validate_magic());
    }
}