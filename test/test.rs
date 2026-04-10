#[cfg(test)]
mod integration_tests {
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_full_encryption_decryption_flow() {
        let password = "Str0ngP@ssw0rd123!";
        let original_content = b"Hello, World! This is a secret message.";

        let input_file = NamedTempFile::new().unwrap();
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();

        input_file.as_file().write_all(original_content).unwrap();

        let keypair = file_encryptor::signature::generate_keypair().unwrap();
        let public_key = keypair.public_key_only();

        let result = file_encryptor::format::EncryptedFile::encrypt_and_sign(
            input_file.path(),
            encrypted_file.path(),
            password,
            &keypair,
            false,
        );
        assert!(result.is_ok());

        let metadata = file_encryptor::format::EncryptedFile::decrypt_and_verify(
            encrypted_file.path(),
            decrypted_file.path(),
            password,
            &public_key,
            false,
        );
        assert!(metadata.is_ok());

        let decrypted_content = std::fs::read(decrypted_file.path()).unwrap();
        assert_eq!(original_content, decrypted_content.as_slice());
    }

    #[test]
    fn test_device_binding() {
        let password = "DeviceBoundP@ss123!";
        let content = b"Device-specific content";

        let input_file = NamedTempFile::new().unwrap();
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();

        input_file.as_file().write_all(content).unwrap();

        let keypair = file_encryptor::signature::generate_keypair().unwrap();

        let result = file_encryptor::format::EncryptedFile::encrypt_and_sign(
            input_file.path(),
            encrypted_file.path(),
            password,
            &keypair,
            true,
        );
        assert!(result.is_ok());

        let public_key = keypair.public_key_only();
        let metadata = file_encryptor::format::EncryptedFile::decrypt_and_verify(
            encrypted_file.path(),
            decrypted_file.path(),
            password,
            &public_key,
            true,
        );
        assert!(metadata.is_ok());
    }

    #[test]
    fn test_signature_verification() {
        let content = b"Content to sign";
        let input_file = NamedTempFile::new().unwrap();
        input_file.as_file().write_all(content).unwrap();

        let keypair = file_encryptor::signature::generate_keypair().unwrap();
        let public_key = keypair.public_key_only();

        let signature = file_encryptor::signature::sign_file(input_file.path(), &keypair).unwrap();

        let is_valid = file_encryptor::signature::verify_file(input_file.path(), &public_key, &signature).unwrap();
        assert!(is_valid);

        // Test with tampered content
        let tampered_file = NamedTempFile::new().unwrap();
        tampered_file.as_file().write_all(b"Tampered content").unwrap();

        let is_valid_tampered = file_encryptor::signature::verify_file(tampered_file.path(), &public_key, &signature).unwrap();
        assert!(!is_valid_tampered);
    }

    #[test]
    fn test_password_strength_enforcement() {
        use file_encryptor::security::validate_password_strength;

        assert!(validate_password_strength("weak").is_err());
        assert!(validate_password_strength("nouppercase123!").is_err());
        assert!(validate_password_strength("NOLOWERCASE123!").is_err());

        assert!(validate_password_strength("Str0ngP@ssw0rd123!").is_ok());
        assert!(validate_password_strength("MySecureP@ss2023!").is_ok());
    }

    #[test]
    fn test_hardware_fingerprint_consistency() {
        let fingerprint1 = file_encryptor::hardware::get_device_fingerprint().unwrap();
        let fingerprint2 = file_encryptor::hardware::get_device_fingerprint().unwrap();

        // Same device should produce same fingerprint (now deterministic)
        assert_eq!(fingerprint1, fingerprint2);
    }

    #[test]
    fn test_wrong_password_rejection() {
        let correct_password = "CorrectP@ss123!";
        let wrong_password = "WrongP@ss1234!";
        let content = b"Secret content";

        let input_file = NamedTempFile::new().unwrap();
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();

        input_file.as_file().write_all(content).unwrap();

        let keypair = file_encryptor::signature::generate_keypair().unwrap();

        file_encryptor::format::EncryptedFile::encrypt_and_sign(
            input_file.path(),
            encrypted_file.path(),
            correct_password,
            &keypair,
            false,
        ).unwrap();

        let public_key = keypair.public_key_only();
        let result = file_encryptor::format::EncryptedFile::decrypt_and_verify(
            encrypted_file.path(),
            decrypted_file.path(),
            wrong_password,
            &public_key,
            false,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_file_integrity_protection() {
        let password = "IntegrityP@ss123!";
        let content = b"Original content";

        let input_file = NamedTempFile::new().unwrap();
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();
        let tampered_file = NamedTempFile::new().unwrap();

        input_file.as_file().write_all(content).unwrap();

        let keypair = file_encryptor::signature::generate_keypair().unwrap();
        let public_key = keypair.public_key_only();

        file_encryptor::format::EncryptedFile::encrypt_and_sign(
            input_file.path(),
            encrypted_file.path(),
            password,
            &keypair,
            false,
        ).unwrap();

        // Tamper with encrypted file
        let mut encrypted_data = std::fs::read(encrypted_file.path()).unwrap();
        if encrypted_data.len() > 50 {
            encrypted_data[50] ^= 0xFF;
            std::fs::write(tampered_file.path(), encrypted_data).unwrap();
        }

        let result = file_encryptor::format::EncryptedFile::decrypt_and_verify(
            tampered_file.path(),
            decrypted_file.path(),
            password,
            &public_key,
            false,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_basic_encrypt_decrypt_with_compression() {
        let password = "CompressP@ss123!";
        let content = "Repetitive data for compression test. ".repeat(100);

        let input_file = NamedTempFile::new().unwrap();
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();

        input_file.as_file().write_all(content.as_bytes()).unwrap();

        file_encryptor::crypto::encrypt_file(
            input_file.path(),
            encrypted_file.path(),
            password,
            None,
        ).unwrap();

        // Encrypted size should be smaller than original due to compression
        let original_size = content.len() as u64;
        let encrypted_size = std::fs::metadata(encrypted_file.path()).unwrap().len();
        assert!(encrypted_size < original_size);

        file_encryptor::crypto::decrypt_file(
            encrypted_file.path(),
            decrypted_file.path(),
            password,
            None,
        ).unwrap();

        let decrypted_content = std::fs::read(decrypted_file.path()).unwrap();
        assert_eq!(content.as_bytes(), decrypted_content.as_slice());
    }

    #[test]
    fn test_config_default() {
        let config = file_encryptor::config::Config::default();
        assert_eq!(config.argon2.m_cost, 19456);
        assert_eq!(config.argon2.t_cost, 2);
        assert!(config.encryption.compress);
        assert_eq!(config.encryption.max_file_size, 2 * 1024 * 1024 * 1024);
    }
}

#[cfg(test)]
mod module_tests {
    #[test]
    fn test_crypto_modules() {
        use file_encryptor::crypto::*;

        let _ = KEY_LENGTH;
        let _ = NONCE_LENGTH;
        let _ = SALT_LENGTH;
        let _ = MAX_FILE_SIZE;
    }

    #[test]
    fn test_signature_modules() {
        use file_encryptor::signature::*;

        let keypair = generate_keypair();
        assert!(keypair.is_ok());
    }

    #[test]
    fn test_hardware_modules() {
        use file_encryptor::hardware::*;

        let fingerprint = get_device_fingerprint();
        assert!(fingerprint.is_ok());
        assert!(!fingerprint.unwrap().is_empty());
    }

    #[test]
    fn test_format_modules() {
        use file_encryptor::format::*;

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
