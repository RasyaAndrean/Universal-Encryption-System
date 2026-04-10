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

        file_encryptor::format::EncryptedFile::encrypt_and_sign(
            input_file.path(), encrypted_file.path(), password, &keypair, false,
        ).unwrap();

        let metadata = file_encryptor::format::EncryptedFile::decrypt_and_verify(
            encrypted_file.path(), decrypted_file.path(), password, &public_key, false,
        ).unwrap();

        let decrypted_content = std::fs::read(decrypted_file.path()).unwrap();
        assert_eq!(original_content, decrypted_content.as_slice());
        assert_eq!(metadata.version, file_encryptor::config::FORMAT_VERSION);
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
        let public_key = keypair.public_key_only();

        file_encryptor::format::EncryptedFile::encrypt_and_sign(
            input_file.path(), encrypted_file.path(), password, &keypair, true,
        ).unwrap();

        let result = file_encryptor::format::EncryptedFile::decrypt_and_verify(
            encrypted_file.path(), decrypted_file.path(), password, &public_key, true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_signature_verification() {
        let content = b"Content to sign";
        let input_file = NamedTempFile::new().unwrap();
        input_file.as_file().write_all(content).unwrap();

        let keypair = file_encryptor::signature::generate_keypair().unwrap();
        let public_key = keypair.public_key_only();

        let signature = file_encryptor::signature::sign_file(input_file.path(), &keypair).unwrap();
        assert!(file_encryptor::signature::verify_file(input_file.path(), &public_key, &signature).unwrap());

        let tampered_file = NamedTempFile::new().unwrap();
        tampered_file.as_file().write_all(b"Tampered").unwrap();
        assert!(!file_encryptor::signature::verify_file(tampered_file.path(), &public_key, &signature).unwrap());
    }

    #[test]
    fn test_password_strength_enforcement() {
        use file_encryptor::security::validate_password_strength;
        assert!(validate_password_strength("weak").is_err());
        assert!(validate_password_strength("Str0ngP@ssw0rd123!").is_ok());
    }

    #[test]
    fn test_hardware_fingerprint_consistency() {
        let fp1 = file_encryptor::hardware::get_device_fingerprint().unwrap();
        let fp2 = file_encryptor::hardware::get_device_fingerprint().unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_wrong_password_rejection() {
        let content = b"Secret content";
        let input_file = NamedTempFile::new().unwrap();
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();

        input_file.as_file().write_all(content).unwrap();

        let keypair = file_encryptor::signature::generate_keypair().unwrap();
        let public_key = keypair.public_key_only();

        file_encryptor::format::EncryptedFile::encrypt_and_sign(
            input_file.path(), encrypted_file.path(), "CorrectP@ss123!", &keypair, false,
        ).unwrap();

        let result = file_encryptor::format::EncryptedFile::decrypt_and_verify(
            encrypted_file.path(), decrypted_file.path(), "WrongP@ss1234!", &public_key, false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_file_integrity_protection() {
        let content = b"Original content";
        let input_file = NamedTempFile::new().unwrap();
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();
        let tampered_file = NamedTempFile::new().unwrap();

        input_file.as_file().write_all(content).unwrap();

        let keypair = file_encryptor::signature::generate_keypair().unwrap();
        let public_key = keypair.public_key_only();

        file_encryptor::format::EncryptedFile::encrypt_and_sign(
            input_file.path(), encrypted_file.path(), "IntegrityP@ss123!", &keypair, false,
        ).unwrap();

        let mut encrypted_data = std::fs::read(encrypted_file.path()).unwrap();
        if encrypted_data.len() > 50 {
            encrypted_data[50] ^= 0xFF;
            std::fs::write(tampered_file.path(), encrypted_data).unwrap();
        }

        let result = file_encryptor::format::EncryptedFile::decrypt_and_verify(
            tampered_file.path(), decrypted_file.path(), "IntegrityP@ss123!", &public_key, false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_compression_round_trip() {
        let content = "Repetitive data for compression test. ".repeat(100);
        let input_file = NamedTempFile::new().unwrap();
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();

        input_file.as_file().write_all(content.as_bytes()).unwrap();

        file_encryptor::crypto::encrypt_file(
            input_file.path(), encrypted_file.path(), "CompressP@ss123!", None,
        ).unwrap();

        let encrypted_size = std::fs::metadata(encrypted_file.path()).unwrap().len();
        assert!(encrypted_size < content.len() as u64);

        file_encryptor::crypto::decrypt_file(
            encrypted_file.path(), decrypted_file.path(), "CompressP@ss123!", None,
        ).unwrap();

        assert_eq!(std::fs::read(decrypted_file.path()).unwrap(), content.as_bytes());
    }

    #[test]
    fn test_encrypted_private_key() {
        let keypair = file_encryptor::signature::generate_keypair().unwrap();
        let temp_file = NamedTempFile::new().unwrap();
        let passphrase = "KeySecret123!";

        file_encryptor::signature::save_keypair_encrypted(&keypair, temp_file.path(), Some(passphrase)).unwrap();

        // Without passphrase should fail
        assert!(file_encryptor::signature::load_keypair_encrypted(temp_file.path(), None).is_err());

        // With correct passphrase
        let loaded = file_encryptor::signature::load_keypair_encrypted(temp_file.path(), Some(passphrase)).unwrap();
        assert_eq!(keypair.public_key, loaded.public_key);
    }

    #[test]
    fn test_re_encrypt() {
        let content = b"Re-encrypt me";
        let input_file = NamedTempFile::new().unwrap();
        let encrypted_file = NamedTempFile::new().unwrap();
        let temp_decrypted = NamedTempFile::new().unwrap();
        let re_encrypted = NamedTempFile::new().unwrap();
        let final_decrypted = NamedTempFile::new().unwrap();

        input_file.as_file().write_all(content).unwrap();

        let old_pass = "OldP@ssword123!";
        let new_pass = "NewP@ssword456!";

        file_encryptor::crypto::encrypt_file(
            input_file.path(), encrypted_file.path(), old_pass, None,
        ).unwrap();

        // Re-encrypt: decrypt with old, encrypt with new
        file_encryptor::crypto::decrypt_file(
            encrypted_file.path(), temp_decrypted.path(), old_pass, None,
        ).unwrap();
        file_encryptor::crypto::encrypt_file(
            temp_decrypted.path(), re_encrypted.path(), new_pass, None,
        ).unwrap();

        // Old password should fail
        assert!(file_encryptor::crypto::decrypt_file(
            re_encrypted.path(), final_decrypted.path(), old_pass, None,
        ).is_err());

        // New password should work
        file_encryptor::crypto::decrypt_file(
            re_encrypted.path(), final_decrypted.path(), new_pass, None,
        ).unwrap();
        assert_eq!(std::fs::read(final_decrypted.path()).unwrap(), content);
    }

    #[test]
    fn test_config_default() {
        let config = file_encryptor::config::Config::default();
        assert_eq!(config.argon2.m_cost, 19456);
        assert!(config.encryption.compress);
        assert!(config.audit.enabled);
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
        assert!(file_encryptor::signature::generate_keypair().is_ok());
    }

    #[test]
    fn test_hardware_modules() {
        let fp = file_encryptor::hardware::get_device_fingerprint();
        assert!(fp.is_ok());
        assert!(!fp.unwrap().is_empty());
    }

    #[test]
    fn test_format_modules() {
        use file_encryptor::format::*;

        let metadata = FileMetadata {
            original_filename: "test.txt".to_string(),
            file_size: 100,
            creation_time: 1234567890,
            modification_time: 1234567890,
            device_fingerprint: "test".to_string(),
            version: 2,
        };

        let header = EncryptedFileHeader::new(metadata, [0u8; 32], false);
        assert!(header.validate_magic());
        assert!(header.validate_version().is_ok());
    }
}
