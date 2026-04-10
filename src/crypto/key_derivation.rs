use argon2::{Argon2, Params, Algorithm, Version, password_hash::{SaltString, PasswordHasher}};
use rand::rngs::OsRng;
use zeroize::Zeroize;
use std::convert::TryInto;

#[derive(Debug, thiserror::Error)]
pub enum KeyDerivationError {
    #[error("Argon2 error: {0}")]
    Argon2(String),
    #[error("Invalid parameters: {0}")]
    InvalidParams(String),
    #[error("Key length mismatch")]
    KeyLengthMismatch,
}

pub struct DerivedKey {
    pub key: [u8; 32],
    pub salt: [u8; 16],
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

// Recommended Argon2 parameters for file encryption
const ARGON2_M_COST: u32 = 19456; // 19 MiB
const ARGON2_T_COST: u32 = 2;     // 2 iterations
const ARGON2_P_COST: u32 = 1;     // 1 thread

/// Combine password and optional device_id with length-prefixed format
/// to prevent collisions (e.g. "a:b" + "c" vs "a" + "b:c").
fn build_input(password: &str, device_id: Option<&str>) -> String {
    if let Some(device_id) = device_id {
        format!("{}:{}:{}", password.len(), password, device_id)
    } else {
        password.to_string()
    }
}

/// Create configured Argon2 instance with standard parameters.
fn build_argon2() -> Result<Argon2<'static>, KeyDerivationError> {
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(32),
    ).map_err(|e| KeyDerivationError::InvalidParams(e.to_string()))?;

    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hash password with given salt and return 32-byte key.
fn hash_password(argon2: &Argon2, input: &str, salt: &SaltString) -> Result<[u8; 32], KeyDerivationError> {
    let hash = argon2
        .hash_password(input.as_bytes(), salt)
        .map_err(|e| KeyDerivationError::Argon2(e.to_string()))?;

    let key_bytes = hash.hash.ok_or_else(||
        KeyDerivationError::Argon2("Hash generation failed".to_string())
    )?;

    key_bytes.as_bytes().try_into()
        .map_err(|_| KeyDerivationError::KeyLengthMismatch)
}

pub fn derive_key_from_password(
    password: &str,
    device_id: Option<&str>,
) -> Result<DerivedKey, KeyDerivationError> {
    let combined_input = build_input(password, device_id);

    let salt = SaltString::generate(&mut OsRng);
    let salt_bytes: [u8; 16] = salt.as_bytes()[..16].try_into()
        .map_err(|_| KeyDerivationError::InvalidParams("Salt conversion failed".to_string()))?;

    let argon2 = build_argon2()?;
    let key = hash_password(&argon2, &combined_input, &salt)?;

    Ok(DerivedKey { key, salt: salt_bytes })
}

pub fn derive_key_with_salt(
    password: &str,
    salt: &[u8; 16],
    device_id: Option<&str>,
) -> Result<[u8; 32], KeyDerivationError> {
    let combined_input = build_input(password, device_id);

    let salt_string = SaltString::b64_encode(salt)
        .map_err(|e| KeyDerivationError::InvalidParams(e.to_string()))?;

    let argon2 = build_argon2()?;
    hash_password(&argon2, &combined_input, &salt_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let password = "test_password_123";
        let device_id = "test_device_id";

        let result = derive_key_from_password(password, Some(device_id));
        assert!(result.is_ok());

        let derived_key = result.unwrap();
        assert_eq!(derived_key.key.len(), 32);
        assert_eq!(derived_key.salt.len(), 16);
    }

    #[test]
    fn test_same_input_different_salt() {
        let password = "consistent_password";
        let device_id = "consistent_device";

        let key1 = derive_key_from_password(password, Some(device_id)).unwrap();
        let key2 = derive_key_from_password(password, Some(device_id)).unwrap();

        // Keys should be different due to random salt
        assert_ne!(key1.key, key2.key);
    }

    #[test]
    fn test_same_salt_same_key() {
        let password = "test_password";
        let salt = [1u8; 16];

        let key1 = derive_key_with_salt(password, &salt, None).unwrap();
        let key2 = derive_key_with_salt(password, &salt, None).unwrap();

        // Same password + same salt = same key
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_device_id_changes_key() {
        let password = "test_password";
        let salt = [1u8; 16];

        let key1 = derive_key_with_salt(password, &salt, Some("device1")).unwrap();
        let key2 = derive_key_with_salt(password, &salt, Some("device2")).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_no_collision() {
        let salt = [1u8; 16];

        // "a:b" + device "c" should differ from "a" + device "b:c"
        let key1 = derive_key_with_salt("a:b", &salt, Some("c")).unwrap();
        let key2 = derive_key_with_salt("a", &salt, Some("b:c")).unwrap();

        assert_ne!(key1, key2);
    }
}
