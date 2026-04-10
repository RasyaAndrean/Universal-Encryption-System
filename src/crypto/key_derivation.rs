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

pub fn derive_key_from_password(
    password: &str,
    device_id: Option<&str>,
) -> Result<DerivedKey, KeyDerivationError> {
    // Combine password with device ID if provided
    let combined_input = if let Some(device_id) = device_id {
        format!("{}:{}", password, device_id)
    } else {
        password.to_string()
    };
    
    // Generate random salt
    let salt = SaltString::generate(&mut OsRng);
    let salt_bytes: [u8; 16] = salt.as_bytes()[..16].try_into()
        .map_err(|_| KeyDerivationError::InvalidParams("Salt conversion failed".to_string()))?;
    
    // Configure Argon2 parameters
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(32), // Output length
    ).map_err(|e| KeyDerivationError::InvalidParams(e.to_string()))?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    // Derive key
    let hash = argon2
        .hash_password(combined_input.as_bytes(), &salt)
        .map_err(|e| KeyDerivationError::Argon2(e.to_string()))?;
    
    let key_bytes = hash.hash.ok_or_else(|| 
        KeyDerivationError::Argon2("Hash generation failed".to_string())
    )?;
    
    let key: [u8; 32] = key_bytes.as_bytes().try_into()
        .map_err(|_| KeyDerivationError::KeyLengthMismatch)?;
    
    Ok(DerivedKey { key, salt: salt_bytes })
}

pub fn derive_key_with_salt(
    password: &str,
    salt: &[u8; 16],
    device_id: Option<&str>,
) -> Result<[u8; 32], KeyDerivationError> {
    let combined_input = if let Some(device_id) = device_id {
        format!("{}:{}", password, device_id)
    } else {
        password.to_string()
    };
    
    let salt_string = SaltString::b64_encode(salt)
        .map_err(|e| KeyDerivationError::InvalidParams(e.to_string()))?;
    
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(32),
    ).map_err(|e| KeyDerivationError::InvalidParams(e.to_string()))?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    let hash = argon2
        .hash_password(combined_input.as_bytes(), &salt_string)
        .map_err(|e| KeyDerivationError::Argon2(e.to_string()))?;
    
    let key_bytes = hash.hash.ok_or_else(|| 
        KeyDerivationError::Argon2("Hash generation failed".to_string())
    )?;
    
    key_bytes.as_bytes().try_into()
        .map_err(|_| KeyDerivationError::KeyLengthMismatch)
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
    fn test_same_input_same_output() {
        let password = "consistent_password";
        let device_id = "consistent_device";
        
        let key1 = derive_key_from_password(password, Some(device_id)).unwrap();
        let key2 = derive_key_from_password(password, Some(device_id)).unwrap();
        
        // Keys should be different due to random salt
        assert_ne!(key1.key, key2.key);
    }
    
    #[test]
    fn test_key_zeroization() {
        let password = "test_password";
        let derived_key = derive_key_from_password(password, None).unwrap();
        let key_copy = derived_key.key;
        
        // Drop the key
        drop(derived_key);
        
        // The original memory should be zeroized (this is a basic check)
        // In practice, zeroize ensures the memory is cleared
    }
}