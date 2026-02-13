# API Documentation

## Library Interface

The File Encryptor can be used as a Rust library in addition to its command-line interface. This documentation covers the public API available for integration into other Rust applications.

## Core Modules

### Crypto Module
```rust
use file_encryptor::crypto::*;
```

#### Functions

##### `encrypt_file`
Encrypts a file using password-based encryption.

```rust
pub fn encrypt_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    password: &str,
    device_id: Option<&str>,
) -> Result<(), CryptoError>
```

**Parameters:**
- `input_path`: Path to the file to encrypt
- `output_path`: Path where encrypted file will be saved
- `password`: Password for key derivation
- `device_id`: Optional device identifier for hardware binding

**Returns:** `Result<(), CryptoError>`

**Example:**
```rust
use file_encryptor::crypto::encrypt_file;

encrypt_file(
    "document.txt",
    "document.encrypted",
    "MySecurePassword123!",
    Some("device-specific-id")
)?;
```

##### `decrypt_file`
Decrypts a previously encrypted file.

```rust
pub fn decrypt_file<P: AsRef<Path>>(
    input_path: P,
    output_path: P,
    password: &str,
    device_id: Option<&str>,
) -> Result<(), CryptoError>
```

**Parameters:**
- `input_path`: Path to the encrypted file
- `output_path`: Path where decrypted file will be saved
- `password`: Password used for original encryption
- `device_id`: Device identifier (must match encryption device if used)

**Returns:** `Result<(), CryptoError>`

**Example:**
```rust
use file_encryptor::crypto::decrypt_file;

decrypt_file(
    "document.encrypted",
    "document_decrypted.txt",
    "MySecurePassword123!",
    Some("device-specific-id")
)?;
```

#### Error Types
```rust
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
}
```

### Signature Module
```rust
use file_encryptor::signature::*;
```

#### KeyPair Structure
```rust
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}
```

#### Functions

##### `generate_keypair`
Generates a new Ed25519 key pair.

```rust
pub fn generate_keypair() -> Result<KeyPair, SignatureError>
```

**Returns:** `Result<KeyPair, SignatureError>`

**Example:**
```rust
use file_encryptor::signature::generate_keypair;

let keypair = generate_keypair()?;
println!("Public key: {:?}", keypair.public_key);
```

##### `sign_file`
Creates a digital signature for a file.

```rust
pub fn sign_file<P: AsRef<Path>>(
    file_path: P,
    keypair: &KeyPair,
) -> Result<Vec<u8>, SignatureError>
```

**Parameters:**
- `file_path`: Path to the file to sign
- `keypair`: KeyPair containing private key for signing

**Returns:** `Result<Vec<u8>, SignatureError>` - The signature bytes

**Example:**
```rust
use file_encryptor::signature::{generate_keypair, sign_file};

let keypair = generate_keypair()?;
let signature = sign_file("document.txt", &keypair)?;
```

##### `verify_file`
Verifies a file's digital signature.

```rust
pub fn verify_file<P: AsRef<Path>>(
    file_path: P,
    public_key: &PublicKeyOnly,
    signature: &[u8],
) -> Result<bool, SignatureError>
```

**Parameters:**
- `file_path`: Path to the file to verify
- `public_key`: PublicKeyOnly structure for verification
- `signature`: Signature bytes to verify against

**Returns:** `Result<bool, SignatureError>` - true if valid, false if invalid

**Example:**
```rust
use file_encryptor::signature::{generate_keypair, sign_file, verify_file, PublicKeyOnly};

let keypair = generate_keypair()?;
let signature = sign_file("document.txt", &keypair)?;

let public_key_only = PublicKeyOnly {
    public_key: keypair.public_key.clone(),
};

let is_valid = verify_file("document.txt", &public_key_only, &signature)?;
assert!(is_valid);
```

##### `save_keypair` / `load_keypair`
Save and load key pairs to/from files.

```rust
pub fn save_keypair<P: AsRef<Path>>(keypair: &KeyPair, path: P) -> Result<(), SignatureError>
pub fn load_keypair<P: AsRef<Path>>(path: P) -> Result<KeyPair, SignatureError>
```

**Example:**
```rust
use file_encryptor::signature::{generate_keypair, save_keypair, load_keypair};

let keypair = generate_keypair()?;
save_keypair(&keypair, "my_keys.json")?;

let loaded_keypair = load_keypair("my_keys.json")?;
assert_eq!(keypair.public_key, loaded_keypair.public_key);
```

#### Error Types
```rust
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    #[error("Signing failed: {0}")]
    Signing(String),
    #[error("Verification failed: {0}")]
    Verification(String),
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
```

### Hardware Module
```rust
use file_encryptor::hardware::*;
```

#### Functions

##### `get_device_fingerprint`
Generates a unique device fingerprint.

```rust
pub fn get_device_fingerprint() -> Result<String, HardwareError>
```

**Returns:** `Result<String, HardwareError>` - Device fingerprint string

**Example:**
```rust
use file_encryptor::hardware::get_device_fingerprint;

let fingerprint = get_device_fingerprint()?;
println!("Device fingerprint: {}", fingerprint);
```

##### `validate_device_fingerprint`
Validates a stored fingerprint against current device.

```rust
pub fn validate_device_fingerprint(stored: &str) -> Result<bool, HardwareError>
```

**Parameters:**
- `stored`: Previously stored fingerprint to validate

**Returns:** `Result<bool, HardwareError>` - true if matches current device

**Example:**
```rust
use file_encryptor::hardware::{get_device_fingerprint, validate_device_fingerprint};

let fingerprint = get_device_fingerprint()?;
let is_valid = validate_device_fingerprint(&fingerprint)?;
assert!(is_valid);
```

#### Error Types
```rust
#[derive(Debug, thiserror::Error)]
pub enum HardwareError {
    #[error("Failed to get system information: {0}")]
    SystemInfo(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
```

### Format Module
```rust
use file_encryptor::format::*;
```

#### Main Structures

##### `FileMetadata`
```rust
pub struct FileMetadata {
    pub original_filename: String,
    pub file_size: u64,
    pub creation_time: u64,
    pub modification_time: u64,
    pub device_fingerprint: String,
    pub version: u32,
}
```

##### `EncryptedFile`
```rust
pub struct EncryptedFile {
    pub header: EncryptedFileHeader,
    pub encrypted_data: Vec<u8>,
    pub signature: Vec<u8>,
}
```

#### Functions

##### `EncryptedFile::encrypt_and_sign`
High-level encryption with digital signature.

```rust
impl EncryptedFile {
    pub fn encrypt_and_sign<P: AsRef<Path>>(
        input_path: P,
        output_path: P,
        password: &str,
        keypair: &KeyPair,
        bind_to_device: bool,
    ) -> Result<Self, FileFormatError>
}
```

**Example:**
```rust
use file_encryptor::format::EncryptedFile;
use file_encryptor::signature::generate_keypair;

let keypair = generate_keypair()?;
let encrypted_file = EncryptedFile::encrypt_and_sign(
    "input.txt",
    "output.encrypted",
    "password123",
    &keypair,
    true, // bind to device
)?;
```

##### `EncryptedFile::decrypt_and_verify`
High-level decryption with signature verification.

```rust
impl EncryptedFile {
    pub fn decrypt_and_verify<P: AsRef<Path>>(
        input_path: P,
        output_path: P,
        password: &str,
        public_key: &PublicKeyOnly,
        validate_device: bool,
    ) -> Result<FileMetadata, FileFormatError>
}
```

#### Error Types
```rust
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
```

## Security Module
```rust
use file_encryptor::security::*;
```

#### Functions

##### `validate_password_strength`
Validates password strength requirements.

```rust
pub fn validate_password_strength(password: &str) -> Result<(), SecurityError>
```

**Example:**
```rust
use file_encryptor::security::validate_password_strength;

validate_password_strength("MyStr0ngP@ssw0rd!")?; // Ok
validate_password_strength("weak")?; // Error
```

##### `RateLimiter`
Rate limiting implementation for preventing brute force attacks.

```rust
pub struct RateLimiter {
    attempts: Vec<Instant>,
    max_attempts: usize,
    time_window: Duration,
}

impl RateLimiter {
    pub fn new(max_attempts: usize, time_window: Duration) -> Self
    pub fn check_rate_limit(&mut self) -> Result<(), SecurityError>
    pub fn reset(&mut self)
}
```

**Example:**
```rust
use file_encryptor::security::RateLimiter;
use std::time::Duration;

let mut limiter = RateLimiter::new(3, Duration::from_secs(1));

limiter.check_rate_limit()?; // First attempt - Ok
limiter.check_rate_limit()?; // Second attempt - Ok
limiter.check_rate_limit()?; // Third attempt - Ok
limiter.check_rate_limit()?; // Fourth attempt - Error: RateLimitExceeded
```

## Error Handling

All public functions return `Result<T, Error>` types where errors are properly categorized and provide descriptive messages.

### Common Error Patterns:
```rust
match function_call() {
    Ok(result) => {
        // Handle successful result
        println!("Success: {:?}", result);
    }
    Err(error) => {
        // Handle specific error types
        match error {
            CryptoError::KeyDerivation(e) => {
                eprintln!("Key derivation failed: {}", e);
            }
            CryptoError::Encryption(e) => {
                eprintln!("Encryption failed: {}", e);
            }
            CryptoError::Io(e) => {
                eprintln!("IO error: {}", e);
            }
            _ => {
                eprintln!("Operation failed: {}", error);
            }
        }
    }
}
```

## Integration Examples

### Basic File Encryption Library Usage:
```rust
use file_encryptor::{encrypt_file, decrypt_file, generate_keypair};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate keys
    let keypair = generate_keypair()?;
    
    // Encrypt file
    encrypt_file(
        "sensitive_data.txt",
        "sensitive_data.encrypted",
        "MySecurePassword123!",
        Some("device-id")
    )?;
    
    // Decrypt file
    decrypt_file(
        "sensitive_data.encrypted",
        "sensitive_data_decrypted.txt",
        "MySecurePassword123!",
        Some("device-id")
    )?;
    
    Ok(())
}
```

### Advanced Usage with Signatures:
```rust
use file_encryptor::format::EncryptedFile;
use file_encryptor::signature::{generate_keypair, PublicKeyOnly};

fn secure_file_operation() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = generate_keypair()?;
    let public_key = PublicKeyOnly {
        public_key: keypair.public_key.clone(),
    };
    
    // Encrypt with signature
    let encrypted = EncryptedFile::encrypt_and_sign(
        "confidential.pdf",
        "confidential.encrypted",
        "StrongPassword2023!",
        &keypair,
        true // Device binding enabled
    )?;
    
    // Decrypt with verification
    let metadata = EncryptedFile::decrypt_and_verify(
        "confidential.encrypted",
        "confidential_restored.pdf",
        "StrongPassword2023!",
        &public_key,
        true // Device validation enabled
    )?;
    
    println!("File decrypted successfully!");
    println!("Original filename: {}", metadata.original_filename);
    println!("File size: {} bytes", metadata.file_size);
    
    Ok(())
}
```

## Thread Safety

The library is designed to be thread-safe:
- All cryptographic operations use thread-local random number generators
- File operations are atomic at the OS level
- Shared data structures use appropriate synchronization
- Memory-safe Rust guarantees prevent data races

## Performance Considerations

When using the library programmatically:

1. **Key Reuse**: Cache derived keys when processing multiple files with the same password
2. **Batch Processing**: Process multiple files in sequence to amortize startup costs
3. **Memory Management**: Large files are processed efficiently without excessive memory usage
4. **Error Recovery**: Implement proper cleanup in error handling paths

## Version Compatibility

The API follows semantic versioning:
- **Major versions**: Breaking changes to public API
- **Minor versions**: New features, backward compatible
- **Patch versions**: Bug fixes, backward compatible

Always check version compatibility when upgrading dependencies.