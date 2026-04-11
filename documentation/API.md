# API Documentation

Library API for integrating File Encryptor into Rust projects.

## Add Dependency

```toml
[dependencies]
file-encryptor = { path = "../Universal-Encryption-System" }
```

## Core Modules

### `crypto` - Encryption & Decryption

```rust
use file_encryptor::crypto::{
    encrypt_file, decrypt_file,
    encrypt_file_with_config, decrypt_file_with_config,
    encrypt_data, decrypt_data,
    compress_data, decompress_data,
    calculate_hash,
};
```

#### `encrypt_file(input, output, password, device_id) -> Result<(), CryptoError>`

Encrypt a file with automatic gzip compression, file size checking, and streaming for large files.

```rust
// Basic
encrypt_file("input.txt", "output.enc", "MyStr0ngP@ss123!", None)?;

// With device binding
let device_id = file_encryptor::get_device_fingerprint()?;
encrypt_file("input.txt", "output.enc", "MyStr0ngP@ss123!", Some(&device_id))?;
```

#### `encrypt_file_with_config(input, output, password, device_id, config)`

Same as above but with explicit `Config` for Argon2 params, compression, streaming threshold.

#### `decrypt_file(input, output, password, device_id) -> Result<(), CryptoError>`

Decrypt a file. Handles compressed (v2) and uncompressed (v1) formats automatically.

#### `encrypt_data(plaintext, password, device_id) -> Result<Vec<u8>, EncryptionError>`

Low-level AES-256-GCM encryption of raw bytes.

#### `decrypt_data(ciphertext, password, device_id) -> Result<Vec<u8>, EncryptionError>`

Low-level AES-256-GCM decryption.

#### `calculate_hash(data) -> [u8; 32]`

SHA-256 hash.

---

### `signature` - Digital Signatures

```rust
use file_encryptor::signature::{
    generate_keypair, sign_file, verify_file,
    save_keypair, load_keypair,
    save_keypair_encrypted, load_keypair_encrypted,
    KeyPair, PublicKeyOnly,
};
```

#### `generate_keypair() -> Result<KeyPair, SignatureError>`

Generate Ed25519 key pair.

#### `KeyPair::sign(message) -> Result<Vec<u8>, SignatureError>`
#### `KeyPair::verify(message, signature) -> Result<bool, SignatureError>`
#### `PublicKeyOnly::verify(message, signature) -> Result<bool, SignatureError>`

#### Encrypted Key Storage

```rust
// Save with passphrase encryption
save_keypair_encrypted(&keypair, "key.json", Some("passphrase"))?;

// Save plaintext (shorthand)
save_keypair(&keypair, "key.json")?;

// Load encrypted
let kp = load_keypair_encrypted("key.json", Some("passphrase"))?;

// Load plaintext (shorthand, also handles old format)
let kp = load_keypair("key.json")?;
```

#### `sign_file(path, keypair) -> Result<Vec<u8>, SignatureError>`
#### `verify_file(path, public_key, signature) -> Result<bool, SignatureError>`

---

### `format` - Encrypted File Format

```rust
use file_encryptor::format::{EncryptedFile, EncryptedFileHeader, FileMetadata};
```

#### `EncryptedFile::encrypt_and_sign(input, output, password, keypair, bind_device)`

Full pipeline: read, compress, hash, create header, encrypt, sign, write.

#### `EncryptedFile::decrypt_and_verify(input, output, password, public_key, validate_device) -> Result<FileMetadata, FileFormatError>`

Full pipeline: read, verify signature, decrypt, decompress, verify hash, validate device.

Returns `FileMetadata` with `original_filename`, `file_size`, `creation_time`, `modification_time`, `device_fingerprint`, `version`.

---

### `hardware` - Device Fingerprinting

```rust
use file_encryptor::hardware::{get_device_fingerprint, validate_device_fingerprint};
```

Fingerprint is a deterministic SHA-256 hash of: CPU vendor ID, hostname, total memory, CPU count, sorted MAC addresses. Consistent across calls on the same machine.

---

### `security` - Password & Rate Limiting

```rust
use file_encryptor::security::{validate_password_strength, RateLimiter, SecureString};
```

#### `validate_password_strength(password) -> Result<(), SecurityError>`

Validates: 12+ chars, 2 upper, 2 lower, 2 digits, 1 special, no common patterns (30+ blocklist).

#### `RateLimiter`

```rust
let mut limiter = RateLimiter::new(3, Duration::from_secs(60));
limiter.check_rate_limit()?; // Err(RateLimitExceeded) if exceeded
```

---

### `config` - Configuration

```rust
use file_encryptor::config::{Config, FORMAT_VERSION, SUPPORTED_FORMAT_VERSIONS};
```

`Config::load_or_default()` loads from `encryptor.toml` or defaults.

Fields: `argon2.{m_cost, t_cost, p_cost}`, `encryption.{max_file_size, compress, compression_level, stream_chunk_size, stream_threshold}`, `audit.{enabled, log_file}`.

---

### `audit` - Audit Logging

```rust
use file_encryptor::audit::{AuditLogger, AuditAction};

let logger = AuditLogger::new(&config.audit);
logger.log(AuditAction::Encrypt, "file.txt", true, "");
```

Actions: `Encrypt`, `Decrypt`, `EncryptDir`, `DecryptDir`, `Sign`, `Verify`, `GenerateKeys`, `ReEncrypt`.

---

## Error Types

| Error | Module | Description |
|-------|--------|-------------|
| `CryptoError` | `crypto` | File too large, compression, encryption |
| `EncryptionError` | `crypto::encryption` | AES-GCM failures, invalid format |
| `KeyDerivationError` | `crypto::key_derivation` | Argon2 errors |
| `SignatureError` | `signature` | Key/sign/verify failures, encrypted key errors |
| `FileFormatError` | `format` | Invalid format, integrity, device binding, unsupported version |
| `HardwareError` | `hardware` | System info unavailable |
| `SecurityError` | `security` | Weak password, rate limit |

## Example: Full Workflow

```rust
use file_encryptor::{generate_keypair, format::EncryptedFile};

fn main() -> anyhow::Result<()> {
    let keypair = generate_keypair()?;
    let public_key = keypair.public_key_only();

    EncryptedFile::encrypt_and_sign(
        "document.pdf", "document.enc", "MyStr0ngP@ss123!", &keypair, false,
    )?;

    let metadata = EncryptedFile::decrypt_and_verify(
        "document.enc", "document_out.pdf", "MyStr0ngP@ss123!", &public_key, false,
    )?;

    println!("Decrypted: {} ({} bytes)", metadata.original_filename, metadata.file_size);
    Ok(())
}
```
