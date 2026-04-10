# File Encryptor - Universal Encryption System

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/RasyaAndrean/Universal-Encryption-System)
[![Security](https://img.shields.io/badge/security-AES--256--GCM-blue)](SECURITY.md)
[![Platform](https://img.shields.io/badge/platform-Cross--platform-lightgrey)](#)

A comprehensive file encryption system built in Rust with advanced security features including password-based encryption, digital signatures, anti-tamper verification, and hardware binding.

## 🛠 Technology Stack

### 🦀 Core Technologies
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Cargo](https://img.shields.io/badge/Cargo-package_manager-orange?logo=rust&logoColor=white)](https://doc.rust-lang.org/cargo/)

### 🔐 Cryptographic Libraries
[![Argon2](https://img.shields.io/badge/Argon2-password_hashing-blue)](https://github.com/RustCrypto/password-hashes)
[![AES-GCM](https://img.shields.io/badge/AES--GCM-authenticated_encryption-blue)](https://github.com/RustCrypto/AEADs)
[![Ed25519](https://img.shields.io/badge/Ed25519-digital_signatures-blue)](https://github.com/dalek-cryptography/ed25519-dalek)
[![SHA-2](https://img.shields.io/badge/SHA--2-hashing-blue)](https://github.com/RustCrypto/hashes)
[![Zeroize](https://img.shields.io/badge/Zeroize-memory_security-blue)](https://github.com/RustCrypto/utils)

### 🖥 System Integration
[![SysInfo](https://img.shields.io/badge/SysInfo-system_info-green)](https://github.com/GuillaumeGomez/sysinfo)
[![UUID](https://img.shields.io/badge/UUID-unique_identifiers-green)](https://github.com/uuid-rs/uuid)
[![Clap](https://img.shields.io/badge/Clap-CLI_parsing-green)](https://github.com/clap-rs/clap)
[![Serde](https://img.shields.io/badge/Serde-serialization-green)](https://github.com/serde-rs/serde)
[![Tokio](https://img.shields.io/badge/Tokio-async_runtime-green)](https://github.com/tokio-rs/tokio)

### 🧪 Development Tools
[![Thiserror](https://img.shields.io/badge/Thiserror-error_handling-purple)](https://github.com/dtolnay/thiserror)
[![Anyhow](https://img.shields.io/badge/Anyhow-flexible_errors-purple)](https://github.com/dtolnay/anyhow)
[![Tempfile](https://img.shields.io/badge/Tempfile-temp_files-purple)](https://github.com/Stebalien/tempfile)

## Features

### 🔐 Core Security Features
- **Password-Based Encryption**: Uses Argon2id for secure key derivation
- **AES-256-GCM**: Authenticated encryption with integrity protection
- **Digital Signatures**: Ed25519 for file authenticity verification
- **Hardware Binding**: Device-specific encryption binding
- **Anti-Tamper Protection**: Detects and prevents file modification
- **Secure Memory Handling**: Automatic zeroization of sensitive data

### 🛡 Advanced Security
- **Rate Limiting**: Prevents brute-force attacks
- **Password Strength Validation**: Enforces strong password requirements
- **Device Fingerprinting**: Unique hardware identification
- **File Integrity Checking**: SHA-256 hash verification
- **Signature Verification**: Cryptographic proof of authenticity

## Installation

### Prerequisites
- Rust 1.70 or later
- Cargo (Rust package manager)

### Building from Source

```bash
# Clone the repository
git clone 
cd file-encryptor

# Build the project
cargo build --release

# The executable will be available at:
# target/release/file-encryptor
```

## Usage

### Basic Commands

#### 1. Generate Key Pair
```bash
# Generate Ed25519 key pair
./file-encryptor generate-keys --output-dir ./keys --name mykey

# This creates:
# ./keys/mykey_private.json  (keep secret!)
# ./keys/mykey_public.json   (can be shared)
```

#### 2. Encrypt a File
```bash
# Basic encryption
./file-encryptor encrypt --input document.txt --output document.encrypted --password "MyStr0ngP@ssw0rd!"

# Encryption with device binding
./file-encryptor encrypt --input document.txt --output document.encrypted --password "MyStr0ngP@ssw0rd!" --bind-device

# Encryption with digital signature
./file-encryptor encrypt --input document.txt --output document.encrypted --password "MyStr0ngP@ssw0rd!" --private-key ./keys/mykey_private.json
```

#### 3. Decrypt a File
```bash
# Basic decryption
./file-encryptor decrypt --input document.encrypted --output document_decrypted.txt --password "MyStr0ngP@ssw0rd!"

# Decryption with device validation
./file-encryptor decrypt --input document.encrypted --output document_decrypted.txt --password "MyStr0ngP@ssw0rd!" --validate-device

# Decryption with signature verification
./file-encryptor decrypt --input document.encrypted --output document_decrypted.txt --password "MyStr0ngP@ssw0rd!" --public-key ./keys/mykey_public.json
```

#### 4. Sign a File
```bash
# Sign a file with private key
./file-encryptor sign --file document.txt --private-key ./keys/mykey_private.json

# Sign with custom output location
./file-encryptor sign --file document.txt --private-key ./keys/mykey_private.json --output signature.sig
```

#### 5. Verify a Signature
```bash
# Verify file signature
./file-encryptor verify --file document.txt --public-key ./keys/mykey_public.json --signature document.txt.sig
```

#### 6. Device Management
```bash
# Get current device fingerprint
./file-encryptor fingerprint

# Validate device fingerprint
./file-encryptor validate-fingerprint "CPU:AMD:Hostname:MYPC:OS:Windows10:1234567890:uuid-string"
```

## Security Features Explained

### Password Requirements
Strong passwords must include:
- Minimum 12 characters
- At least 2 uppercase letters
- At least 2 lowercase letters
- At least 2 digits
- At least 1 special character
- No common patterns or dictionary words

### Hardware Binding
When `--bind-device` is used:
- Creates a unique device fingerprint
- Binds encryption key to specific hardware
- File can only be decrypted on the same device
- Prevents unauthorized device access

### Digital Signatures
- Uses Ed25519 elliptic curve cryptography
- Provides cryptographic proof of file authenticity
- Detects any modification to signed files
- Public key can be shared for verification

### Anti-Tamper Protection
- SHA-256 hash of original content stored in header
- AES-GCM provides built-in integrity checking
- Signature verification ensures authenticity
- Any modification will cause decryption to fail

## File Format

The encrypted file format includes:
```
Header (JSON):
- Magic bytes and version
- Original file metadata
- SHA-256 hash of content
- Device fingerprint (if bound)

Encrypted Data:
- AES-256-GCM encrypted content
- Includes header + original file data

Signature:
- Ed25519 signature of encrypted data
```

## Library Usage

The system can also be used as a Rust library:

```rust
use file_encryptor::{encrypt_file, decrypt_file, generate_keypair};

// Generate keypair
let keypair = generate_keypair()?;

// Encrypt file
encrypt_file(
    "input.txt",
    "encrypted.dat",
    "MyPassword123!",
    Some("device_id") // Optional device binding
)?;

// Decrypt file
decrypt_file(
    "encrypted.dat",
    "output.txt",
    "MyPassword123!",
    Some("device_id") // Must match encryption device
)?;
```

## Security Best Practices

### Key Management
- Store private keys securely
- Never share private keys
- Backup key pairs in secure location
- Use different key pairs for different purposes

### Password Security
- Use unique passwords for each file
- Change passwords periodically
- Never reuse passwords across systems
- Store passwords in secure password manager

### Device Binding
- Enable device binding for highly sensitive files
- Understand that files become device-specific
- Keep device fingerprint records for recovery
- Test decryption on target devices before deployment

## Performance Considerations

### Encryption Speed
- Argon2 parameters are tuned for security vs performance
- Large files may take longer to process
- Consider file size when choosing security parameters

### Memory Usage
- Secure memory zeroization after use
- Temporary files are automatically cleaned up
- Key material is never written to disk

## Troubleshooting

### Common Issues

**Decryption fails with "Invalid password"**
- Verify password is exactly correct
- Check for typos or case sensitivity
- Ensure same device if device binding was used

**Device binding validation fails**
- File was encrypted on different device
- Hardware configuration has changed
- System time or boot time has changed significantly

**Signature verification fails**
- File has been modified after signing
- Wrong public key provided
- Signature file is corrupted

### Error Messages
- `Integrity check failed`: File has been tampered with
- `Device binding failed`: Wrong device or hardware change
- `Signature verification failed`: File authenticity cannot be confirmed
- `Rate limit exceeded`: Too many failed attempts, try again later

## Development

### Running Tests
```bash
# Run all tests
cargo test

# Run specific test suite
cargo test integration_tests

# Run with verbose output
cargo test -- --nocapture
```

### Building Documentation
```bash
# Generate documentation
cargo doc --open
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## Acknowledgments

- Uses the RustCrypto ecosystem for cryptographic primitives
- Built with security-first design principles
- Implements industry-standard algorithms and practices