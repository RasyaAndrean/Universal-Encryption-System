# File Encryptor - Universal Encryption System

A comprehensive file encryption system built in Rust with advanced security features including password-based encryption, digital signatures, anti-tamper verification, and hardware binding.

## 🛠 Technology Stack

### 🦀 Core Technologies
- **Language**: [Rust](https://www.rust-lang.org/) - Memory-safe systems programming
- **Build System**: [Cargo](https://doc.rust-lang.org/cargo/) - Rust package manager and build tool
- **Version**: Rust 1.70+

### 🔐 Cryptographic Libraries
- **[Argon2](https://github.com/RustCrypto/password-hashes)** - Password hashing and key derivation
- **[AES-GCM](https://github.com/RustCrypto/AEADs)** - Authenticated encryption
- **[Ed25519](https://github.com/dalek-cryptography/ed25519-dalek)** - Digital signatures
- **[SHA-2](https://github.com/RustCrypto/hashes)** - Cryptographic hashing
- **[Zeroize](https://github.com/RustCrypto/utils)** - Secure memory clearing

### 🖥 System Integration
- **[SysInfo](https://github.com/GuillaumeGomez/sysinfo)** - Hardware and system information
- **[UUID](https://github.com/uuid-rs/uuid)** - Universally unique identifiers
- **[Clap](https://github.com/clap-rs/clap)** - Command-line argument parsing
- **[Serde](https://github.com/serde-rs/serde)** - Serialization framework
- **[Tokio](https://github.com/tokio-rs/tokio)** - Async runtime

### 🧪 Development Tools
- **[Thiserror](https://github.com/dtolnay/thiserror)** - Error handling macros
- **[Anyhow](https://github.com/dtolnay/anyhow)** - Flexible error handling
- **[Tempfile](https://github.com/Stebalien/tempfile)** - Temporary file management

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