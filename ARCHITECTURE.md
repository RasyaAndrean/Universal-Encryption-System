# System Architecture

## Overview
The File Encryptor system is built with a modular architecture focusing on security, performance, and usability. The system implements multiple layers of protection using industry-standard cryptographic algorithms.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI Application Layer                    │
│  (Command parsing, user interaction, argument validation)   │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                   Core Security Modules                     │
├─────────────────────────────────────────────────────────────┤
│  • Crypto Module     │  • Signature Module  │  • Format     │
│  (Encryption/Decryption)│(Digital Signatures)│(File Format) │
├─────────────────────────────────────────────────────────────┤
│  • Hardware Module   │  • Security Module   │               │
│  (Device Binding)    │  (Validation/Ratelimit)              │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Cryptographic Libraries                  │
│  Argon2 │ AES-GCM │ Ed25519 │ SHA-256 │ SysInfo │ Zeroize   │
└─────────────────────────────────────────────────────────────┘
```

## Module Breakdown

### 1. Crypto Module (`src/crypto/`)
**Responsibilities:**
- Key derivation using Argon2id
- AES-256-GCM encryption/decryption
- Secure password handling
- File I/O operations

**Components:**
- `key_derivation.rs`: Password-based key generation
- `encryption.rs`: Core encryption/decryption logic
- `mod.rs`: Module interface and error handling

**Security Features:**
- Memory-safe key handling with automatic zeroization
- Salted key derivation to prevent rainbow table attacks
- Authenticated encryption with GCM mode

### 2. Signature Module (`src/signature/`)
**Responsibilities:**
- Ed25519 key pair generation
- Digital signing of files
- Signature verification
- Key storage and retrieval

**Key Features:**
- Fast elliptic curve cryptography
- Base64-encoded key storage
- JSON serialization for keys
- Separation of public/private key operations

### 3. Hardware Module (`src/hardware/`)
**Responsibilities:**
- Device fingerprint generation
- System information collection
- Hardware-based encryption binding
- MAC address and disk identification

**Components:**
- `DeviceFingerprint` structure with hardware identifiers
- System metadata collection
- Consistent fingerprint generation

### 4. Format Module (`src/format/`)
**Responsibilities:**
- Encrypted file structure definition
- Metadata embedding
- Integrity verification
- File format versioning

**Structure:**
```
{
  "header": {
    "magic": "SECURE\0\0",
    "version": 1,
    "metadata": {
      "original_filename": "document.txt",
      "file_size": 1024,
      "device_fingerprint": "AMD:DESKTOP-123:Windows 10:1234567890:uuid"
    },
    "data_hash": "SHA-256-hash-bytes"
  },
  "encrypted_data": "base64-encoded-data",
  "signature": "base64-encoded-signature"
}
```

### 5. Security Module (`src/security.rs`)
**Responsibilities:**
- Password strength validation
- Rate limiting implementation
- Secure string handling
- Memory security utilities

**Features:**
- Configurable password requirements
- Time-based rate limiting
- Automatic memory zeroization
- Secure temporary file handling

## Data Flow

### Encryption Process:
1. **Input Validation** → CLI validates arguments
2. **Key Derivation** → Argon2id derives key from password + device ID
3. **File Processing** → Original file is read and hashed
4. **Metadata Creation** → File metadata and device fingerprint collected
5. **Encryption** → AES-256-GCM encrypts data with authentication
6. **Signing** → Ed25519 signs the encrypted data
7. **Storage** → JSON structure with encrypted data and signature saved

### Decryption Process:
1. **Input Validation** → File format and signature verification
2. **Key Derivation** → Same process as encryption using provided password
3. **Decryption** → AES-GCM decryption with authentication verification
4. **Integrity Check** → SHA-256 hash comparison
5. **Device Validation** → Hardware fingerprint verification (if enabled)
6. **Output** → Original file restored

## Security Design Principles

### 1. Defense in Depth
Multiple layers of security:
- Strong password requirements
- Key derivation with salt
- Authenticated encryption
- Digital signatures
- Hardware binding
- Anti-tamper verification

### 2. Memory Safety
- Rust's memory safety guarantees
- Zeroization of sensitive data
- No manual memory management
- Secure temporary file handling

### 3. Cryptographic Best Practices
- Industry-standard algorithms
- Proper parameter selection
- Secure random number generation
- Constant-time operations where critical

### 4. Error Handling
- Comprehensive error types
- No information leakage through errors
- Graceful failure handling
- Clear error messages

## Performance Considerations

### Bottlenecks:
- **Key Derivation**: Argon2id is intentionally slow for security
- **Encryption**: AES-GCM performance depends on file size
- **Signing**: Ed25519 is fast but scales with data size

### Optimizations:
- Parallel processing where possible
- Efficient memory usage
- Streaming for large files (future enhancement)
- Caching of device fingerprints

## Future Enhancements

### Planned Features:
- Streaming encryption for large files
- Multi-threaded processing
- Plugin architecture for additional algorithms
- GUI interface
- Cloud storage integration
- Key management service

### Scalability Improvements:
- Database-backed key storage
- Distributed processing capabilities
- Performance monitoring
- Resource usage optimization

## Dependencies Overview

### Core Cryptographic:
- `argon2` - Password hashing
- `aes-gcm` - Authenticated encryption
- `ed25519-dalek` - Digital signatures
- `sha2` - Hash functions
- `zeroize` - Secure memory clearing

### System Integration:
- `sysinfo` - Hardware information
- `uuid` - Unique identifiers
- `clap` - Command-line parsing
- `serde` - Serialization
- `tokio` - Async runtime

This architecture provides a solid foundation for a secure, maintainable, and extensible file encryption system.