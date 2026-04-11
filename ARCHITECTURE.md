# System Architecture

## Overview

File Encryptor is a synchronous Rust application providing file encryption, digital signatures, device binding, compression, and audit logging.

```
CLI (clap)
  |
  +-- Config (encryptor.toml)
  +-- Audit Logger
  |
  +-- Encrypt/Decrypt
  |     +-- File Size Check
  |     +-- Compression (flate2 gzip)
  |     +-- Streaming (chunked reads for large files)
  |     +-- Key Derivation (Argon2id)
  |     +-- AES-256-GCM Encrypt/Decrypt
  |
  +-- Sign/Verify (Ed25519)
  |     +-- Encrypted Key Storage
  |
  +-- Format v2 (JSON structure)
  |     +-- Header + Metadata + Hash
  |     +-- Compression flag
  |     +-- Backward compat with v1
  |
  +-- Hardware (Device Fingerprint)
  |     +-- Deterministic SHA-256
  |
  +-- Security
        +-- Password Validation
        +-- Rate Limiting
        +-- Secure Memory (zeroize)
```

## Module Breakdown

### `cli` (src/cli/mod.rs)
- Parses CLI arguments via `clap` with subcommands
- Interactive password prompts with confirmation (`rpassword`)
- Progress spinners (`indicatif`)
- Input validation (file exists, directory check)
- Rate limiting on decrypt attempts
- Shell completion generation (`clap_complete`)
- Delegates to crypto/format/signature modules

### `crypto` (src/crypto/)
- **mod.rs**: High-level file encryption with compression and streaming
  - `encrypt_file` / `decrypt_file`: default config
  - `encrypt_file_with_config` / `decrypt_file_with_config`: explicit config
  - Gzip compression (skipped if output is larger than input)
  - Streaming mode for files above threshold (default 100 MiB)
  - File size limit enforcement
- **encryption.rs**: Core AES-256-GCM operations
  - Wire format: magic bytes + version + salt + nonce + ciphertext + tag
  - Random nonce per encryption (12 bytes)
  - Random salt per key derivation (16 bytes)
- **key_derivation.rs**: Argon2id key derivation
  - Configurable parameters (m_cost, t_cost, p_cost)
  - Length-prefixed password+device_id to prevent collisions
  - Shared helper functions (deduplicated)

### `signature` (src/signature/mod.rs)
- Ed25519 key pair generation, signing, verification
- Encrypted private key storage (AES-256-GCM with passphrase)
- Backward compatible loading (detects encrypted vs plaintext format)
- File permissions (0600 on Unix)

### `format` (src/format/mod.rs)
- Encrypted file format version 2:
  - Magic bytes (`SECURE\0\0`)
  - Version field (2, backward compat with 1)
  - FileMetadata: filename, size, timestamps, device fingerprint
  - SHA-256 data hash (of original uncompressed content)
  - Compression flag
  - Length-prefixed header in encrypted payload
- `encrypt_and_sign`: compress + encrypt + Ed25519 sign
- `decrypt_and_verify`: verify signature + decrypt + decompress + verify hash

### `hardware` (src/hardware/mod.rs)
- Deterministic device fingerprint via SHA-256 of:
  - CPU vendor ID
  - Hostname
  - Total memory
  - CPU count
  - Sorted MAC addresses (excluding 00:00:00:00:00:00)
- Consistent across calls and reboots on the same machine
- Disk serial hashing from disk attributes

### `security` (src/security.rs)
- Password strength validation (12+ chars, mixed types, 30+ common pattern blocklist)
- Rate limiter (configurable max attempts per time window)
- SecureString with zeroize-on-drop
- Constant-time comparison

### `config` (src/config.rs)
- TOML configuration file support
- Search: `./encryptor.toml` then `~/.config/file-encryptor/config.toml`
- Sections: argon2, encryption, audit
- `Config::load_or_default()` with sensible defaults

### `audit` (src/audit.rs)
- File-based audit logging with timestamps
- Actions: Encrypt, Decrypt, EncryptDir, DecryptDir, Sign, Verify, GenerateKeys, ReEncrypt
- Configurable via `[audit]` section in config

## Data Flow

### Encryption (encrypt_file)
```
Read file -> Check size -> Compress (gzip) -> Prepend flag byte
  -> Derive key (Argon2id) -> Encrypt (AES-256-GCM)
  -> Write: magic + version + salt + nonce + ciphertext + tag
```

### Encryption with Signing (encrypt_and_sign)
```
Read file -> Create metadata -> Hash original (SHA-256)
  -> Compress (if beneficial) -> Create header (v2)
  -> Serialize: 4-byte header length + header JSON + compressed content
  -> Derive key -> Encrypt (AES-256-GCM)
  -> Sign encrypted blob (Ed25519)
  -> Write JSON: { header, base64(encrypted), base64(signature) }
```

### Decryption
```
Read file -> (If signed: verify Ed25519 signature)
  -> Extract salt + nonce -> Derive key (Argon2id with same salt)
  -> Decrypt (AES-256-GCM) -> Check flag byte
  -> Decompress if needed -> (If signed: verify SHA-256 hash)
  -> Write output
```

## Design Decisions

- **Synchronous**: No async runtime needed. All operations are file I/O bound, not network bound.
- **Compression before encryption**: Encrypted data has high entropy and cannot be compressed after.
- **Length-prefixed headers**: Avoids the broken `file_size + 1000` approximation from v1.
- **Deterministic fingerprint**: SHA-256 of stable hardware attributes instead of random UUID.
- **Format versioning**: `SUPPORTED_FORMAT_VERSIONS` array allows adding new versions while keeping old files decodable.
- **Separate encrypt paths**: `encrypt_file` for simple use, `encrypt_and_sign` for signed+metadata use. Both share the same underlying AES-256-GCM.

## Future Enhancements

- True chunked AEAD (e.g., STREAM construction) for constant-memory encryption of arbitrarily large files
- Hardware security module (HSM) integration for key storage
- Multi-recipient encryption (encrypt for multiple public keys)
- Key escrow and recovery mechanisms
- WASM build for browser-based encryption
