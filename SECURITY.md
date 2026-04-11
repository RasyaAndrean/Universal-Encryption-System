# Security Documentation

## Threat Model

### Protected Against
- Unauthorized file access (AES-256-GCM encryption)
- Password brute-force (Argon2id with configurable cost)
- File tampering (GCM authentication tag + SHA-256 hash)
- Signature forgery (Ed25519 digital signatures)
- Cross-device access (deterministic hardware binding)
- Memory forensics (zeroize on drop)
- Weak passwords (strength validation with 30+ pattern blocklist)
- Rapid brute-force (rate limiting, 3 attempts per 60 seconds)

### Not Protected Against
- Compromised system (keylogger, memory dump on live system)
- Physical access to unlocked machine with decrypted files
- Quantum computing attacks (future concern for all classical crypto)
- Side-channel attacks on the host system

## Cryptographic Primitives

### Key Derivation: Argon2id

- **Algorithm:** Argon2id (hybrid of Argon2i and Argon2d)
- **Version:** 1.3 (0x13)
- **Default parameters:**
  - Memory: 19,456 KiB (19 MiB)
  - Iterations: 2
  - Parallelism: 1
  - Output: 32 bytes (256 bits)
- **Salt:** 16 bytes, randomly generated per encryption
- **Configurable:** via `encryptor.toml` `[argon2]` section

Password and device ID are combined using length-prefixed format (`len:password:device_id`) to prevent input collision.

### Encryption: AES-256-GCM

- **Key size:** 256 bits
- **Nonce:** 12 bytes (96 bits), randomly generated per encryption
- **Tag:** 16 bytes (128 bits), appended to ciphertext
- **Wire format:** `ENCRYPT\0` + version(1) + salt(16) + nonce(12) + ciphertext + tag(16)

Each encryption produces unique output due to random salt and random nonce.

### Digital Signatures: Ed25519

- **Key size:** 256 bits (32 bytes each for public and private)
- **Signature size:** 64 bytes
- **Usage:** Signs the encrypted data blob (sign-then-encrypt is not used; we sign the ciphertext)

### Hashing: SHA-256

- Used for file integrity verification (hash of original uncompressed content)
- Used in device fingerprinting (hash of hardware attributes)

### Compression: Gzip (flate2)

- Applied before encryption (encrypted data cannot be compressed)
- Compression is skipped if output is larger than input
- Default level: 6 (configurable 0-9)
- No security implications: compression happens on plaintext before encryption

## Password Requirements

Enforced in CLI before encryption:

| Requirement | Value |
|-------------|-------|
| Minimum length | 12 characters |
| Uppercase letters | 2+ |
| Lowercase letters | 2+ |
| Digits | 2+ |
| Special characters | 1+ |
| Common patterns | 30+ patterns blocked |

Blocked patterns include: password, 123456, qwerty, abc123, admin, welcome, letmein, monkey, dragon, master, login, princess, iloveyou, trustno1, sunshine, shadow, passw0rd, football, baseball, superman, batman, access, hello, charlie, donald, and numeric sequences.

## Device Binding

When `--bind-device` is enabled:

1. A deterministic device fingerprint is computed from:
   - CPU vendor ID
   - Hostname
   - Total physical memory
   - CPU core count
   - Sorted MAC addresses (excluding null addresses)
2. These are hashed with SHA-256 to produce a stable identifier
3. The fingerprint is mixed into the Argon2id key derivation
4. The fingerprint is stored in file metadata for validation

The fingerprint is **deterministic** (same on every call) and **stable across reboots**. It will change if hardware is significantly modified (RAM upgrade, hostname change, network adapter swap).

## Rate Limiting

- 3 decryption attempts per 60-second window (CLI-enforced)
- Per-process limiter (resets on restart)
- Logged in audit trail on failure

## Encrypted Key Storage

Private keys can be encrypted at rest with a passphrase:

- Key JSON is encrypted with AES-256-GCM using the passphrase
- Stored in `EncryptedKeyFile` format with `encrypted: true` flag
- Backward compatible: plain KeyPair JSON files still loadable
- File permissions set to 0600 on Unix systems

## File Format Security

### Format Version 2

```json
{
  "header": {
    "magic": [83, 69, 67, 85, 82, 69, 0, 0],
    "version": 2,
    "metadata": { "original_filename", "file_size", "timestamps", "device_fingerprint" },
    "data_hash": "<sha256 of original uncompressed content>",
    "compressed": true
  },
  "encrypted_data": "<base64 of AES-256-GCM ciphertext>",
  "signature": "<base64 of Ed25519 signature>"
}
```

Inner encrypted payload: `4-byte header length (LE) + header JSON + (compressed) content`

### Version Migration

- `SUPPORTED_FORMAT_VERSIONS = [1, 2]`
- v1 files (no `compressed` field) are handled via `#[serde(default)]`
- Unsupported versions produce a clear error with the supported list

## Audit Trail

All operations are logged when `audit.enabled = true`:

```
[timestamp] ACTION STATUS target=/path details
```

Log file location is configurable. The audit log provides:
- Who decrypted what and when
- Failed decryption attempts (potential attacks)
- Key generation events
- Password rotation (re-encrypt) events

## Secure Memory

- All key material uses `zeroize` crate for automatic cleanup on drop
- `DerivedKey` struct zeroizes the 32-byte key on drop
- `SecureString` zeroizes password bytes on drop
- Temporary files created via `tempfile` crate (OS-managed cleanup)

## Best Practices

### For Users
- Use interactive password prompts (don't pass passwords on command line where shell history may record them)
- Encrypt private keys with `--passphrase`
- Enable device binding for highly sensitive files
- Review audit logs regularly
- Back up key pairs in a secure, separate location

### For Deployment
- Set restrictive file permissions on encrypted files and keys
- Use a dedicated service account for automated encryption
- Monitor audit logs for unusual patterns
- Rotate passwords periodically using `re-encrypt`
- Store `encryptor.toml` with appropriate permissions (may contain security-relevant settings)

## Known Limitations

1. **Not constant-memory for non-streaming**: Files below the streaming threshold are loaded fully into RAM
2. **Per-process rate limiting**: Rate limiter resets when the process restarts
3. **No key revocation**: No built-in mechanism to revoke compromised keys
4. **Single-recipient**: Each file is encrypted with one password; no multi-recipient support
5. **GCM nonce size**: 12-byte random nonce limits safe encryption count to ~2^32 per key (not an issue with random salt per encryption)
