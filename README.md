# File Encryptor - Universal Encryption System

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/RasyaAndrean/Universal-Encryption-System/actions/workflows/ci.yml/badge.svg)](https://github.com/RasyaAndrean/Universal-Encryption-System/actions/workflows/ci.yml)
[![Security](https://img.shields.io/badge/security-AES--256--GCM-blue)](SECURITY.md)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](#)

A comprehensive file encryption system built in Rust with AES-256-GCM encryption, Ed25519 digital signatures, Argon2id key derivation, gzip compression, hardware device binding, streaming support for large files, and audit logging.

## Features

### Core Security
- **AES-256-GCM** authenticated encryption with integrity protection
- **Argon2id** password-based key derivation (configurable parameters)
- **Ed25519** digital signatures for file authenticity
- **Device binding** ties encrypted files to specific hardware
- **Secure memory** automatic zeroization of sensitive data

### v0.3.0 Highlights
- **Gzip compression** before encryption (automatic, reduces file size)
- **Streaming encryption** for large files (configurable threshold, default 100 MiB)
- **Directory encryption** archive and encrypt entire directories
- **Re-encrypt command** change password without manual decrypt + re-encrypt
- **Encrypted private keys** protect key files with a passphrase
- **Configuration file** (`encryptor.toml`) for Argon2, compression, limits
- **Audit logging** all operations logged with timestamps
- **Shell completions** for bash, zsh, fish, powershell
- **Progress indicators** spinner for all operations
- **Interactive password** prompts with confirmation
- **Rate limiting** on decryption attempts
- **Format versioning** backward compatible decryption of older formats
- **CI/CD pipeline** build + test on Linux/Windows/macOS
- **Release workflow** automatic binary builds on git tag

## Installation

### Prerequisites
- Rust 1.70+ and Cargo

### Build from Source
```bash
git clone https://github.com/RasyaAndrean/Universal-Encryption-System.git
cd Universal-Encryption-System
cargo build --release
# Binary: target/release/file-encryptor
```

## Usage

### Encrypt a File
```bash
# With password on command line
file-encryptor encrypt -i secret.txt -o secret.enc -p "MyStr0ngP@ss123!"

# Interactive password prompt (recommended)
file-encryptor encrypt -i secret.txt -o secret.enc

# With device binding + digital signature
file-encryptor encrypt -i secret.txt -o secret.enc --bind-device -k keys/my_private.json
```

### Decrypt a File
```bash
file-encryptor decrypt -i secret.enc -o secret.txt -p "MyStr0ngP@ss123!"

# With signature verification
file-encryptor decrypt -i secret.enc -o secret.txt -k keys/my_public.json
```

### Encrypt / Decrypt a Directory
```bash
file-encryptor encrypt-dir -i ./my-folder -o folder.enc
file-encryptor decrypt-dir -i folder.enc -o ./my-folder-restored
```

### Re-encrypt with New Password
```bash
file-encryptor re-encrypt -i secret.enc -o secret_new.enc
```

### Generate Key Pair
```bash
# Plaintext private key
file-encryptor generate-keys -o ./keys -n mykey

# Encrypted private key (recommended)
file-encryptor generate-keys -o ./keys -n mykey --passphrase "KeyFileSecret!"
```

### Sign / Verify
```bash
file-encryptor sign -f document.txt -k keys/mykey_private.json
file-encryptor verify -f document.txt -k keys/mykey_public.json -s document.sig
```

### Device Fingerprint
```bash
file-encryptor fingerprint
file-encryptor validate-fingerprint "GenuineIntel:MYPC:Windows..."
```

### Shell Completions
```bash
# Bash
file-encryptor completions bash > ~/.local/share/bash-completion/completions/file-encryptor

# Zsh
file-encryptor completions zsh > ~/.zfunc/_file-encryptor

# Fish
file-encryptor completions fish > ~/.config/fish/completions/file-encryptor.fish

# PowerShell
file-encryptor completions powershell > file-encryptor.ps1
```

### Configuration
```bash
# Generate default config
file-encryptor init-config

# Edit encryptor.toml to customize:
# - Argon2 parameters (m_cost, t_cost, p_cost)
# - Max file size
# - Compression on/off and level
# - Streaming threshold
# - Audit log path
```

## Password Requirements

- Minimum 12 characters
- At least 2 uppercase + 2 lowercase letters
- At least 2 digits + 1 special character
- No common patterns (password, qwerty, 123456, etc.)

## File Format

```
EncryptedFileStructure (JSON):
  header:
    magic: "SECURE\0\0"
    version: 2
    metadata: { filename, size, timestamps, device_fingerprint }
    data_hash: SHA-256 of original content
    compressed: true/false
  encrypted_data: base64(AES-256-GCM ciphertext)
  signature: base64(Ed25519 signature)
```

Format v1 files (without compression) are still decryptable.

## Benchmarks

```bash
cargo bench
```

Benchmarks Argon2id key derivation and AES-256-GCM encrypt/decrypt throughput at 1 KiB, 64 KiB, and 1 MiB.

## Development

```bash
# Run tests
cargo test

# Run clippy
cargo clippy

# Format code
cargo fmt

# Generate docs
cargo doc --open
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for system design details.
See [SECURITY.md](SECURITY.md) for threat model and crypto implementation details.

## License

MIT License - see [LICENSE](LICENSE).
