<div align="center">

# Universal Encryption System

**A fast, secure, and comprehensive file encryption toolkit built in Rust.**

Encrypt files and directories with military-grade AES-256-GCM, sign with Ed25519 digital signatures, bind to hardware fingerprints, and compress automatically — all from a single CLI.

[![CI](https://github.com/RasyaAndrean/Universal-Encryption-System/actions/workflows/ci.yml/badge.svg)](https://github.com/RasyaAndrean/Universal-Encryption-System/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/RasyaAndrean/Universal-Encryption-System?color=%2340C057&label=latest)](https://github.com/RasyaAndrean/Universal-Encryption-System/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)](#installation)

[Features](#features) · [Installation](#installation) · [Quick Start](#quick-start) · [Usage](#usage) · [Documentation](#documentation) · [Contributing](#contributing)

</div>

---

## Why Universal Encryption System?

Most file encryption tools do one thing. This one does everything:

- **Encrypt** individual files or entire directories with a single command
- **Sign** files cryptographically so recipients can verify authenticity
- **Bind** encrypted files to specific hardware — they can only be decrypted on authorized machines
- **Compress** data before encryption to minimize storage and transfer overhead
- **Stream** large files without loading them entirely into memory
- **Audit** every operation with structured, timestamped logs

All of this with zero configuration required — sane defaults out of the box, full customization when you need it.

---

## Features

### Cryptography

| Feature | Details |
|---------|---------|
| **Encryption** | AES-256-GCM authenticated encryption (AEAD) |
| **Key Derivation** | Argon2id with configurable memory/time/parallelism cost |
| **Digital Signatures** | Ed25519 (RFC 8032) with encrypted private key storage |
| **Integrity** | SHA-256 file hashing, GCM authentication tags |
| **Format Versioning** | v2 format with full backward compatibility for v1 |

### Operations

| Feature | Details |
|---------|---------|
| **File Encryption** | Encrypt/decrypt individual files with password protection |
| **Directory Encryption** | Tar-archive and encrypt entire directory trees |
| **Streaming Mode** | Chunked processing for files above configurable threshold (default: 100 MiB) |
| **Compression** | Automatic gzip compression before encryption (skipped if no size benefit) |
| **Re-encryption** | Rotate passwords without manual decrypt/re-encrypt cycle |
| **Device Binding** | Deterministic SHA-256 hardware fingerprint ties files to specific machines |

### Security

| Feature | Details |
|---------|---------|
| **Password Validation** | Strength enforcement: length, complexity, common pattern rejection |
| **Rate Limiting** | Brute-force protection on decryption attempts (3 per 60s) |
| **Secure Memory** | Zeroize-on-drop for sensitive data in memory |
| **Audit Logging** | Timestamped logs of all encrypt/decrypt/sign/verify operations |
| **Encrypted Keys** | Private keys are AES-256-GCM encrypted at rest with a passphrase |

### Developer Experience

| Feature | Details |
|---------|---------|
| **Shell Completions** | Auto-generated for bash, zsh, fish, and PowerShell |
| **Configuration File** | TOML-based config with layered resolution (local → user → defaults) |
| **Cross-platform** | First-class support for Linux, macOS, and Windows |
| **CI/CD Ready** | GitHub Actions workflows for testing, linting, and binary releases |
| **Benchmarks** | Criterion-based benchmarks for Argon2id and AES-GCM throughput |

---

## Installation

### From Releases (Recommended)

Download a prebuilt binary for your platform from the [latest release](https://github.com/RasyaAndrean/Universal-Encryption-System/releases/latest):

| Platform | Binary |
|----------|--------|
| Linux (x86_64) | `file-encryptor-linux-amd64` |
| macOS (x86_64) | `file-encryptor-macos-amd64` |
| macOS (Apple Silicon) | `file-encryptor-macos-arm64` |
| Windows (x86_64) | `file-encryptor-windows-amd64.exe` |

```bash
# Linux / macOS
chmod +x file-encryptor-*
sudo mv file-encryptor-* /usr/local/bin/file-encryptor
```

### From Source

Requires [Rust](https://www.rust-lang.org/tools/install) 1.70 or later.

```bash
git clone https://github.com/RasyaAndrean/Universal-Encryption-System.git
cd Universal-Encryption-System
cargo build --release
```

The binary will be at `target/release/file-encryptor` (or `.exe` on Windows).

### Shell Completions

```bash
# Bash
file-encryptor completions bash > ~/.local/share/bash-completion/completions/file-encryptor

# Zsh
file-encryptor completions zsh > ~/.zfunc/_file-encryptor

# Fish
file-encryptor completions fish > ~/.config/fish/completions/file-encryptor.fish

# PowerShell
file-encryptor completions powershell >> $PROFILE
```

---

## Quick Start

```bash
# Encrypt a file (you'll be prompted for a password)
file-encryptor encrypt -i secret.txt -o secret.enc

# Decrypt it
file-encryptor decrypt -i secret.enc -o secret.txt

# Encrypt an entire directory
file-encryptor encrypt-dir -i ./confidential/ -o confidential.enc

# Decrypt the directory
file-encryptor decrypt-dir -i confidential.enc -o ./confidential/
```

That's it. No setup, no config files, no key management — just encrypt and decrypt.

---

## Usage

### File Encryption

```bash
# Basic encryption
file-encryptor encrypt -i document.pdf -o document.pdf.enc

# Encrypt with device binding (can only decrypt on this machine)
file-encryptor encrypt -i document.pdf -o document.pdf.enc --bind-device

# Decrypt with device validation
file-encryptor decrypt -i document.pdf.enc -o document.pdf --validate-device
```

### Digital Signatures

```bash
# Generate a key pair (passphrase-protected)
file-encryptor generate-keys -o ./keys -n mykey --passphrase "StrongKeyPass1!"

# Encrypt and sign in one step
file-encryptor encrypt -i report.pdf -o report.pdf.enc -k keys/mykey_private.json

# Decrypt and verify signature
file-encryptor decrypt -i report.pdf.enc -o report.pdf -k keys/mykey_public.json

# Sign/verify standalone
file-encryptor sign -i file.txt -k keys/mykey_private.json -o file.txt.sig
file-encryptor verify -i file.txt -k keys/mykey_public.json -s file.txt.sig
```

### Directory Encryption

```bash
# Encrypt a directory (creates a tar archive, then encrypts)
file-encryptor encrypt-dir -i ./project-files/ -o project.enc

# Decrypt and extract
file-encryptor decrypt-dir -i project.enc -o ./project-files/
```

### Password Rotation

```bash
# Change the password on an encrypted file
file-encryptor re-encrypt -i old.enc -o new.enc
```

### Device Fingerprint

```bash
# Display this machine's fingerprint
file-encryptor fingerprint

# Validate a known fingerprint
file-encryptor validate-fingerprint -f "abc123..."
```

### Configuration

```bash
# Generate a default config file
file-encryptor init-config

# Edit encryptor.toml to customize:
#   - Argon2 memory/time/parallelism costs
#   - Max file size limit
#   - Compression level (0-9)
#   - Streaming chunk size and threshold
#   - Audit log file path
```

See [`encryptor.example.toml`](encryptor.example.toml) for all available options.

---

## Command Reference

| Command | Description |
|---------|-------------|
| `encrypt` | Encrypt a file with optional signing and device binding |
| `decrypt` | Decrypt a file with optional signature verification |
| `encrypt-dir` | Archive and encrypt an entire directory |
| `decrypt-dir` | Decrypt and extract a directory archive |
| `re-encrypt` | Change the password on an encrypted file |
| `generate-keys` | Generate an Ed25519 key pair with optional passphrase |
| `sign` | Create a detached Ed25519 signature |
| `verify` | Verify a detached signature against a public key |
| `fingerprint` | Display the current device's hardware fingerprint |
| `validate-fingerprint` | Check if a fingerprint matches this device |
| `init-config` | Generate a default `encryptor.toml` configuration file |
| `completions` | Output shell completions for bash/zsh/fish/powershell |

Run `file-encryptor <command> --help` for detailed options on any command.

---

## How It Works

```
                    ┌─────────────┐
                    │  plaintext  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  gzip       │  Compression (skipped if no benefit)
                    └──────┬──────┘
                           │
              ┌────────────▼────────────┐
              │  AES-256-GCM encrypt    │  Key derived via Argon2id
              │  (random salt + nonce)  │  from password + device ID
              └────────────┬────────────┘
                           │
                    ┌──────▼──────┐
                    │  Ed25519    │  Optional digital signature
                    │  sign       │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  .enc file  │  Length-prefixed JSON header
                    └─────────────┘  + encrypted payload + signature
```

**Wire Format (v2):**

```
[4 bytes: header length (LE)] [JSON header] [encrypted content]

Header fields:
  - format_version: 2
  - original_filename, original_size
  - sha256_hash (of plaintext)
  - salt, nonce (base64)
  - compressed: true/false
  - device_id (optional)
  - signature (optional, base64)
```

---

## Documentation

| Document | Description | Audience |
|----------|-------------|----------|
| **[Quick Start](documentation/QUICK_START.md)** | Get running in 5 minutes | Beginners |
| **[Installation](documentation/INSTALLATION.md)** | Full build and setup guide | All users |
| **[API Reference](documentation/API.md)** | Rust library API documentation | Developers |
| **[Advanced Usage](documentation/ADVANCED_USAGE.md)** | Config tuning, batch ops, CI/CD integration | Power users |
| **[Troubleshooting](documentation/TROUBLESHOOTING.md)** | Common errors and solutions | All users |
| **[Architecture](ARCHITECTURE.md)** | System design and module breakdown | Contributors |
| **[Security](SECURITY.md)** | Threat model, algorithms, and audit details | Security engineers |

---

## Development

```bash
# Run the test suite
cargo test

# Run lints
cargo clippy -- -D warnings

# Check formatting
cargo fmt -- --check

# Run benchmarks
cargo bench

# Generate API docs
cargo doc --open
```

### Project Structure

```
src/
├── main.rs              # Entry point
├── lib.rs               # Public library exports
├── cli/mod.rs           # CLI argument parsing and command dispatch
├── crypto/
│   ├── mod.rs           # File encryption/decryption with compression
│   ├── encryption.rs    # AES-256-GCM core operations
│   └── key_derivation.rs # Argon2id key derivation
├── format/mod.rs        # Wire format: header serialization, versioning
├── signature/mod.rs     # Ed25519 signing, verification, key management
├── hardware/mod.rs      # Deterministic device fingerprinting
├── security.rs          # Password validation, rate limiting, secure memory
├── config.rs            # TOML configuration loading
└── audit.rs             # Structured audit logging
```

---

## Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-feature`
3. **Write** your changes with tests
4. **Validate** locally:
   ```bash
   cargo test && cargo clippy -- -D warnings && cargo fmt -- --check
   ```
5. **Commit** with a clear message and open a **Pull Request**

Please read [ARCHITECTURE.md](ARCHITECTURE.md) before making structural changes.

---

## Security

This project takes security seriously. For details on the threat model, cryptographic choices, and security properties, see **[SECURITY.md](SECURITY.md)**.

If you discover a security vulnerability, please report it responsibly by opening a [GitHub issue](https://github.com/RasyaAndrean/Universal-Encryption-System/issues) with the `security` label.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Acknowledgments

Built on the shoulders of excellent open-source Rust crates:

- **[RustCrypto](https://github.com/RustCrypto)** — AES-GCM, Argon2, SHA-256
- **[ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)** — Ed25519 signatures
- **[clap](https://github.com/clap-rs/clap)** — CLI framework with derive macros
- **[sysinfo](https://github.com/GuillaumeGomez/sysinfo)** — Cross-platform hardware information
- **[flate2](https://github.com/rust-lang/flate2-rs)** — Gzip compression
- **[serde](https://github.com/serde-rs/serde)** + **[toml](https://github.com/toml-rs/toml)** — Serialization and configuration

---

<div align="center">

**[Download Latest Release](https://github.com/RasyaAndrean/Universal-Encryption-System/releases/latest)**

Made with Rust

</div>
