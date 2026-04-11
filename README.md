# Universal Encryption System

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/RasyaAndrean/Universal-Encryption-System/actions/workflows/ci.yml/badge.svg)](https://github.com/RasyaAndrean/Universal-Encryption-System/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/RasyaAndrean/Universal-Encryption-System)](https://github.com/RasyaAndrean/Universal-Encryption-System/releases)
[![Security](https://img.shields.io/badge/crypto-AES--256--GCM%20%7C%20Argon2id%20%7C%20Ed25519-blue)](SECURITY.md)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](#)

A comprehensive file encryption system built in Rust. Encrypt files and directories with AES-256-GCM, sign them with Ed25519, bind to specific hardware, and compress automatically — all from one CLI tool.

## Highlights

- **AES-256-GCM** authenticated encryption with **Argon2id** key derivation
- **Gzip compression** before encryption (automatic, reduces output size)
- **Streaming encryption** for large files (configurable, default >100 MiB)
- **Ed25519 digital signatures** with encrypted private key storage
- **Directory encryption** via tar archiving
- **Device binding** ties files to specific hardware (deterministic SHA-256 fingerprint)
- **Re-encrypt** command to change passwords without manual decrypt/re-encrypt
- **Configuration file** (`encryptor.toml`) for all parameters
- **Audit logging** of all operations with timestamps
- **Shell completions** for bash, zsh, fish, powershell
- **Interactive password** prompts with confirmation and strength validation
- **Rate limiting** on decryption attempts (brute-force protection)
- **Format versioning** with backward compatibility
- **Cross-platform CI/CD** with automatic binary releases

## Quick Start

```bash
# Build
git clone https://github.com/RasyaAndrean/Universal-Encryption-System.git
cd Universal-Encryption-System
cargo build --release

# Encrypt a file (interactive password prompt)
file-encryptor encrypt -i secret.txt -o secret.enc

# Decrypt
file-encryptor decrypt -i secret.enc -o secret.txt

# Encrypt a directory
file-encryptor encrypt-dir -i ./my-folder -o folder.enc

# Change password
file-encryptor re-encrypt -i secret.enc -o secret_new.enc
```

## All Commands

| Command | Description |
|---------|-------------|
| `encrypt` | Encrypt a file with optional signing and device binding |
| `decrypt` | Decrypt a file with optional signature verification |
| `encrypt-dir` | Archive and encrypt a directory |
| `decrypt-dir` | Decrypt and extract a directory |
| `re-encrypt` | Change password on an encrypted file |
| `generate-keys` | Generate Ed25519 key pair (optional passphrase encryption) |
| `sign` | Sign a file with private key |
| `verify` | Verify a file signature |
| `fingerprint` | Show device fingerprint |
| `validate-fingerprint` | Validate a stored fingerprint |
| `init-config` | Generate default configuration file |
| `completions` | Generate shell completions (bash/zsh/fish/powershell) |

## Encryption with Signing

```bash
# Generate keys (encrypted with passphrase)
file-encryptor generate-keys -o ./keys -n mykey --passphrase "KeySecret!"

# Encrypt + sign
file-encryptor encrypt -i file.txt -o file.enc -k keys/mykey_private.json

# Decrypt + verify
file-encryptor decrypt -i file.enc -o file.txt -k keys/mykey_public.json
```

## Device Binding

```bash
file-encryptor encrypt -i secret.txt -o secret.enc --bind-device
file-encryptor decrypt -i secret.enc -o secret.txt --validate-device
```

## Configuration

```bash
file-encryptor init-config  # Creates encryptor.toml
```

Configurable: Argon2 parameters, max file size, compression level, streaming threshold, audit log path. See [encryptor.example.toml](encryptor.example.toml).

## Password Requirements

12+ characters, 2 uppercase, 2 lowercase, 2 digits, 1 special character, no common patterns.

## File Format

```
Format v2 (JSON):
  header: magic + version(2) + metadata + SHA-256 hash + compressed flag
  encrypted_data: base64(AES-256-GCM ciphertext)
  signature: base64(Ed25519 signature)
```

Format v1 files are still decryptable (backward compatible).

## Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](documentation/QUICK_START.md) | 5-minute setup guide |
| [Installation](documentation/INSTALLATION.md) | Full build and setup |
| [API Reference](documentation/API.md) | Rust library API |
| [Advanced Usage](documentation/ADVANCED_USAGE.md) | Config, batch ops, CI/CD |
| [Troubleshooting](documentation/TROUBLESHOOTING.md) | Error solutions |
| [Architecture](ARCHITECTURE.md) | System design |
| [Security](SECURITY.md) | Threat model and crypto details |

## Development

```bash
cargo test          # Run tests
cargo clippy        # Lint
cargo fmt           # Format
cargo bench         # Benchmarks (Argon2id + AES-GCM throughput)
cargo doc --open    # API docs
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes and add tests
4. Run `cargo test && cargo clippy && cargo fmt -- --check`
5. Commit and push
6. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE).

## Acknowledgments

- [RustCrypto](https://github.com/RustCrypto) ecosystem for cryptographic primitives
- [clap](https://github.com/clap-rs/clap) for CLI framework
- [sysinfo](https://github.com/GuillaumeGomez/sysinfo) for hardware fingerprinting
