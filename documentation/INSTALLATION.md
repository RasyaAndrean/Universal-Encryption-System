# Installation and Setup Guide

## System Requirements

- **Rust:** 1.70 or later
- **OS:** Linux, Windows 10+, macOS 12+
- **RAM:** 64 MB minimum (Argon2id uses ~19 MiB during key derivation)
- **Disk:** ~20 MB for the compiled binary

## Install Rust

```bash
# Linux / macOS
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Windows: download rustup-init.exe from https://rustup.rs/
```

Verify:

```bash
rustc --version   # 1.70+
cargo --version
```

## Build from Source

```bash
git clone https://github.com/RasyaAndrean/Universal-Encryption-System.git
cd Universal-Encryption-System
cargo build --release
```

Binary: `target/release/file-encryptor` (or `.exe` on Windows).

### Install to PATH

```bash
cargo install --path .
```

## Dependencies

All managed by Cargo automatically:

| Category | Crate | Purpose |
|----------|-------|---------|
| Crypto | `argon2` | Argon2id key derivation |
| Crypto | `aes-gcm` | AES-256-GCM encryption |
| Crypto | `ed25519-dalek` | Ed25519 signatures |
| Crypto | `sha2` | SHA-256 hashing |
| Crypto | `rand` | CSPRNG |
| Crypto | `zeroize` | Secure memory wiping |
| CLI | `clap` | Argument parsing |
| CLI | `clap_complete` | Shell completions |
| CLI | `rpassword` | Hidden password input |
| CLI | `indicatif` | Progress spinners |
| Serialization | `serde` / `serde_json` | JSON serialization |
| Serialization | `base64` / `hex` | Encoding |
| System | `sysinfo` | Hardware fingerprinting |
| Compression | `flate2` | Gzip compression |
| Files | `tar` | Directory archiving |
| Files | `tempfile` | Secure temp files |
| Config | `toml` | Configuration parsing |
| Logging | `chrono` | Audit timestamps |
| Error | `thiserror` / `anyhow` | Error handling |

## Project Structure

```
src/
  main.rs              # Entry point (synchronous)
  lib.rs               # Library exports
  cli/mod.rs           # CLI commands, interactive prompts, progress UI
  crypto/
    mod.rs             # File encrypt/decrypt, compression, streaming
    encryption.rs      # AES-256-GCM core
    key_derivation.rs  # Argon2id with deduplication
  signature/mod.rs     # Ed25519, encrypted key storage
  hardware/mod.rs      # Deterministic device fingerprint (SHA-256)
  format/mod.rs        # File format v2 with compression + versioning
  security.rs          # Password validation, rate limiting
  config.rs            # encryptor.toml support
  audit.rs             # Audit logging
test/test.rs           # Integration tests
benches/crypto_bench.rs # Criterion benchmarks
.github/workflows/
  ci.yml               # CI pipeline
  release.yml          # Release binary builds
```

## Development Setup

```bash
cargo test          # Run all tests
cargo clippy        # Lint
cargo fmt           # Format
cargo bench         # Run benchmarks
cargo doc --open    # API documentation
```

## Cross-Platform Building

```bash
rustup target add x86_64-unknown-linux-gnu
rustup target add x86_64-pc-windows-msvc
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

cargo build --release --target x86_64-unknown-linux-gnu
```

## Post-Install Setup

### Shell Completions

```bash
file-encryptor completions bash > ~/.local/share/bash-completion/completions/file-encryptor
file-encryptor completions zsh > ~/.zfunc/_file-encryptor
file-encryptor completions fish > ~/.config/fish/completions/file-encryptor.fish
```

### Configuration File

```bash
file-encryptor init-config
# Creates encryptor.toml with defaults
```

### Verify Installation

```bash
file-encryptor --version
file-encryptor fingerprint
```
