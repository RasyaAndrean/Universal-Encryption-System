# File Encryptor - Documentation Index

## Documentation Structure

| Document | Purpose | Audience |
|----------|---------|----------|
| [QUICK_START.md](QUICK_START.md) | 5-minute setup and usage | Beginners |
| [INSTALLATION.md](INSTALLATION.md) | Full build and setup guide | All users |
| [API.md](API.md) | Rust library API reference | Developers |
| [ADVANCED_USAGE.md](ADVANCED_USAGE.md) | Config, batch ops, CI/CD, key management | Advanced users |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Error solutions and diagnostics | All users |
| [ARCHITECTURE.md](../ARCHITECTURE.md) | System design and module breakdown | Developers |
| [SECURITY.md](../SECURITY.md) | Threat model and crypto details | Security professionals |

## Quick Navigation

### New User
1. [QUICK_START.md](QUICK_START.md) - Get running in 5 minutes
2. [INSTALLATION.md](INSTALLATION.md) - Detailed setup
3. [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - If something goes wrong

### Developer
1. [ARCHITECTURE.md](../ARCHITECTURE.md) - System design
2. [API.md](API.md) - Library reference
3. [ADVANCED_USAGE.md](ADVANCED_USAGE.md) - Complex scenarios

### Security Professional
1. [SECURITY.md](../SECURITY.md) - Threat model and algorithms
2. [ARCHITECTURE.md](../ARCHITECTURE.md) - Implementation details
3. [ADVANCED_USAGE.md](ADVANCED_USAGE.md) - Enterprise deployment

## Version

This documentation covers **v0.3.0** featuring:
- AES-256-GCM encryption with Argon2id key derivation
- Gzip compression before encryption
- Streaming encryption for large files
- Directory encrypt/decrypt via tar archiving
- Ed25519 digital signatures with encrypted key storage
- Deterministic device fingerprinting (SHA-256)
- Configuration file (`encryptor.toml`)
- Audit logging
- Shell completions (bash/zsh/fish/powershell)
- Re-encrypt command for password rotation
- Rate limiting and password strength validation
- CI/CD pipeline with cross-platform binary releases
