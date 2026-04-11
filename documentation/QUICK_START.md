# Quick Start Guide

Get up and running with File Encryptor in 5 minutes.

## Prerequisites

- Rust 1.70+ installed ([rustup.rs](https://rustup.rs/))

## Install

```bash
git clone https://github.com/RasyaAndrean/Universal-Encryption-System.git
cd Universal-Encryption-System
cargo build --release
```

The binary is at `target/release/file-encryptor`.

## 1. Encrypt a File

```bash
# Interactive password prompt (recommended)
file-encryptor encrypt -i secret.txt -o secret.enc

# Or pass password directly
file-encryptor encrypt -i secret.txt -o secret.enc -p "MyStr0ngP@ss123!"
```

Password requirements: 12+ chars, 2 uppercase, 2 lowercase, 2 digits, 1 special character.

## 2. Decrypt a File

```bash
file-encryptor decrypt -i secret.enc -o secret.txt
```

## 3. Encrypt a Directory

```bash
file-encryptor encrypt-dir -i ./my-folder -o folder.enc
file-encryptor decrypt-dir -i folder.enc -o ./restored-folder
```

## 4. Generate Signing Keys

```bash
# With encrypted private key (recommended)
file-encryptor generate-keys -o ./keys -n mykey --passphrase "KeySecret!"

# Plaintext private key
file-encryptor generate-keys -o ./keys -n mykey
```

## 5. Encrypt + Sign

```bash
file-encryptor encrypt -i secret.txt -o secret.enc -k keys/mykey_private.json
file-encryptor decrypt -i secret.enc -o secret.txt -k keys/mykey_public.json
```

## 6. Device Binding

Tie encrypted files to the current machine:

```bash
file-encryptor encrypt -i secret.txt -o secret.enc --bind-device
file-encryptor decrypt -i secret.enc -o secret.txt --validate-device
```

## 7. Change Password

```bash
file-encryptor re-encrypt -i secret.enc -o secret_new.enc
```

## 8. Configuration

```bash
file-encryptor init-config
# Edit encryptor.toml to adjust Argon2 params, compression, file limits, audit logging
```

## 9. Shell Completions

```bash
file-encryptor completions bash > ~/.local/share/bash-completion/completions/file-encryptor
file-encryptor completions zsh > ~/.zfunc/_file-encryptor
file-encryptor completions fish > ~/.config/fish/completions/file-encryptor.fish
file-encryptor completions powershell > file-encryptor.ps1
```

## Common Use Cases

| Scenario | Command |
|----------|---------|
| Personal file encryption | `encrypt -i file -o file.enc` |
| Business with signatures | `encrypt -i file -o file.enc -k private.json` |
| Device-locked encryption | `encrypt -i file -o file.enc --bind-device` |
| Directory backup | `encrypt-dir -i ./folder -o backup.enc` |
| Password rotation | `re-encrypt -i old.enc -o new.enc` |

## Security Checklist

- Use strong passwords (12+ chars, mixed types)
- Store private keys securely (use `--passphrase` to encrypt them)
- Enable device binding for sensitive files
- Keep `encryptor_audit.log` for operation history
- Back up key pairs in a secure location

## Troubleshooting Quick Reference

| Problem | Solution |
|---------|----------|
| "Password rejected" | Password doesn't meet strength requirements |
| "Rate limit exceeded" | Too many decrypt attempts, wait 60 seconds |
| "File not found" | Check input file path exists |
| "Device binding failed" | File was encrypted on a different machine |
| "Integrity check failed" | File was tampered with or wrong key |

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for detailed solutions.
