# Troubleshooting Guide

## Installation Issues

### `cargo build` fails with dependency errors

```bash
# Update Rust toolchain
rustup update stable

# Clean and rebuild
cargo clean
cargo build --release
```

### Missing system libraries (Linux)

Some systems may need development headers for `sysinfo`:

```bash
# Debian/Ubuntu
sudo apt install build-essential pkg-config

# Fedora
sudo dnf install gcc pkg-config
```

---

## Encryption Issues

### "Password rejected: Password too weak"

Password must meet all requirements:
- 12+ characters
- 2+ uppercase letters
- 2+ lowercase letters
- 2+ digits
- 1+ special character (`!@#$%^&*` etc.)
- No common patterns (password, qwerty, 123456, etc.)

### "File too large: X bytes (max: Y bytes)"

Default max file size is 2 GiB. Increase in `encryptor.toml`:

```toml
[encryption]
max_file_size = 4294967296  # 4 GiB
```

### "Input file not found"

Check the file path exists and is accessible. Use absolute paths if relative paths fail.

### Encrypted file is larger than original

Expected for small files due to encryption overhead (salt, nonce, tag, header). For larger files, gzip compression usually makes the output smaller. If the input is already compressed (`.zip`, `.jpg`, `.mp4`), disable compression:

```toml
[encryption]
compress = false
```

---

## Decryption Issues

### "Decryption failed" / "aead::Error"

- Wrong password (most common)
- File was encrypted with device binding but `--validate-device` uses different device
- File is corrupted

### "Rate limit exceeded"

Too many failed decryption attempts. Wait 60 seconds and try again.

### "Invalid file format"

- File was not encrypted by this tool
- File was truncated or corrupted during transfer
- Trying to use `decrypt` on a file encrypted with `encrypt_and_sign` (use `-k` flag with public key)

### "Unsupported format version: X"

The file was created with a newer version of the tool. Update to the latest version:

```bash
git pull
cargo build --release
```

---

## Signature Issues

### "Integrity check failed"

The file has been modified after encryption/signing. Re-encrypt from the original.

### "Signature verification FAILED"

- Wrong public key
- File was modified after signing
- Signature file (`.sig`) is corrupted or mismatched

### "Key file is encrypted -- passphrase required"

The private key was saved with `--passphrase`. Add `--passphrase "your_passphrase"` to the command:

```bash
file-encryptor sign -f file.txt -k key_private.json --passphrase "YourPassphrase"
```

---

## Device Binding Issues

### "Device binding validation failed"

The file was encrypted on a different machine. Device fingerprint is based on: CPU vendor, hostname, total memory, CPU count, MAC addresses.

Causes:
- Different physical machine
- Hostname changed
- Network adapter changed (MAC address shift)
- Significant hardware change (RAM upgrade/downgrade)

Recovery: decrypt on the original machine, or re-encrypt without `--bind-device`.

### Fingerprint changes after hardware modification

This is by design. If you upgraded RAM or changed network adapters, the fingerprint will differ. Get the new fingerprint:

```bash
file-encryptor fingerprint
```

---

## Configuration Issues

### Config file not loading

Search order:
1. `./encryptor.toml` (current directory)
2. `~/.config/file-encryptor/config.toml` (home directory)

If neither exists, defaults are used. Generate a config:

```bash
file-encryptor init-config
```

### Invalid TOML syntax

```bash
# Validate your config
cat encryptor.toml
```

Common mistakes:
- Missing quotes around string values
- Wrong data types (e.g., `true` not `"true"`)
- Missing section headers (`[argon2]`, `[encryption]`, `[audit]`)

---

## Directory Encryption Issues

### "Input is not a directory"

Use `encrypt-dir` for directories and `encrypt` for files.

### Empty output after `decrypt-dir`

The tar archive inside may be corrupted. Try decrypting to a file first:

```bash
file-encryptor decrypt -i folder.enc -o folder.tar
```

Then manually inspect the tar.

---

## Shell Completion Issues

### Completions not working after install

Make sure the completion file is in the right location and your shell is configured to load it:

**Bash:**
```bash
source ~/.local/share/bash-completion/completions/file-encryptor
```

**Zsh:** Add to `~/.zshrc`:
```bash
fpath=(~/.zfunc $fpath)
autoload -Uz compinit && compinit
```

---

## Audit Log Issues

### Log file not created

Check `encryptor.toml`:
```toml
[audit]
enabled = true
log_file = "encryptor_audit.log"
```

Ensure the directory is writable. Use an absolute path if needed.

---

## Performance Issues

### Encryption is slow

Argon2id key derivation is intentionally slow (security feature). To speed up at the cost of security:

```toml
[argon2]
m_cost = 8192    # Less memory (8 MiB)
t_cost = 1       # Fewer iterations
```

### High memory usage on large files

Files above the streaming threshold (default 100 MiB) use chunked reads. Lower the threshold:

```toml
[encryption]
stream_threshold = 52428800  # 50 MiB
stream_chunk_size = 33554432 # 32 MiB chunks
```

---

## Getting Help

1. Check this guide for your specific error message
2. Run with `--help` for command-specific usage
3. Check [GitHub Issues](https://github.com/RasyaAndrean/Universal-Encryption-System/issues)
4. Review [SECURITY.md](../SECURITY.md) for cryptographic details
