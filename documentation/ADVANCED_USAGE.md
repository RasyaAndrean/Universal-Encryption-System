# Advanced Usage Guide

## Configuration File

Generate and customize `encryptor.toml`:

```bash
file-encryptor init-config
```

### Argon2 Tuning

```toml
[argon2]
m_cost = 19456   # Memory in KiB (19 MiB default)
t_cost = 2       # Iterations
p_cost = 1       # Parallelism
```

For higher security on powerful hardware:
```toml
m_cost = 65536   # 64 MiB
t_cost = 4       # 4 iterations
p_cost = 2       # 2 threads
```

### Compression Settings

```toml
[encryption]
compress = true          # Enable gzip compression (default)
compression_level = 6    # 0 (none) to 9 (max), default 6
```

Compression is skipped automatically if the compressed output is larger than the original (already compressed files like .zip, .jpg, .mp4).

### Large File Settings

```toml
[encryption]
max_file_size = 2147483648    # 2 GiB max (default)
stream_chunk_size = 67108864  # 64 MiB chunks for streaming reads
stream_threshold = 104857600  # Files > 100 MiB use streaming mode
```

Streaming mode reads files in chunks to limit RAM usage for large files.

### Audit Logging

```toml
[audit]
enabled = true
log_file = "encryptor_audit.log"
```

Log format:
```
[2026-04-11 10:30:15.123] ENCRYPT OK target=/path/to/file.txt
[2026-04-11 10:30:20.456] DECRYPT FAIL target=/path/to/file.enc invalid password
```

## Encrypted Private Keys

Protect private key files with a passphrase:

```bash
# Generate with passphrase
file-encryptor generate-keys -o ./keys -n mykey --passphrase "KeyFileSecret!"

# Sign using passphrase-protected key
file-encryptor sign -f document.txt -k keys/mykey_private.json --passphrase "KeyFileSecret!"
```

The private key JSON is encrypted with AES-256-GCM. Without the passphrase, the key file is unreadable.

## Directory Encryption

Encrypt entire directories using tar archiving:

```bash
# Encrypt a project folder
file-encryptor encrypt-dir -i ./project -o project.enc

# Restore
file-encryptor decrypt-dir -i project.enc -o ./project-restored

# With signing
file-encryptor encrypt-dir -i ./project -o project.enc -k keys/mykey_private.json
```

## Password Rotation

Change the password on an encrypted file without manually decrypting:

```bash
# Interactive prompts
file-encryptor re-encrypt -i secret.enc -o secret_new.enc

# Non-interactive
file-encryptor re-encrypt -i secret.enc -o secret_new.enc \
    --old-password "OldP@ss123!" --new-password "NewP@ss456!"
```

## Batch Processing

### Encrypt Multiple Files

```bash
#!/bin/bash
PASSWORD="BatchP@ss123!"
for file in ./documents/*.pdf; do
    file-encryptor encrypt -i "$file" -o "${file}.enc" -p "$PASSWORD"
done
```

### Decrypt All Files in Directory

```bash
#!/bin/bash
PASSWORD="BatchP@ss123!"
for file in ./encrypted/*.enc; do
    output="${file%.enc}"
    file-encryptor decrypt -i "$file" -o "$output" -p "$PASSWORD"
done
```

### Batch Sign and Verify

```bash
# Sign all files
for file in ./release/*; do
    file-encryptor sign -f "$file" -k keys/release_private.json
done

# Verify all signatures
for file in ./release/*.sig; do
    original="${file%.sig}"
    file-encryptor verify -f "$original" -k keys/release_public.json -s "$file"
done
```

## Multi-User Key Management

### Setup

```bash
# Each user generates their own keypair
file-encryptor generate-keys -o ./keys -n alice --passphrase "AliceSecret!"
file-encryptor generate-keys -o ./keys -n bob --passphrase "BobSecret!"

# Share public keys
cp keys/alice_public.json shared_keys/
cp keys/bob_public.json shared_keys/
```

### Workflow

```bash
# Alice encrypts and signs
file-encryptor encrypt -i report.pdf -o report.enc \
    -p "SharedP@ss123!" -k keys/alice_private.json

# Bob verifies Alice's signature and decrypts
file-encryptor decrypt -i report.enc -o report.pdf \
    -p "SharedP@ss123!" -k shared_keys/alice_public.json
```

## Device-Bound Deployments

For files that must only be accessible on specific machines:

```bash
# On the target machine: get fingerprint
file-encryptor fingerprint
# Output: GenuineIntel:SERVER01:Windows...:<hash>

# Encrypt with device binding on that machine
file-encryptor encrypt -i config.json -o config.enc --bind-device

# Can only decrypt on the same machine
file-encryptor decrypt -i config.enc -o config.json --validate-device
```

Device fingerprint is a deterministic SHA-256 hash of CPU, hostname, total memory, CPU count, and MAC addresses. It remains stable across reboots but changes if hardware is modified.

## Integration with CI/CD

### GitHub Actions Example

```yaml
- name: Decrypt secrets
  run: |
    file-encryptor decrypt -i secrets.enc -o .env \
      -p "${{ secrets.ENCRYPTION_PASSWORD }}"
```

### Pre-commit Hook

```bash
#!/bin/bash
# Prevent committing unencrypted secrets
for file in $(git diff --cached --name-only); do
    if [[ "$file" == *"secret"* ]] && [[ "$file" != *".enc" ]]; then
        echo "ERROR: Unencrypted secret file: $file"
        exit 1
    fi
done
```

## Performance Optimization

### Benchmarking

```bash
cargo bench
```

Benchmarks Argon2id key derivation and AES-256-GCM at 1 KiB, 64 KiB, and 1 MiB.

### Tips

- **Disable compression** for already-compressed files (`.zip`, `.mp4`, `.jpg`): set `compress = false` in config
- **Reduce Argon2 memory** for faster operations on constrained systems: lower `m_cost`
- **Increase streaming threshold** if you have ample RAM and want fewer disk reads
- **Parallel batch processing** with shell tools like `xargs -P` or GNU `parallel`
