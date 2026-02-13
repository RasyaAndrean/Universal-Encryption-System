# Quick Start Guide

## Getting Started in 5 Minutes

### Step 1: Generate Your Keys
```bash
./file-encryptor generate-keys
```
This creates `key_private.json` and `key_public.json` in your current directory.

### Step 2: Check Your Device Fingerprint
```bash
./file-encryptor fingerprint
```
Save this fingerprint for reference.

### Step 3: Create a Test File
```bash
echo "This is my secret document" > secret.txt
```

### Step 4: Encrypt with Maximum Security
```bash
./file-encryptor encrypt \
  --input secret.txt \
  --output secret.encrypted \
  --password "MyV3ryStr0ngP@ssw0rd!" \
  --bind-device \
  --private-key key_private.json
```

### Step 5: Verify Encryption Worked
```bash
./file-encryptor decrypt \
  --input secret.encrypted \
  --output secret_decrypted.txt \
  --password "MyV3ryStr0ngP@ssw0rd!" \
  --validate-device \
  --public-key key_public.json

cat secret_decrypted.txt
```

## Common Use Cases

### 🔒 Personal File Encryption
```bash
# Encrypt personal documents
./file-encryptor encrypt --input finances.xlsx --output finances.enc --password "MySecurePassword123!"

# Decrypt when needed
./file-encryptor decrypt --input finances.enc --output finances.xlsx --password "MySecurePassword123!"
```

### 🏢 Business Document Protection
```bash
# Generate company key pair
./file-encryptor generate-keys --name company

# Encrypt sensitive business files
./file-encryptor encrypt \
  --input confidential_report.pdf \
  --output confidential_report.enc \
  --password "CompanySecret2023!" \
  --private-key company_private.json

# Verify authenticity
./file-encryptor verify \
  --file confidential_report.pdf \
  --public-key company_public.json \
  --signature confidential_report.pdf.sig
```

### 💾 Device-Specific Encryption
```bash
# Encrypt files that only work on your laptop
./file-encryptor encrypt \
  --input personal_notes.txt \
  --output personal_notes.enc \
  --password "MyDeviceOnlyPass123!" \
  --bind-device

# This file won't decrypt on other devices!
```

### 📱 Mobile Backup Security
```bash
# Create encrypted backup
./file-encryptor encrypt \
  --input backup.zip \
  --output backup.enc \
  --password "BackupPass2023!" \
  --private-key backup_key.json

# Store encrypted backup safely
# Only you can decrypt it with your password and key
```

## Security Checklist

Before using in production:

- [ ] Generated strong key pairs
- [ ] Tested encryption/decryption workflow
- [ ] Verified device fingerprint consistency
- [ ] Backed up private keys securely
- [ ] Tested password recovery process
- [ ] Understood device binding implications
- [ ] Validated signature verification works

## Troubleshooting Quick Reference

| Problem | Solution |
|---------|----------|
| "Invalid password" | Double-check password exactly, including case |
| "Device binding failed" | File encrypted on different device |
| "Signature verification failed" | File was modified or wrong public key |
| "Rate limit exceeded" | Wait 1 minute and try again |
| "File integrity check failed" | File was corrupted or tampered with |

## Next Steps

1. **Read the full documentation** in README.md
2. **Run the test suite**: `cargo test`
3. **Experiment with different security levels**
4. **Set up key backup procedures**
5. **Test cross-device scenarios**

## Need Help?

- Check the detailed README.md
- Run `./file-encryptor --help` for command reference
- Review the examples in the documentation
- Run integration tests to verify setup