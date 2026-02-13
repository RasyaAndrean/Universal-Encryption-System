# Troubleshooting Guide

## Common Issues and Solutions

### 1. Installation and Build Problems

#### Issue: Rust/Cargo not found
**Error Message:** `command not found: rustc` or `command not found: cargo`

**Solutions:**
```bash
# Install Rust using rustup (recommended)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Or install via package manager
# Ubuntu/Debian
sudo apt update && sudo apt install rustc cargo

# macOS with Homebrew
brew install rust

# Windows
# Download rustup-init.exe from https://rust-lang.org
```

#### Issue: Missing system dependencies
**Error Message:** `failed to run custom build command` or linking errors

**Solutions:**
```bash
# Ubuntu/Debian
sudo apt install build-essential pkg-config libssl-dev

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install openssl-devel

# macOS
brew install openssl
export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig"

# Windows (using vcpkg)
vcpkg install openssl:x64-windows
```

#### Issue: Compilation failures
**Error Message:** Various compilation errors

**Solutions:**
```bash
# Clean build cache
cargo clean
cargo build --release

# Update dependencies
cargo update

# Check specific error
cargo check --verbose

# Build with specific toolchain
rustup default stable
cargo build
```

### 2. Runtime Errors

#### Issue: Invalid password error
**Error Message:** `Invalid password` or `Decryption failed`

**Solutions:**
```bash
# Verify password exactly (case-sensitive)
# Check for typos or extra spaces
# Ensure same password used for encryption

# Test with a simple password first
echo "test content" > test.txt
./file-encryptor encrypt --input test.txt --output test.enc --password "Simple123!"
./file-encryptor decrypt --input test.enc --output test_decrypted.txt --password "Simple123!"

# If device binding was used, ensure same device
./file-encryptor fingerprint  # Check current fingerprint
```

#### Issue: Device binding validation failed
**Error Message:** `Device binding failed` or `Device fingerprint mismatch`

**Solutions:**
```bash
# Check current device fingerprint
./file-encryptor fingerprint

# If you need to decrypt on different device:
# Option 1: Disable device validation (less secure)
./file-encryptor decrypt --input file.encrypted --output file.txt --password "password" --no-validate-device

# Option 2: Recreate the same fingerprint (advanced)
# This requires identical hardware configuration
```

#### Issue: Signature verification failed
**Error Message:** `Signature verification failed` or `Integrity check failed`

**Solutions:**
```bash
# Verify you're using the correct public key
./file-encryptor verify --file original.txt --public-key correct_key.json --signature file.sig

# Check if file was modified after signing
# Recreate signature if file changed
./file-encryptor sign --file original.txt --private-key key.json

# Verify file integrity manually
sha256sum original.txt  # Compare with stored hash
```

#### Issue: File format errors
**Error Message:** `Invalid file format` or `Corrupted file`

**Solutions:**
```bash
# Verify file is not corrupted
file file.encrypted  # Should show it's a data file

# Check file size
ls -la file.encrypted  # Should not be 0 bytes

# Try with a fresh file
echo "test data" > fresh.txt
./file-encryptor encrypt --input fresh.txt --output fresh.enc --password "test123"
./file-encryptor decrypt --input fresh.enc --output fresh_decrypted.txt --password "test123"
```

### 3. Performance Issues

#### Issue: Slow encryption/decryption
**Problem:** Large files taking too long to process

**Solutions:**
```bash
# Check system resources
free -h  # Memory usage
df -h    # Disk space
top      # CPU usage

# For large files, consider:
# 1. Using release build instead of debug
cargo build --release

# 2. Processing in chunks
split -b 100M largefile.zip part_
for part in part_*; do
    ./file-encryptor encrypt --input "$part" --output "${part}.enc" --password "pass"
done

# 3. Using faster storage
# Move files to SSD if currently on HDD
```

#### Issue: High memory usage
**Problem:** Application consuming excessive RAM

**Solutions:**
```bash
# Monitor memory usage
ps aux | grep file-encryptor

# Process smaller batches
# Use the chunking approach shown above

# Check for memory leaks
valgrind --tool=memcheck ./file-encryptor encrypt --input file.txt --output file.enc --password "test"

# Use system monitoring
htop  # Real-time process monitoring
```

### 4. Key Management Issues

#### Issue: Lost private key
**Problem:** Cannot decrypt files without private key

**Solutions:**
```bash
# Prevention is key - always backup keys
# Create secure backups:
mkdir -p /secure/key-backups
cp *.json /secure/key-backups/
chmod 600 /secure/key-backups/*.json

# For enterprise environments:
# Use hardware security modules (HSM)
# Implement key escrow procedures
# Maintain key recovery documentation

# If key is truly lost:
# Unfortunately, files cannot be recovered without the private key
# This is by design for security
```

#### Issue: Key file corruption
**Error Message:** `Invalid key format` or `Key loading failed`

**Solutions:**
```bash
# Verify key file integrity
file key_private.json  # Should be JSON
cat key_private.json   # Should be valid JSON

# Check file permissions
ls -la key_private.json
chmod 600 key_private.json  # Private keys should be read-only

# Recreate key if backup available
cp /backup/key_private.json ./

# If no backup, generate new key pair
# Note: This won't help decrypt existing files
./file-encryptor generate-keys --name new-key
```

### 5. Platform-Specific Issues

#### Windows Issues:
```powershell
# Path issues
# Use forward slashes or escape backslashes
./file-encryptor encrypt --input "C:/path/to/file.txt" --output "C:/output/file.enc" --password "pass"

# Permission issues
# Run as administrator if needed
Start-Process PowerShell -Verb RunAs

# Antivirus interference
# Add exception for file-encryptor executable
# Temporarily disable real-time scanning for testing
```

#### macOS Issues:
```bash
# Gatekeeper restrictions
# Allow app execution:
sudo xattr -rd com.apple.quarantine /path/to/file-encryptor

# Permission dialogs
# Grant accessibility permissions in System Preferences
# Security & Privacy → Privacy → Files and Folders

# Homebrew path issues
export PATH="/opt/homebrew/bin:$PATH"
```

#### Linux Issues:
```bash
# Library path issues
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# SELinux/AppArmor restrictions
# Check audit logs
sudo ausearch -m avc -ts recent

# File system permissions
# Ensure proper ownership
sudo chown $USER:$USER /path/to/files
```

## Diagnostic Commands

### System Information Collection:
```bash
# Create diagnostic report
echo "=== File Encryptor Diagnostic Report ===" > diagnostic.txt
date >> diagnostic.txt
echo "" >> diagnostic.txt

echo "System Information:" >> diagnostic.txt
uname -a >> diagnostic.txt
echo "" >> diagnostic.txt

echo "Rust Version:" >> diagnostic.txt
rustc --version >> diagnostic.txt
cargo --version >> diagnostic.txt
echo "" >> diagnostic.txt

echo "File Encryptor Version:" >> diagnostic.txt
./file-encryptor --version 2>/dev/null || echo "Version command not available" >> diagnostic.txt
echo "" >> diagnostic.txt

echo "Device Fingerprint:" >> diagnostic.txt
./file-encryptor fingerprint 2>/dev/null || echo "Fingerprint command failed" >> diagnostic.txt
echo "" >> diagnostic.txt

echo "Test Encryption:" >> diagnostic.txt
echo "test data" > test_input.txt
./file-encryptor encrypt --input test_input.txt --output test_output.enc --password "Diagnostic123!" 2>&1 >> diagnostic.txt
echo "" >> diagnostic.txt

echo "Test Decryption:" >> diagnostic.txt
./file-encryptor decrypt --input test_output.enc --output test_decrypted.txt --password "Diagnostic123!" 2>&1 >> diagnostic.txt
echo "" >> diagnostic.txt

cat diagnostic.txt
```

### Verbose Debugging:
```bash
# Enable debug logging
export RUST_LOG=debug
./file-encryptor encrypt --input file.txt --output file.enc --password "test" --verbose

# Run with backtrace
export RUST_BACKTRACE=1
./file-encryptor encrypt --input file.txt --output file.enc --password "test"

# Memory profiling
valgrind --tool=massif ./file-encryptor encrypt --input file.txt --output file.enc --password "test"
ms_print massif.out.*
```

## Recovery Procedures

### 1. File Recovery Process:
```bash
# Step 1: Verify the encrypted file
file encrypted_file.enc
ls -la encrypted_file.enc

# Step 2: Check if it's a valid JSON format
head -n 5 encrypted_file.enc

# Step 3: Test with known good password
./file-encryptor decrypt --input encrypted_file.enc --output test_output.txt --password "known_password"

# Step 4: If device binding was used, verify fingerprint
./file-encryptor fingerprint
```

### 2. Key Recovery Process:
```bash
# Check standard backup locations
find / -name "*.json" -path "*/keys/*" 2>/dev/null

# Search for key files
locate *_private.json
locate *_public.json

# Check common backup directories
ls -la ~/backup/
ls -la /etc/file-encryptor/
ls -la ~/.config/file-encryptor/

# Verify key file integrity
for key in *.json; do
    echo "Checking $key:"
    jq . "$key" >/dev/null 2>&1 && echo "  ✓ Valid JSON" || echo "  ✗ Invalid JSON"
done
```

### 3. System Recovery:
```bash
# Reinstall the application
cargo clean
git pull  # if using version control
cargo build --release

# Restore configuration
cp /backup/.file-encryptor-config ~/.config/file-encryptor/

# Verify functionality
./file-encryptor --help
./file-encryptor generate-keys --name test-recovery
echo "test" | ./file-encryptor encrypt --input - --output test.enc --password "recovery123"
```

## Prevention Best Practices

### 1. Regular Maintenance:
```bash
# Weekly checks
# Verify key file integrity
jq . *.json >/dev/null

# Test encryption/decryption with sample files
./test_encryption.sh

# Update dependencies
cargo update
cargo audit
```

### 2. Backup Procedures:
```bash
# Automated backup script
#!/bin/bash
BACKUP_DIR="/secure/backups/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup keys
cp *.json "$BACKUP_DIR/"
chmod 600 "$BACKUP_DIR"/*.json

# Backup important encrypted files
cp important_files/*.enc "$BACKUP_DIR/"

# Create backup verification
sha256sum "$BACKUP_DIR"/* > "$BACKUP_DIR/checksums.txt"

# Encrypt backup
./file-encryptor encrypt --input "$BACKUP_DIR" --output "${BACKUP_DIR}.backup.enc" --password "BackupPassword123!"
```

### 3. Monitoring Setup:
```bash
# Create monitoring script
#!/bin/bash
# monitor_encryption.sh

LOG_FILE="/var/log/file-encryptor/monitor.log"
ALERT_EMAIL="admin@company.com"

# Check for failed operations
if grep -q "ERROR\|FAILED" "$LOG_FILE"; then
    # Send alert
    echo "File Encryptor errors detected" | mail -s "Security Alert" "$ALERT_EMAIL"
fi

# Check disk space
if [ $(df / | awk 'NR==2 {print $5}' | sed 's/%//') -gt 90 ]; then
    echo "Low disk space warning" | mail -s "System Alert" "$ALERT_EMAIL"
fi
```

## Support Information

### When to Seek Help:
- After trying all troubleshooting steps above
- For security-related concerns
- Enterprise deployment issues
- Custom integration problems

### Information to Provide:
```bash
# System information
uname -a
rustc --version
./file-encryptor --version

# Error details
# Exact error message
# Steps to reproduce
# Sample files (if possible)

# Diagnostic output
./diagnostic_script.sh > diagnostic_output.txt
```

This troubleshooting guide covers the most common issues users encounter with the File Encryptor system and provides systematic approaches to diagnosis and resolution.