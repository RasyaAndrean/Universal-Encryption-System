# Advanced Usage Guide

## Professional Security Configurations

### Enterprise Deployment Scenarios

#### 1. Multi-User Environment Setup
```bash
# Create secure user group
sudo groupadd file-encryptor-users
sudo usermod -a -G file-encryptor-users username

# Set up secure key storage directory
sudo mkdir -p /etc/file-encryptor/keys
sudo chown root:file-encryptor-users /etc/file-encryptor/keys
sudo chmod 750 /etc/file-encryptor/keys

# Create user-specific key directories
sudo mkdir /etc/file-encryptor/keys/user1
sudo mkdir /etc/file-encryptor/keys/user2
sudo chown user1:file-encryptor-users /etc/file-encryptor/keys/user1
sudo chown user2:file-encryptor-users /etc/file-encryptor/keys/user2
```

#### 2. Centralized Key Management
```bash
# Generate master key pair for organization
./file-encryptor generate-keys --output-dir /etc/file-encryptor/master --name org-master

# Create department-specific keys
./file-encryptor generate-keys --output-dir /etc/file-encryptor/departments/finance --name finance
./file-encryptor generate-keys --output-dir /etc/file-encryptor/departments/hr --name hr

# Set appropriate permissions
sudo chown -R root:file-encryptor-admins /etc/file-encryptor/master
sudo chmod -R 600 /etc/file-encryptor/master
sudo chmod -R 640 /etc/file-encryptor/departments
```

### High-Security Configurations

#### 1. Air-Gapped System Setup
```bash
# On air-gapped system
# Generate keys offline
./file-encryptor generate-keys --output-dir /secure/keys --name offline-system

# Encrypt sensitive files
./file-encryptor encrypt \
  --input /sensitive/data.confidential \
  --output /encrypted/data.confidential.enc \
  --password "OfflineSystemP@ss2023!" \
  --bind-device \
  --private-key /secure/keys/offline-system_private.json

# Verify encryption
./file-encryptor verify \
  --file /sensitive/data.confidential \
  --public-key /secure/keys/offline-system_public.json \
  --signature /sensitive/data.confidential.sig
```

#### 2. Hardware Security Module Integration
```bash
# Using HSM for key generation (conceptual example)
# This would require HSM-specific libraries and configuration

# Generate key on HSM
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --keypairgen --key-type rsa:2048 \
  --label "file-encryptor-key"

# Export public key for verification
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --read-object --type pubkey \
  --label "file-encryptor-key" > public_key.pem
```

## Automation and Scripting

### 1. Batch Processing Scripts

#### PowerShell Script (Windows):
```powershell
# batch_encrypt.ps1
param(
    [string]$InputDirectory,
    [string]$OutputDirectory,
    [string]$Password,
    [string]$KeyFile
)

Get-ChildItem -Path $InputDirectory -File | ForEach-Object {
    $inputFile = $_.FullName
    $outputFile = Join-Path $OutputDirectory "$($_.BaseName).encrypted"
    
    Write-Host "Encrypting: $inputFile"
    ./file-encryptor encrypt `
        --input $inputFile `
        --output $outputFile `
        --password $Password `
        --private-key $KeyFile
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Successfully encrypted: $($_.Name)"
    } else {
        Write-Error "✗ Failed to encrypt: $($_.Name)"
    }
}
```

#### Bash Script (Linux/macOS):
```bash
#!/bin/bash
# batch_encrypt.sh

INPUT_DIR="$1"
OUTPUT_DIR="$2"
PASSWORD="$3"
KEY_FILE="$4"

if [ $# -ne 4 ]; then
    echo "Usage: $0 <input_dir> <output_dir> <password> <key_file>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

find "$INPUT_DIR" -type f -not -name "*.encrypted" | while read -r file; do
    filename=$(basename "$file")
    output_file="$OUTPUT_DIR/${filename}.encrypted"
    
    echo "Encrypting: $filename"
    ./file-encryptor encrypt \
        --input "$file" \
        --output "$output_file" \
        --password "$PASSWORD" \
        --private-key "$KEY_FILE"
    
    if [ $? -eq 0 ]; then
        echo "✓ Successfully encrypted: $filename"
    else
        echo "✗ Failed to encrypt: $filename"
    fi
done
```

### 2. Automated Backup System

#### Backup Script with Rotation:
```bash
#!/bin/bash
# secure_backup.sh

SOURCE_DIR="/important/data"
BACKUP_DIR="/secure/backups"
PASSWORD="BackupP@ss2023!"
KEY_FILE="/secure/keys/backup_key.json"
RETENTION_DAYS=30

# Create timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_NAME="backup_$TIMESTAMP"

# Create backup archive
tar -czf "/tmp/${BACKUP_NAME}.tar.gz" -C "$SOURCE_DIR" .

# Encrypt backup
./file-encryptor encrypt \
    --input "/tmp/${BACKUP_NAME}.tar.gz" \
    --output "$BACKUP_DIR/${BACKUP_NAME}.encrypted" \
    --password "$PASSWORD" \
    --private-key "$KEY_FILE"

# Clean up temporary file
rm "/tmp/${BACKUP_NAME}.tar.gz"

# Sign backup for integrity verification
./file-encryptor sign \
    --file "$BACKUP_DIR/${BACKUP_NAME}.encrypted" \
    --private-key "$KEY_FILE"

# Remove old backups
find "$BACKUP_DIR" -name "backup_*.encrypted" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR" -name "backup_*.encrypted.sig" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $BACKUP_NAME"
```

### 3. Continuous Monitoring Script

#### File Integrity Monitor:
```python
#!/usr/bin/env python3
# file_monitor.py

import os
import sys
import hashlib
import json
import subprocess
from pathlib import Path
from datetime import datetime

class FileMonitor:
    def __init__(self, config_file="monitor_config.json"):
        self.config_file = config_file
        self.load_config()
        
    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = {
                "watched_directories": [],
                "baseline_file": "baseline.json",
                "alert_script": "/path/to/alert.sh"
            }
    
    def create_baseline(self):
        """Create baseline hash signatures for all files"""
        baseline = {}
        
        for directory in self.config["watched_directories"]:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    filepath = os.path.join(root, file)
                    if os.path.isfile(filepath):
                        file_hash = self.calculate_hash(filepath)
                        baseline[filepath] = {
                            "hash": file_hash,
                            "mtime": os.path.getmtime(filepath),
                            "size": os.path.getsize(filepath)
                        }
        
        with open(self.config["baseline_file"], 'w') as f:
            json.dump(baseline, f, indent=2)
        
        print(f"Baseline created with {len(baseline)} files")
    
    def calculate_hash(self, filepath):
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def check_integrity(self):
        """Check file integrity against baseline"""
        if not os.path.exists(self.config["baseline_file"]):
            print("No baseline found. Creating baseline first.")
            self.create_baseline()
            return
        
        with open(self.config["baseline_file"], 'r') as f:
            baseline = json.load(f)
        
        alerts = []
        
        for filepath, baseline_info in baseline.items():
            if not os.path.exists(filepath):
                alerts.append(f"File missing: {filepath}")
                continue
            
            current_hash = self.calculate_hash(filepath)
            current_mtime = os.path.getmtime(filepath)
            current_size = os.path.getsize(filepath)
            
            if current_hash != baseline_info["hash"]:
                alerts.append(f"File modified: {filepath}")
            elif current_mtime != baseline_info["mtime"]:
                alerts.append(f"File timestamp changed: {filepath}")
            elif current_size != baseline_info["size"]:
                alerts.append(f"File size changed: {filepath}")
        
        if alerts:
            self.send_alerts(alerts)
        else:
            print("All files integrity verified")
    
    def send_alerts(self, alerts):
        """Send alerts via configured method"""
        alert_text = "\n".join(alerts)
        timestamp = datetime.now().isoformat()
        
        # Log alerts
        with open("security_alerts.log", "a") as f:
            f.write(f"[{timestamp}] {alert_text}\n")
        
        # Execute alert script if configured
        if self.config["alert_script"] and os.path.exists(self.config["alert_script"]):
            try:
                subprocess.run([self.config["alert_script"], alert_text], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Alert script failed: {e}")

# Usage
if __name__ == "__main__":
    monitor = FileMonitor()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "baseline":
            monitor.create_baseline()
        elif sys.argv[1] == "check":
            monitor.check_integrity()
    else:
        print("Usage: python3 file_monitor.py [baseline|check]")
```

## Integration Examples

### 1. Git Pre-commit Hook
```bash
#!/bin/bash
# .git/hooks/pre-commit

# Check if file-encryptor is available
if ! command -v file-encryptor &> /dev/null; then
    echo "file-encryptor not found. Please install it first."
    exit 1
fi

# Configuration
KEY_FILE="/secure/git-signing-key.json"
PASSWORD="GitCommitP@ss2023!"

# Get list of files to be committed
FILES=$(git diff --cached --name-only --diff-filter=ACM)

for file in $FILES; do
    if [[ "$file" == *.sensitive ]] || [[ "$file" == *.confidential ]]; then
        echo "Encrypting sensitive file: $file"
        
        # Encrypt the file
        file-encryptor encrypt \
            --input "$file" \
            --output "${file}.encrypted" \
            --password "$PASSWORD" \
            --private-key "$KEY_FILE"
        
        # Remove original from commit
        git rm --cached "$file"
        
        # Add encrypted version
        git add "${file}.encrypted"
        
        echo "✓ File encrypted and staged: ${file}.encrypted"
    fi
done
```

### 2. Systemd Service for Automated Tasks
```ini
# /etc/systemd/system/file-encryptor-backup.service
[Unit]
Description=File Encryptor Automated Backup
After=network.target

[Service]
Type=oneshot
User=backup-user
Group=backup-group
ExecStart=/usr/local/bin/secure_backup.sh
WorkingDirectory=/home/backup-user

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/file-encryptor-backup.timer
[Unit]
Description=Run File Encryptor Backup Daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Enable the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable file-encryptor-backup.timer
sudo systemctl start file-encryptor-backup.timer
```

### 3. Web API Integration
```python
# api_server.py
from flask import Flask, request, jsonify
import subprocess
import tempfile
import os

app = Flask(__name__)

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    password = request.form.get('password')
    bind_device = request.form.get('bind_device', 'false').lower() == 'true'
    
    if not password:
        return jsonify({'error': 'Password required'}), 400
    
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False) as temp_input:
        file.save(temp_input.name)
        input_path = temp_input.name
    
    output_path = input_path + '.encrypted'
    
    try:
        # Build command
        cmd = [
            './file-encryptor', 'encrypt',
            '--input', input_path,
            '--output', output_path,
            '--password', password
        ]
        
        if bind_device:
            cmd.append('--bind-device')
        
        # Execute encryption
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Read encrypted file
            with open(output_path, 'rb') as f:
                encrypted_data = f.read()
            
            return jsonify({
                'status': 'success',
                'message': 'File encrypted successfully',
                'data': encrypted_data.hex()
            })
        else:
            return jsonify({
                'error': 'Encryption failed',
                'details': result.stderr
            }), 500
            
    finally:
        # Cleanup temporary files
        for path in [input_path, output_path]:
            if os.path.exists(path):
                os.unlink(path)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
```

## Performance Optimization

### 1. Parallel Processing
```bash
# Using GNU parallel for batch encryption
find /large/directory -type f -not -name "*.encrypted" | \
parallel -j 4 ./file-encryptor encrypt \
  --input {} \
  --output {}.encrypted \
  --password "BatchP@ss2023!" \
  --private-key /secure/batch_key.json
```

### 2. Memory-Efficient Processing
```bash
# For very large files, process in chunks
split -b 100M large_file.zip large_file_part_
for part in large_file_part_*; do
    ./file-encryptor encrypt \
      --input "$part" \
      --output "${part}.encrypted" \
      --password "LargeFileP@ss2023!" \
      --private-key /secure/large_file_key.json
done
cat large_file_part_*.encrypted > large_file.zip.encrypted
rm large_file_part_*
```

## Compliance and Auditing

### 1. Audit Trail Generator
```bash
#!/bin/bash
# audit_trail.sh

LOG_FILE="/var/log/file-encryptor/audit.log"
KEY_FILE="/secure/audit_key.json"
PASSWORD="AuditP@ss2023!"

# Create log entry
log_action() {
    local action="$1"
    local file="$2"
    local user="${3:-$(whoami)}"
    local timestamp=$(date -Iseconds)
    
    echo "[$timestamp] USER:$user ACTION:$action FILE:$file" >> "$LOG_FILE"
    
    # Create signed log entry
    echo "[$timestamp] USER:$user ACTION:$action FILE:$file" | \
    ./file-encryptor sign \
        --private-key "$KEY_FILE" \
        --output "/var/log/file-encryptor/signatures/$(date +%s).sig"
}

# Example usage in scripts
encrypt_with_audit() {
    local input_file="$1"
    local output_file="$2"
    
    log_action "ENCRYPT_START" "$input_file"
    
    ./file-encryptor encrypt \
        --input "$input_file" \
        --output "$output_file" \
        --password "$PASSWORD" \
        --private-key "$KEY_FILE"
    
    if [ $? -eq 0 ]; then
        log_action "ENCRYPT_SUCCESS" "$input_file"
    else
        log_action "ENCRYPT_FAILED" "$input_file"
        return 1
    fi
}
```

### 2. Compliance Report Generator
```python
#!/usr/bin/env python3
# compliance_report.py

import json
import os
from datetime import datetime, timedelta

class ComplianceReporter:
    def __init__(self, log_directory="/var/log/file-encryptor"):
        self.log_directory = log_directory
        self.audit_log = os.path.join(log_directory, "audit.log")
        self.report_dir = os.path.join(log_directory, "reports")
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate_monthly_report(self):
        """Generate compliance report for the current month"""
        now = datetime.now()
        start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        if now.month == 1:
            end_date = now.replace(year=now.year-1, month=12, day=31, 
                                 hour=23, minute=59, second=59)
        else:
            end_date = now.replace(month=now.month-1, day=1) - timedelta(days=1)
            end_date = end_date.replace(hour=23, minute=59, second=59)
        
        # Parse log entries
        entries = self.parse_logs(start_date, end_date)
        
        # Generate report
        report = {
            "report_period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "summary": self.generate_summary(entries),
            "detailed_entries": entries,
            "compliance_check": self.check_compliance(entries)
        }
        
        # Save report
        report_filename = f"compliance_report_{now.strftime('%Y%m')}.json"
        report_path = os.path.join(self.report_dir, report_filename)
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate human-readable version
        self.generate_text_report(report, report_filename.replace('.json', '.txt'))
        
        return report_path
    
    def parse_logs(self, start_date, end_date):
        """Parse audit log entries within date range"""
        entries = []
        
        if not os.path.exists(self.audit_log):
            return entries
        
        with open(self.audit_log, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        # Parse log format: [timestamp] USER:user ACTION:action FILE:file
                        parts = line.strip().split(' ', 3)
                        if len(parts) >= 4:
                            timestamp_str = parts[0][1:-1]  # Remove brackets
                            timestamp = datetime.fromisoformat(timestamp_str)
                            
                            if start_date <= timestamp <= end_date:
                                user_part = parts[1]
                                action_part = parts[2]
                                file_part = parts[3]
                                
                                entry = {
                                    "timestamp": timestamp.isoformat(),
                                    "user": user_part.split(':')[1],
                                    "action": action_part.split(':')[1],
                                    "file": file_part.split(':')[1]
                                }
                                entries.append(entry)
                    except (ValueError, IndexError):
                        continue
        
        return entries
    
    def generate_summary(self, entries):
        """Generate summary statistics"""
        actions = {}
        users = {}
        files = {}
        
        for entry in entries:
            action = entry["action"]
            user = entry["user"]
            file = entry["file"]
            
            actions[action] = actions.get(action, 0) + 1
            users[user] = users.get(user, 0) + 1
            files[file] = files.get(file, 0) + 1
        
        return {
            "total_operations": len(entries),
            "action_breakdown": actions,
            "user_activity": users,
            "file_operations": len(files)
        }
    
    def check_compliance(self, entries):
        """Check compliance against security policies"""
        issues = []
        
        # Check for failed operations
        failed_ops = [e for e in entries if "FAILED" in e["action"]]
        if failed_ops:
            issues.append({
                "type": "FAILED_OPERATIONS",
                "count": len(failed_ops),
                "description": f"Found {len(failed_ops)} failed operations"
            })
        
        # Check for unauthorized users (example policy)
        authorized_users = {"admin", "backup-user", "security-audit"}
        unauthorized_users = set(e["user"] for e in entries) - authorized_users
        if unauthorized_users:
            issues.append({
                "type": "UNAUTHORIZED_ACCESS",
                "users": list(unauthorized_users),
                "description": f"Unauthorized users detected: {', '.join(unauthorized_users)}"
            })
        
        return {
            "compliant": len(issues) == 0,
            "issues": issues
        }
    
    def generate_text_report(self, report, filename):
        """Generate human-readable text report"""
        text_path = os.path.join(self.report_dir, filename)
        
        with open(text_path, 'w') as f:
            f.write("FILE ENCRYPTOR COMPLIANCE REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            period = report["report_period"]
            f.write(f"Reporting Period: {period['start']} to {period['end']}\n\n")
            
            summary = report["summary"]
            f.write("SUMMARY\n")
            f.write("-" * 20 + "\n")
            f.write(f"Total Operations: {summary['total_operations']}\n")
            f.write(f"Files Processed: {summary['file_operations']}\n\n")
            
            f.write("ACTION BREAKDOWN\n")
            f.write("-" * 20 + "\n")
            for action, count in summary["action_breakdown"].items():
                f.write(f"{action}: {count}\n")
            
            compliance = report["compliance_check"]
            f.write(f"\nCOMPLIANCE STATUS: {'PASS' if compliance['compliant'] else 'FAIL'}\n")
            if not compliance['compliant']:
                f.write("Issues Found:\n")
                for issue in compliance['issues']:
                    f.write(f"- {issue['description']}\n")

# Usage
if __name__ == "__main__":
    reporter = ComplianceReporter()
    report_path = reporter.generate_monthly_report()
    print(f"Compliance report generated: {report_path}")
```

This advanced usage guide provides professional-level configurations, automation scripts, and integration examples for enterprise deployment and sophisticated security workflows.