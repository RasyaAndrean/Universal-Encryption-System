#!/bin/bash
# Example usage script for file-encryptor

echo "=== File Encryptor Demo Script ==="
echo

# Create test directory
mkdir -p demo_files
cd demo_files

echo "1. Creating test files..."
echo "This is a confidential business document" > business_doc.txt
echo "Personal financial records and passwords" > personal_data.txt
echo "Company strategic plans for 2024" > strategic_plan.txt

echo "Test files created:"
ls -la *.txt
echo

echo "2. Generating key pairs..."
../target/release/file-encryptor generate-keys --name demo
echo "Keys generated:"
ls -la *.json
echo

echo "3. Checking device fingerprint..."
DEVICE_FINGERPRINT=$(../target/release/file-encryptor fingerprint)
echo "Device fingerprint: $DEVICE_FINGERPRINT"
echo

echo "4. Demonstrating basic encryption..."
../target/release/file-encryptor encrypt \
  --input business_doc.txt \
  --output business_doc.encrypted \
  --password "DemoP@ss123!" \
  --private-key demo_private.json

echo "5. Demonstrating device-bound encryption..."
../target/release/file-encryptor encrypt \
  --input personal_data.txt \
  --output personal_data.encrypted \
  --password "DeviceBoundP@ss123!" \
  --bind-device \
  --private-key demo_private.json

echo "6. Demonstrating signature-only operation..."
../target/release/file-encryptor sign \
  --file strategic_plan.txt \
  --private-key demo_private.json

echo "7. Verifying signatures..."
../target/release/file-encryptor verify \
  --file strategic_plan.txt \
  --public-key demo_public.json \
  --signature strategic_plan.txt.sig

echo
echo "8. Testing decryption..."
../target/release/file-encryptor decrypt \
  --input business_doc.encrypted \
  --output business_doc_decrypted.txt \
  --password "DemoP@ss123!" \
  --public-key demo_public.json

echo "9. Testing device-bound decryption..."
../target_release/file-encryptor decrypt \
  --input personal_data.encrypted \
  --output personal_data_decrypted.txt \
  --password "DeviceBoundP@ss123!" \
  --validate-device \
  --public-key demo_public.json

echo
echo "=== Demo Complete ==="
echo
echo "Created encrypted files:"
ls -la *.encrypted *.sig
echo
echo "Decrypted verification files:"
ls -la *_decrypted.txt
echo
echo "Security features demonstrated:"
echo "- Password-based encryption (Argon2 + AES-256-GCM)"
echo "- Digital signatures (Ed25519)"
echo "- Device binding and validation"
echo "- File integrity protection"
echo "- Anti-tamper verification"