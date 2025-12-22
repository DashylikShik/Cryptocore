# CryptoCore User Guide

## Quick Start

### Installation
```bash
# Clone repository
git clone https://github.com/Dashylikjopka/Cryptocore.git
cd cryptocore

# Install dependencies
pip install -r requirements.txt

Basic Commands
1. File Encryption

# Encrypt file with AES-256 CBC
python src/main.py encrypt --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input plain.txt --output encrypted.bin

# Decrypt file
python src/main.py encrypt --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input encrypted.bin --output decrypted.txt
2. File Hashing

# SHA-256 hash
python src/main.py dgst --algorithm sha256 --input document.pdf

# SHA3-256 hash with output file
python src/main.py dgst --algorithm sha3-256 --input backup.tar --output backup.sha3
3. HMAC (Message Authentication)

# Generate HMAC
python src/main.py dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff --input message.txt

# Verify HMAC
python src/main.py dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input message.txt --verify hmac.txt
4. Key Derivation (PBKDF2)

# Derive key from password
python src/main.py derive --password "MyPassword123" \
  --salt 1234567890abcdef --iterations 100000 --length 32
5. GCM Authenticated Encryption

# Encrypt with authentication
python src/main.py encrypt --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input data.txt --output encrypted.bin --aad metadata123

# Decrypt with authentication check
python src/main.py encrypt --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input encrypted.bin --output decrypted.txt --aad metadata123
Command Reference
Encryption/Decryption

python src/main.py encrypt
  --algorithm aes
  --mode [ecb|cbc|cfb|ofb|ctr|gcm]
  --encrypt|--decrypt
  --key HEX_STRING
  --input FILE
  --output FILE
  [--iv HEX_STRING]    # For modes requiring IV
  [--aad HEX_STRING]   # For GCM mode only
Hashing

python src/main.py dgst
  --algorithm [sha256|sha3-256]
  --input FILE
  [--output FILE]
  [--hmac]             # Enable HMAC mode
  [--key HEX_STRING]   # Required for HMAC
  [--verify FILE]      # Verify against stored hash
Key Derivation

python src/main.py derive
  --password STRING
  [--salt HEX_STRING]  # Auto-generated if not provided
  [--iterations N]     # Default: 100000
  [--length N]         # Default: 32 bytes
  [--output FILE]
Comparison with Other Tools
CryptoCore vs OpenSSL
Operation	CryptoCore	OpenSSL Equivalent
AES-256 CBC Encryption	python src/main.py encrypt --algorithm aes --mode cbc --encrypt --key <hex> --input file	openssl enc -aes-256-cbc -K <key> -iv <iv> -in file -out file.enc
SHA-256 Hash	python src/main.py dgst --algorithm sha256 --input file	openssl dgst -sha256 file
HMAC-SHA256	python src/main.py dgst --algorithm sha256 --hmac --key <key> --input file	openssl dgst -sha256 -hmac <key> file
PBKDF2 Key Derivation	python src/main.py derive --password "pwd" --salt <salt> --iterations 100000	openssl kdf -keylen 32 -kdfopt pass:"pwd" -kdfopt salt:<salt> -kdfopt iter:100000 PBKDF2
GCM Encryption	python src/main.py encrypt --algorithm aes --mode gcm --encrypt --key <key> --aad <data>	openssl enc -aes-256-gcm -K <key> -iv <iv> -aad <data> -in file
CryptoCore vs GPG
Feature	CryptoCore	GPG (GnuPG)
Symmetric Encryption	✅ AES-256, all modes	✅ AES, Twofish, etc.
Asymmetric Encryption	❌ Not supported	✅ RSA, ECC, etc.
Digital Signatures	❌ Not supported	✅ Full support
Key Management	Basic (password/key files)	Advanced (keyring, web of trust)
File Formats	Custom binary format	Standard OpenPGP format
Command Simplicity	Simple, focused commands	Complex, many options
When to Use Which Tool
Use CryptoCore when:

You need lightweight symmetric encryption

You want to avoid complex dependencies

You need a simple, focused tool

You're working in Python environments

You want educational/transparent implementation

Use OpenSSL when:

You need industry-standard compatibility

You require asymmetric cryptography

You need certificate management

You're integrating with existing systems

You need maximum performance

Use GPG when:

You need email encryption/signing

You want OpenPGP compatibility

You need key management with web of trust

You're encrypting for multiple recipients

Cheat Sheet (Quick Reference)
Essential Commands
Encryption
bash
# Auto-generate key
python src/main.py encrypt --algorithm aes --mode gcm --encrypt --input file.txt --output file.enc

# With specific key
python src/main.py encrypt --algorithm aes --mode cbc --encrypt --key $(head -c 32 /dev/urandom | xxd -p) --input data.bin

# With IV
python src/main.py encrypt --algorithm aes --mode ctr --encrypt --key <key> --iv $(head -c 16 /dev/urandom | xxd -p) --input file
Hashing
bash
# Quick hash check
python src/main.py dgst --algorithm sha256 --input downloaded_file.iso

# Save hash
python src/main.py dgst --algorithm sha3-256 --input backup.tar.gz --output backup.sha3
HMAC
bash
# Generate and save
python src/main.py dgst --algorithm sha256 --hmac --key <secret> --input message.txt --output message.hmac

# Quick verify
python src/main.py dgst --algorithm sha256 --hmac --key <secret> --input message.txt --verify message.hmac
Key Management
bash
# Generate strong key from password
python src/main.py derive --password "$(pwgen 20 1)" --salt $(head -c 16 /dev/urandom | xxd -p) --iterations 210000

# Save to file
python src/main.py derive --password "MyPass" --output keyfile.bin
Common Key Lengths (Hex Format)
Algorithm	Hex Length	Bytes	Example
AES-128	32 chars	16	00112233445566778899aabbccddeeff
AES-192	48 chars	24	00112233445566778899aabbccddeeff0011223344556677
AES-256	64 chars	32	00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
IV	32 chars	16	aabbccddeeff00112233445566778899
SHA-256	64 chars	32	e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Mode Selection Guide
Mode	Confidentiality	Integrity	Use Case
ECB	✅	❌	Never use for real data - testing only
CBC	✅	❌	Legacy systems, with HMAC
CFB	✅	❌	Streaming, with HMAC
OFB	✅	❌	Streaming, with HMAC
CTR	✅	❌	Parallel encryption, with HMAC
GCM	✅	✅	Recommended - modern applications
One-Liners for Common Tasks

# Encrypt with random key (shows key)
python src/main.py encrypt --algorithm aes --mode gcm --encrypt --input secret.txt

# Verify file hasn't changed
python src/main.py dgst --algorithm sha256 --input important.doc --verify important.doc.sha256

# Create password-protected backup
echo -n "Enter password: " && read PASS && python src/main.py derive --password "$PASS" --iterations 210000 | python src/main.py encrypt --algorithm aes --mode gcm --encrypt --key-stdin --input data.tar

# Batch process files
for file in *.txt; do python src/main.py encrypt --algorithm aes --mode gcm --encrypt --input "$file" --output "${file}.enc"; done

# Check multiple hashes
for file in *; do python src/main.py dgst --algorithm sha256 --input "$file" >> checksums.txt; done
Examples Directory
See examples/ folder for complete working examples:

examples/backup_script.py - Automated backup encryption

examples/file_integrity.py - File integrity monitoring

examples/password_manager.py - Simple password manager

examples/secure_archive.py - Create encrypted archives

Troubleshooting
Common Issues
"Invalid key length"

Key must be 16, 24, or 32 bytes in hex (32, 48, or 64 hex characters)

Example valid key: 00112233445566778899aabbccddeeff (32 chars = 16 bytes)

"File not found"

Check file path and permissions

Use absolute paths if needed: --input /home/user/file.txt

"Authentication failed" (GCM)

Wrong AAD (Additional Authenticated Data)

Tampered ciphertext

Wrong key used for decryption

Ensure AAD is exactly the same for encryption and decryption

"HMAC verification failed"

File has been modified

Wrong HMAC key

Corrupted HMAC file

"IV required for this mode"

CBC, CFB, OFB, CTR modes require IV

Either provide with --iv or let it auto-generate

Debug Mode
Add --verbose flag for detailed output:


python src/main.py encrypt --algorithm aes --mode gcm --encrypt --input test.txt --verbose
Performance Tips
Large Files: CryptoCore automatically uses chunk processing (1MB chunks)

PBKDF2: >100,000 iterations can be slow - adjust based on security needs

SHA3-256: Slower than SHA-256 but more secure against certain attacks

GCM: Fastest authenticated mode, recommended for most use cases

Memory: Processing doesn't load entire file into memory

Best Practices
Always use GCM for file encryption (provides both confidentiality and integrity)

Never use ECB for real data (only for testing/education)

Generate random IVs for each encryption operation

Use strong passwords for PBKDF2 (minimum 12 characters, mixed)

Verify hashes of downloaded/transferred files

Store keys securely - never commit to version control

Rotate keys periodically for sensitive data

Test decryption after encryption to ensure it works

Security Considerations
Key Management
Generate keys with python src/main.py derive or external CSPRNG

Store keys in secure key management systems

Never hardcode keys in source code

Use different keys for different purposes

Algorithm Choices
Recommended: AES-256-GCM for encryption

Recommended: SHA3-256 for hashing

Recommended: 210,000+ iterations for PBKDF2

Avoid: ECB mode for anything but testing

Avoid: SHA-1, MD5 (deprecated)

Operational Security
Clear sensitive data from memory after use

Use secure deletion for temporary files

Implement access controls for encrypted data

Regular security audits of your implementation

Getting Help
Check python src/main.py --help for command reference

Review examples in examples/ directory

See docs/API.md for developer documentation

File issues on GitHub

Contributing
See CONTRIBUTING.md for guidelines on contributing to CryptoCore.

Security Issues
Please report security vulnerabilities according to SECURITY.md.