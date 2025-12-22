
```markdown
# CryptoCore Development Guide

## Project Structure
cryptocore/
├── src/ # Source code
│ ├── hash/ # Hash functions (SHA-256, SHA3-256)
│ ├── kdf/ # Key derivation (PBKDF2, HKDF)
│ ├── mac/ # Message authentication (HMAC)
│ ├── modes/ # Encryption modes (CBC, CTR, GCM, etc.)
│ ├── aes.py # AES core implementation
│ ├── csprng.py # Cryptographically secure RNG
│ ├── file_io.py # File input/output utilities
│ └── main.py # Command-line interface
├── tests/ # Test suite
│ ├── unit/ # Unit tests
│ ├── integration/ # Integration tests
│ ├── vectors/ # Test vectors
│ └── run_tests.py # Test runner
└── docs/ # Documentation

text

## Development Setup

### 1. Clone and Install
```bash
git clone https://github.com/Dashylikjopka/Cryptocore.git
cd cryptocore
pip install -r requirements.txt
2. Run Tests
bash
# Run all tests
python tests/run_tests.py

# Run specific test module
python -m pytest tests/unit/test_hash.py -v

# Check test coverage
pip install pytest-cov
pytest --cov=src --cov-report=html
3. Code Style
Follow PEP 8

Use meaningful variable names

Add docstrings to all public functions

Write unit tests for new functionality

Adding New Features
1. New Hash Algorithm
Create src/hash/new_hash.py

Implement the hash class with update() and digest() methods

Add to CLI in src/main.py

Write tests in tests/unit/test_new_hash.py

Update documentation

2. New Encryption Mode
Create src/modes/new_mode.py

Implement encrypt() and decrypt() functions

Add to mode selection in src/main.py

Write interoperability tests with OpenSSL

Update user guide

Testing Strategy
Unit Tests
Test individual functions

Use known test vectors (NIST, RFC)

Test edge cases (empty files, large files)

Integration Tests
Test CLI commands end-to-end

Test file I/O operations

Test interoperability with OpenSSL

Security Tests
Test random number generation

Test key/IV uniqueness

Test authentication failures

Dependencies
pycryptodome>=3.19.0 - For AES primitives

Python 3.7+

Versioning
Use semantic versioning: MAJOR.MINOR.PATCH

MAJOR: Breaking changes

MINOR: New features, backwards compatible

PATCH: Bug fixes