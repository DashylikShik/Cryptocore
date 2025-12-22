markdown
# CryptoCore API Documentation

## Overview
CryptoCore provides cryptographic functions for encryption, hashing, and key derivation.

## Modules

### `src.aes` - AES Encryption
```python
from src.aes import encrypt_block, decrypt_block

# encrypt_block(key: bytes, plaintext: bytes) -> bytes
# decrypt_block(key: bytes, ciphertext: bytes) -> bytes

src.modes - Encryption Modes

from src.modes import ecb, cbc, cfb, ofb, ctr, gcm

# Each mode provides:
# - encrypt(key, data, iv=None) -> bytes
# - decrypt(key, data, iv=None) -> bytes


src.hash - Hash Functions

from src.hash.sha256 import SHA256
from src.hash.sha3_256 import SHA3_256

sha256 = SHA256()
hash_value = sha256.hash(b"data")
src.mac - Message Authentication

from src.mac.hmac import HMAC

hmac = HMAC(key=b"secret")
mac = hmac.compute(b"message")
src.kdf - Key Derivation

from src.kdf.pbkdf2 import pbkdf2_hmac_sha256

key = pbkdf2_hmac_sha256(
    password=b"password",
    salt=b"salt",
    iterations=100000,
    dklen=32
)


src.csprng - Random Number Generation

from src.csprng import generate_random_bytes

random_data = generate_random_bytes(16)
Usage Examples
Basic AES Encryption
python
from src.modes.cbc import encrypt, decrypt

key = b"0" * 16
iv = generate_random_bytes(16)
ciphertext = encrypt(key, b"secret message", iv)
plaintext = decrypt(key, ciphertext, iv)
Hashing Files
python
from src.hash.sha256 import SHA256

sha256 = SHA256()
with open("file.txt", "rb") as f:
    while chunk := f.read(4096):
        sha256.update(chunk)
hash_result = sha256.digest()
text


