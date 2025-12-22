from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

try:
    from csprng import generate_random_bytes
except ImportError:
    # Для тестов
    from .csprng import generate_random_bytes

# Режимы с паддингом (ECB, CBC)
def encrypt_ecb(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data, AES.block_size)
    return cipher.encrypt(padded_data)

def decrypt_ecb(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(data)
    return unpad(decrypted, AES.block_size)

def encrypt_cbc(key, data):
    iv = generate_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return iv + ciphertext

def decrypt_cbc(key, data):
    if len(data) < 16:
        raise ValueError("Ciphertext too short")
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, AES.block_size)

# Режимы без паддинга (CFB, OFB, CTR)
def encrypt_cfb(key, data):
    iv = generate_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    ciphertext = cipher.encrypt(data)
    return iv + ciphertext

def decrypt_cfb(key, data):
    if len(data) < 16:
        raise ValueError("Ciphertext too short")
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    return cipher.decrypt(ciphertext)

def encrypt_ofb(key, data):
    iv = generate_random_bytes(16)
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    ciphertext = cipher.encrypt(data)
    return iv + ciphertext

def decrypt_ofb(key, data):
    if len(data) < 16:
        raise ValueError("Ciphertext too short")
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    return cipher.decrypt(ciphertext)

def encrypt_ctr(key, data):
    nonce = generate_random_bytes(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(data)
    return nonce + ciphertext

def decrypt_ctr(key, data):
    if len(data) < 8:
        raise ValueError("Ciphertext too short")
    nonce = data[:8]
    ciphertext = data[8:]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)