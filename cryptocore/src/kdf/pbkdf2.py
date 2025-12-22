from typing import Union
import sys
import os

# Добавляем src в путь для импорта
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Теперь можно импортировать правильно
try:
    from mac.hmac import HMAC
except ImportError:
    # Альтернативный вариант импорта
    from src.mac.hmac import HMAC

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA256 using your own implementations"""
    # Создаем экземпляр HMAC с ключом
    hmac_obj = HMAC(key)
    # Используем метод compute_bytes() который возвращает bytes
    return hmac_obj.compute_bytes(msg)

def pbkdf2_hmac_sha256(
    password: Union[str, bytes],
    salt: Union[str, bytes],
    iterations: int,
    dklen: int
) -> bytes:
    """PBKDF2-HMAC-SHA256 implementation according to RFC 2898"""
    
    # Convert inputs to bytes
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    if isinstance(salt, str):
        # Try to decode as hex, otherwise use as raw string
        try:
            salt = bytes.fromhex(salt)
        except ValueError:
            salt = salt.encode('utf-8')
    
    hlen = 32  # SHA-256 output length
    blocks_needed = (dklen + hlen - 1) // hlen
    derived_key = b''
    
    for i in range(1, blocks_needed + 1):
        # U1 = HMAC(password, salt || INT_32_BE(i))
        block = hmac_sha256(password, salt + i.to_bytes(4, 'big'))
        u_prev = block
        
        # Compute U2 through Uc
        for _ in range(2, iterations + 1):
            u_curr = hmac_sha256(password, u_prev)
            # XOR u_curr into block
            block = bytes(a ^ b for a, b in zip(block, u_curr))
            u_prev = u_curr
        
        derived_key += block
    
    # Return exactly dklen bytes
    return derived_key[:dklen]