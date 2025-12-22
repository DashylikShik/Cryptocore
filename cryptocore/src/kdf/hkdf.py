# src/kdf/hkdf.py
from typing import Union

# ИСПРАВЛЕННЫЙ ИМПОРТ - используем абсолютный путь
from mac.hmac import HMAC

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA256 using your own implementations"""
    # Создаем экземпляр HMAC с ключом
    hmac_obj = HMAC(key)
    # Используем метод compute_bytes() который возвращает bytes
    return hmac_obj.compute_bytes(msg)

def derive_key(
    master_key: bytes,
    context: Union[str, bytes],
    length: int = 32
) -> bytes:
    """Derive a key from a master key using HMAC-based method"""
    
    if isinstance(context, str):
        context = context.encode('utf-8')
    
    derived = b''
    counter = 1
    
    while len(derived) < length:
        # T_i = HMAC(master_key, context || counter)
        block = hmac_sha256(master_key, context + counter.to_bytes(4, 'big'))
        derived += block
        counter += 1
    
    return derived[:length]