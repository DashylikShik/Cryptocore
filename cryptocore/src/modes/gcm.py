"""
GCM (Galois/Counter Mode) - шифрование с проверкой подлинности
Формат выходного файла: [12 байт nonce] + [шифротекст] + [16 байт тег]
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AuthenticationError(Exception):
    """Ошибка, когда проверка подлинности не прошла"""
    pass


def gcm_encrypt(key, plaintext, aad=b"", nonce=None):
    """
    Шифрует данные в режиме GCM
    
    key: ключ (16, 24 или 32 байта)
    plaintext: данные для шифрования
    aad: дополнительные данные (будут проверены, но не зашифрованы)
    nonce: случайное число (12 байт). Если None - создается автоматически
    
    Возвращает: nonce + шифротекст + тег (12 + N + 16 байт)
    """
    # 1. Создаём случайный nonce (12 байт)
    if nonce is None:
        nonce = os.urandom(12)
    
    # 2. Настраиваем шифр AES-GCM
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, min_tag_length=16),
        backend=default_backend()
    )
    
    # 3. Шифруем
    encryptor = cipher.encryptor()
    
    # 4. Добавляем AAD для проверки
    if aad:
        encryptor.authenticate_additional_data(aad)
    
    # 5. Получаем шифротекст и тег
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    
    # 6. Возвращаем в нужном формате
    return nonce + ciphertext + tag


def gcm_decrypt(key, data, aad=b""):
    """
    Расшифровывает данные в режиме GCM с проверкой
    
    key: тот же ключ, что и при шифровании
    data: nonce + шифротекст + тег
    aad: те же дополнительные данные, что и при шифровании
    
    Возвращает: расшифрованные данные
    Или вызывает AuthenticationError, если проверка не прошла
    """
    # 1. Проверяем, что данных достаточно
    if len(data) < 12 + 16:  # минимум nonce(12) + tag(16)
        raise ValueError("Файл повреждён или не в формате GCM")
    
    # 2. Разбираем данные на части
    nonce = data[:12]          # первые 12 байт
    ciphertext = data[12:-16]  # всё кроме первого nonce и последнего tag
    tag = data[-16:]           # последние 16 байт
    
    try:
        # 3. Настраиваем расшифрование
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag, min_tag_length=16),
            backend=default_backend()
        )
        
        # 4. Расшифровываем
        decryptor = cipher.decryptor()
        
        # 5. Проверяем AAD
        if aad:
            decryptor.authenticate_additional_data(aad)
        
        # 6. Получаем исходные данные
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
        
    except Exception as e:
        # 7. Если что-то пошло не так - ошибка проверки
        raise AuthenticationError(f"Проверка не прошла: {str(e)}")