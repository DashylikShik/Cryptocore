Документация API CryptoCore
Обзор

CryptoCore предоставляет криптографические функции для шифрования, хеширования и генерации ключей.

Модули
src.aes — Шифрование AES
from src.aes import encrypt_block, decrypt_block
# encrypt_block(key: bytes, plaintext: bytes) -> bytes
# decrypt_block(key: bytes, ciphertext: bytes) -> bytes

src.modes — Режимы шифрования
from src.modes import ecb, cbc, cfb, ofb, ctr, gcm
Каждый режим предоставляет:
encrypt(key, data, iv=None) -> bytes
decrypt(key, data, iv=None) -> bytes

src.hash — Хеш-функции
from src.hash.sha256 import SHA256
from src.hash.sha3_256 import SHA3_256

src.mac — Аутентификация сообщений
from src.mac.hmac import HMAC

src.kdf — Генерация ключей
from src.kdf.pbkdf2 import pbkdf2_hmac_sha256

src.csprng — Криптографический ГСЧ
from src.csprng import generate_random_bytes

Пример использования
Базовое AES-шифрование
from src.modes.cbc import encrypt, decrypt
Хеширование файлов
(пример потокового чтения)
