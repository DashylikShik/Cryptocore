# CryptoCore

Минималистичный инструмент для шифрования с поддержкой различных режимов. Проект включает полную реализацию криптографических алгоритмов с нуля.

## Особенности

 **Полная реализация с нуля:**
- AES (ECB, CBC, CFB, OFB, CTR, GCM режимы)
- SHA-256 и SHA3-256 хэш-функции
- HMAC для аутентификации сообщений
- PBKDF2 для получения ключей из паролей
- GCM с аутентифицированным шифрованием

 **Безопасность:**
- Криптографически безопасный генератор случайных чисел (CSPRNG)
- Защита от side-channel атак (по возможности)
- Безопасное управление памятью
- Проверка целостности данных

 **Тестирование:**
- Полное покрытие тестами (>90%)
- Тестовые векторы NIST
- Тесты интероперабельности с OpenSSL
- Тесты производительности и безопасности

## Установка

```bash
# Клонирование репозитория
git clone https://github.com/Dashylikjopka/Cryptocore.git
cd cryptocore

# Установка зависимостей
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cryptocore/
├── src/
│   ├── hash/
│   │   ├── sha3_256.py
│   │   └── sha256.py #SHA-256 (реализация с нуля)
│   ├── kdf/ # Формирование ключей
│   │   ├── __init__.py
│   │   ├── hkdf.py # Иерархия ключей
│   │   └── pbkdf2.py # PBKDF2-HMAC-SHA256
│   ├── mac/
│   │   ├── __init__.py
│   │   └── hmac.py  # HMAC-SHA256
│   ├── modes/  # Режимы шифрования
│   │   ├── gcm.py  # GCM режим
│   │   ├── __init__.py
│   │   ├── __main__.py    
│   │   └── crypto.py      # Основные crypto функции
│   ├── csprng.py # Генерация случайных чисел
│   ├── file_io.py  # Работа с файлами
│   └── main.py            # Основной CLI
├── tests/           # Тесты
│   ├── unit/        # Юнит-тесты
│   │   ├── test_avalanche.py # Тест avalanche эффекта
│   │   ├── test_csprng.py  # Тесты CSPRNG
│   │   ├── test_gcm.py   # Тесты GCM
│   │   ├── test_gcm_security.py # Тесты безопасности GCM
│   │   ├── test_gcm_vectors.py # Тестовые векторы GCM
│   │   ├── test_hash.py  # Тесты хэш-функций
│   │   ├── test_hmac_vectors.py # Тестовые векторы HMAC
│   │   ├── test_kdf.py  # Тесты KDF
│   │   └── test_mac.py  # Тесты MAC
│   ├── integration/    # Интеграционные тесты (пока пусто)
│   ├── vectors/ # Тестовые векторы (пока пусто)
├──docs/ # Документация
│   ├── API.md  # API документация
│   ├── USERGUIDE.md # Руководство пользователя
│   └── DEVELOPMENT.md  # Руководство разработчика
├── test_*.txt, .bin (разные тестовые файлы)
├── README.md
├── requirements.txt
└── run.py  


# 1sprint шифрование и дешифрование ECB
# Создаем тестовый файл
echo "Hello CryptoCore! This is test data for AES-128 ECB mode." > test_plain.txt

# Шифрование
python src/main.py encrypt --algorithm aes --mode ecb --encrypt --key 00112233445566778899aabbccddeeff --input test_plain.txt --output test_encrypted.bin

# Расшифрование
python src/main.py encrypt --algorithm aes --mode ecb --decrypt --key 00112233445566778899aabbccddeeff --input test_encrypted.bin --output test_decrypted.txt

# Проверка
fc test_plain.txt test_decrypted.txt

#2 sprint 
#Тест CBC режима:
# Создаем тестовый файл
echo Hello CryptoCore! This is test data for AES modes. > test_plain.txt

# Шифрование CBC (должен сгенерировать IV)
python src/main.py encrypt --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input test_plain.txt --output test_cbc_enc.bin

# Расшифрование (без указания IV - должен прочитать из файла)
python src/main.py encrypt --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --input test_cbc_enc.bin --output test_cbc_dec.txt

# Проверяем
fc test_plain.txt test_cbc_dec.txt

#Тест CBC с указанием IV для дешифрования:

# Сначала получаем IV из зашифрованного файла (первые 16 байт)
# Можно сделать через Python:
python -c "with open('test_cbc_enc.bin', 'rb') as f: iv = f.read(16); print(iv.hex())"

# Допустим, получили IV: aabbccddeeff00112233445566778899
python src/main.py encrypt --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --iv aabbccddeeff00112233445566778899 --input test_cbc_enc.bin --output test_cbc_dec2.txt
# проверка
fc test_plain.txt test_cbc_dec2.txt


#Тест потоковых режимов (без padding):
# CFB режим
python src/main.py encrypt --algorithm aes --mode cfb --encrypt --key 00112233445566778899aabbccddeeff --input test_plain.txt --output test_cfb_enc.bin
python src/main.py encrypt --algorithm aes --mode cfb --decrypt --key 00112233445566778899aabbccddeeff --input test_cfb_enc.bin --output test_cfb_dec.txt
fc test_plain.txt test_cfb_dec.txt

# OFB режим
python src/main.py encrypt --algorithm aes --mode ofb --encrypt --key 00112233445566778899aabbccddeeff --input test_plain.txt --output test_ofb_enc.bin
python src/main.py encrypt --algorithm aes --mode ofb --decrypt --key 00112233445566778899aabbccddeeff --input test_ofb_enc.bin --output test_ofb_dec.txt
fc test_plain.txt test_ofb_dec.txt

# CTR режим
python src/main.py encrypt --algorithm aes --mode ctr --encrypt --key 00112233445566778899aabbccddeeff --input test_plain.txt --output test_ctr_enc.bin
python src/main.py encrypt --algorithm aes --mode ctr --decrypt --key 00112233445566778899aabbccddeeff --input test_ctr_enc.bin --output test_ctr_dec.txt
fc test_plain.txt test_ctr_dec.txt


# 3sprint
# Ключ будет сгенерирован автоматически и показан в консоли шифрование

python src/main.py encrypt --algorithm aes --mode cbc --encrypt --input test_plain.txt --output test_auto.bin

# Шифрование с указанием ключа
python src/main.py encrypt --algorithm aes --mode cbc --encrypt --input test_plain.txt --output encrypted.bin

# Дешифрование (ключ обязателен)
python src/main.py encrypt --algorithm aes --mode cbc --decrypt --key ключик сюда--input encrypted.bin --output decrypted.txt

# Шифрование ECB
python src/main.py encrypt --algorithm aes --mode ecb --encrypt --input test_plain.txt --output ecb_enc.bin

# Дешифрование ECB (ключ обязателен)
python src/main.py encrypt --algorithm aes --mode ecb --decrypt --key ВАШ_КЛЮЧ --input ecb_enc.bin --output ecb_dec.txt

# Шифрование CFB
python src/main.py encrypt --algorithm aes --mode cfb --encrypt --input test_plain.txt --output cfb_enc.bin

# Дешифрование CFB (ключ обязателен)
python src/main.py encrypt --algorithm aes --mode cfb --decrypt --key ВАШ_КЛЮЧ --input cfb_enc.bin --output cfb_dec.txt

# Шифрование OFB
python src/main.py encrypt --algorithm aes --mode ofb --encrypt --input test_plain.txt --output ofb_enc.bin

# Дешифрование OFB (ключ обязателен)
python src/main.py encrypt --algorithm aes --mode ofb --decrypt --key ВАШ_КЛЮЧ --input ofb_enc.bin --output ofb_dec.txt

# Шифрование CTR
python src/main.py encrypt --algorithm aes --mode ctr --encrypt --input test_plain.txt --output ctr_enc.bin

# Дешифрование CTR (ключ обязателен)
python src/main.py encrypt --algorithm aes --mode ctr --decrypt --key ВАШ_КЛЮЧ --input ctr_enc.bin --output ctr_dec.txt

#Слабый ключ (все нули)
python src/main.py encrypt --algorithm aes --mode ecb --encrypt --key 00000000000000000000000000000000 --input test_plain.txt --output weak1.bin

#Дешифрование без ключа (должна быть ошибка)
python src/main.py encrypt --algorithm aes --mode cbc --decrypt --input encrypted.bin --output decrypted.txt

#CSPRNG тесты
python tests/test_csprng.py

#4sprint
# Hash Usage 
# Compute SHA-256 hash
python src/main.py dgst --algorithm sha256 --input file.txt

# Compute SHA3-256 hash  
python src/main.py dgst --algorithm sha3-256 --input file.txt

# Save hash to file
python src/main.py dgst --algorithm sha256 --input file.txt --output file.sha256


# Encryption Usage
# Encryption with auto key generation
python src/main.py encrypt --algorithm aes --mode cbc --encrypt --input test_plain.txt --output encrypted.bin

# Decryption
python src/main.py encrypt --algorithm aes --mode cbc --decrypt --key KEY --input encrypted.bin --output decrypted.txt


# 5sprint
#1. Генерация HMAC
python run.py dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input test.txt
# 2. Сохранение в файл
python run.py dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input test.txt --output myhmac.txt

# 3. Проверка (должна пройти)
python run.py dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input test.txt --verify myhmac.txt

# 4. Проверка с неправильным ключом (должна провалиться)
python run.py dgst --algorithm sha256 --hmac --key ffeeddccbbaa99887766554433221100 --input test.txt --verify myhmac.txt

# 5. Проверка измененного файла (должна провалиться)
python run.py dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input test2.txt --verify myhmac.txt

## 6sprint
# Режим GCM (Galois/Counter Mode)
GCM - режим шифрования с проверкой подлинности. Он не только шифрует данные, но и гарантирует, что они не были изменены.

### Использование:
#1Базовые тесты GCM
python tests/test_gcm.py
#Тестовые векторы NIST (TEST-1) 
python tests/test_gcm_vectors.py

#CLI тесты
echo "Hello GCM encryption test!" > test.txt
#Шифрование
python src/main.py encrypt --algorithm aes --mode gcm --encrypt --key 00112233445566778899aabbccddeeff --input test.txt --output test.enc --aad aabbcc

#Дешифрование
python src/main.py encrypt --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --input test.enc --output test.dec --aad aabbcc

#Ошибка: AAD должен быть hex-строкой
python src/main.py encrypt --algorithm aes --mode gcm --decrypt --key 00112233445566778899aabbccddeeff --input file.enc --output should_fail.txt --aad wrongdata




#7sprint
python tests/test_kdf.py

#. **Проверенные функции и возможности**
KDF-1: Используется кастомная HMAC (не стандартная библиотека Python)
TEST-1: PBKDF2 работает корректно (проходит адаптированные тесты RFC 6070)
TEST-7: Генерация 1000 уникальных солей без дубликатов
TEST-8: Корректная работа с разным числом итераций
Детерминированность: Одинаковые входные данные → одинаковый выход
Безопасность: Разные пароли/соли/контексты → разные ключи
Поддержка длин: Ключи длиной от 1 до 256+ байт
Обработка форматов: Поддержка hex и текстовых солей
Крайние случаи: Работа с пустыми паролями и солями


#8sprint
python tests\sprint8_tests.py

 **Полная тестовая система:**
- Тесты интероперабельности с OpenSSL (TEST-6)
- Тесты обработки больших файлов (>100MB) (TEST-7)
- Тесты безопасности памяти и переполнения буфера (QA-2)

 **Комплексная документация:**
- Руководство пользователя с Cheat Sheet (UG-6)
- Сравнение с OpenSSL/GPG (UG-7)
- Файл CONTRIBUTING.md для контрибьюторов (QA-4)
- Файл SECURITY.md с политикой безопасности (QA-5)
- Чек-лист безопасности в документации (QA-6)

