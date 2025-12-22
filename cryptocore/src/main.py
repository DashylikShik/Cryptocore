import argparse
import sys
import os
import secrets
import binascii

# Добавляем путь для импортов
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

try:
    # Старые импорты
    from crypto import (
        encrypt_ecb, decrypt_ecb,
        encrypt_cbc, decrypt_cbc,
        encrypt_cfb, decrypt_cfb,
        encrypt_ofb, decrypt_ofb,
        encrypt_ctr, decrypt_ctr
    )
    from src.file_io import read_file, write_file
    from src.csprng import generate_random_bytes
    from src.hash.sha256 import SHA256
    from src.hash.sha3_256 import SHA3_256
    from src.mac.hmac import HMAC
    
    # НОВЫЙ импорт для GCM
    from src.modes.gcm import gcm_encrypt, gcm_decrypt, AuthenticationError
    GCM_AVAILABLE = True
    
    # НОВЫЕ импорты для KDF
    from src.kdf.pbkdf2 import pbkdf2_hmac_sha256
    from src.kdf.hkdf import derive_key
    
except ImportError as e:
    print(f"Ошибка импорта: {e}")
    print("Проверьте структуру проекта:")
    print("cryptocore/src/ со всеми модулями")
    sys.exit(1)


def is_weak_key(key_bytes):
    """Проверка слабых ключей"""
    if all(b == 0 for b in key_bytes):
        return True
    
    is_sequential_inc = all(key_bytes[i] == (key_bytes[i-1] + 1) % 256 for i in range(1, len(key_bytes)))
    is_sequential_dec = all(key_bytes[i] == (key_bytes[i-1] - 1) % 256 for i in range(1, len(key_bytes)))
    
    if is_sequential_inc or is_sequential_dec:
        return True
    
    byte_counts = {}
    for byte in key_bytes:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    if max(byte_counts.values()) > len(key_bytes) * 0.75:
        return True
    
    return False


def compute_hash(args):
    """Вычисление хеша"""
    try:
        input_data = read_file(args.input)
    except FileNotFoundError:
        print(f"Ошибка: Файл '{args.input}' не найден", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка чтения файла: {e}", file=sys.stderr)
        sys.exit(1)
    
    if args.algorithm == 'sha256':
        hasher = SHA256()
    elif args.algorithm == 'sha3-256':
        hasher = SHA3_256()
    else:
        print(f"Ошибка: Алгоритм '{args.algorithm}' не поддерживается", file=sys.stderr)
        sys.exit(1)
    
    hash_value = hasher.hash(input_data)
    output_text = f"{hash_value}  {args.input}"
    
    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(output_text)
            print(f"Хеш записан в: {args.output}")
        except Exception as e:
            print(f"Ошибка записи файла: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(output_text)


def handle_encryption(args):
    """Обработка шифрования/расшифрования"""
    key_bytes = None
    key_generated = False
    
    # Проверяем режим
    is_gcm_mode = (args.mode == 'gcm')
    
    # 1. ОБРАБОТКА КЛЮЧА
    if args.encrypt:  # Шифрование
        if args.key:  # Ключ указан вручную
            try:
                key_bytes = bytes.fromhex(args.key)
                if is_gcm_mode:
                    # GCM поддерживает 16, 24 или 32 байта
                    if len(key_bytes) not in [16, 24, 32]:
                        print("Ошибка: Ключ должен быть 16, 24 или 32 байта для GCM", file=sys.stderr)
                        sys.exit(1)
                else:
                    # Остальные режимы - 16 байт
                    if len(key_bytes) != 16:
                        print("Ошибка: Ключ должен быть 16 байт (32 hex символа)", file=sys.stderr)
                        sys.exit(1)
                
                if is_weak_key(key_bytes):
                    print("Предупреждение: Ключ выглядит слабым", file=sys.stderr)
            except ValueError:
                print("Ошибка: Ключ должен быть hex-строкой", file=sys.stderr)
                sys.exit(1)
        else:  # Ключ не указан - генерируем
            try:
                key_bytes = generate_random_bytes(16)
                key_generated = True
                print(f"[INFO] Сгенерирован ключ: {key_bytes.hex()}")
            except Exception as e:
                print(f"Ошибка генерации ключа: {e}", file=sys.stderr)
                sys.exit(1)
    
    else:  # Расшифрование
        if not args.key:
            print("Ошибка: Для расшифрования нужен ключ (--key)", file=sys.stderr)
            sys.exit(1)
        
        try:
            key_bytes = bytes.fromhex(args.key)
            if is_gcm_mode:
                if len(key_bytes) not in [16, 24, 32]:
                    print("Ошибка: Ключ должен быть 16, 24 или 32 байта для GCM", file=sys.stderr)
                    sys.exit(1)
            else:
                if len(key_bytes) != 16:
                    print("Ошибка: Ключ должен быть 16 байт (32 hex символа)", file=sys.stderr)
                    sys.exit(1)
        except ValueError:
            print("Ошибка: Ключ должен быть hex-строкой", file=sys.stderr)
            sys.exit(1)
    
    # 2. ОБРАБОТКА AAD (дополнительные данные)
    aad_bytes = b""
    if is_gcm_mode and args.aad:
        try:
            aad_bytes = bytes.fromhex(args.aad)
        except ValueError:
            print("Ошибка: AAD должен быть hex-строкой", file=sys.stderr)
            sys.exit(1)
    
    # 3. ОБРАБОТКА IV/NONCE
    iv_bytes = None
    if args.iv:
        try:
            iv_bytes = bytes.fromhex(args.iv)
            if is_gcm_mode:
                if len(iv_bytes) != 12:
                    print("Предупреждение: Для GCM рекомендуется nonce 12 байт", file=sys.stderr)
            elif args.mode == 'ctr':
                if len(iv_bytes) != 8:
                    print("Ошибка: Для CTR нужен nonce 8 байт", file=sys.stderr)
                    sys.exit(1)
            elif len(iv_bytes) != 16:
                print("Ошибка: IV должен быть 16 байт", file=sys.stderr)
                sys.exit(1)
        except ValueError:
            print("Ошибка: IV должен быть hex-строкой", file=sys.stderr)
            sys.exit(1)
    
    # 4. ЧИТАЕМ ВХОДНОЙ ФАЙЛ
    input_data = read_file(args.input)
    
    try:
        # 5. ВЫПОЛНЯЕМ ОПЕРАЦИЮ
        if is_gcm_mode:  # РЕЖИМ GCM
            if not GCM_AVAILABLE:
                print("Ошибка: GCM не доступен. Установите 'pip install cryptography'", file=sys.stderr)
                sys.exit(1)
            
            if args.encrypt:
                # ШИФРОВАНИЕ GCM
                output_data = gcm_encrypt(key_bytes, input_data, aad_bytes, iv_bytes)
                print("Файл зашифрован в режиме GCM!")
                if key_generated:
                    print(f"[ВАЖНО] Сохраните ключ: {key_bytes.hex()}")
            
            else:
                # РАСШИФРОВАНИЕ GCM
                try:
                    output_data = gcm_decrypt(key_bytes, input_data, aad_bytes)
                    print("Файл расшифрован из режима GCM!")
                
                except AuthenticationError as e:
                    # ОШИБКА ПРОВЕРКИ - КРИТИЧЕСКИЙ СЛУЧАЙ!
                    print(f"[ОШИБКА] Проверка не прошла: {e}", file=sys.stderr)
                    
                    # УДАЛЯЕМ файл, если он уже создался
                    if os.path.exists(args.output):
                        os.remove(args.output)
                        print(f"[INFO] Удалён повреждённый файл: {args.output}")
                    
                    sys.exit(1)  # Выходим с ошибкой
        
        # СТАРЫЕ РЕЖИМЫ (оставляем как было)
        elif args.mode == 'ecb':
            if args.encrypt:
                output_data = encrypt_ecb(key_bytes, input_data)
                print("Файл зашифрован в режиме ECB!")
            else:
                output_data = decrypt_ecb(key_bytes, input_data)
                print("Файл расшифрован из режима ECB!")
        
        elif args.mode == 'cbc':
            if args.encrypt:
                output_data = encrypt_cbc(key_bytes, input_data)
                print("Файл зашифрован в режиме CBC!")
            else:
                if args.iv:
                    output_data = decrypt_cbc(key_bytes, iv_bytes + input_data)
                else:
                    output_data = decrypt_cbc(key_bytes, input_data)
                print("Файл расшифрован из режима CBC!")
        
        elif args.mode == 'cfb':
            if args.encrypt:
                output_data = encrypt_cfb(key_bytes, input_data)
                print("Файл зашифрован в режиме CFB!")
            else:
                if args.iv:
                    output_data = decrypt_cfb(key_bytes, iv_bytes + input_data)
                else:
                    output_data = decrypt_cfb(key_bytes, input_data)
                print("Файл расшифрован из режима CFB!")
        
        elif args.mode == 'ofb':
            if args.encrypt:
                output_data = encrypt_ofb(key_bytes, input_data)
                print("Файл зашифрован в режиме OFB!")
            else:
                if args.iv:
                    output_data = decrypt_ofb(key_bytes, iv_bytes + input_data)
                else:
                    output_data = decrypt_ofb(key_bytes, input_data)
                print("Файл расшифрован из режима OFB!")
        
        elif args.mode == 'ctr':
            if args.encrypt:
                output_data = encrypt_ctr(key_bytes, input_data)
                print("Файл зашифрован в режиме CTR!")
            else:
                if args.iv:
                    output_data = decrypt_ctr(key_bytes, iv_bytes + input_data)
                else:
                    output_data = decrypt_ctr(key_bytes, input_data)
                print("Файл расшифрован из режима CTR!")
        
        # 6. ЗАПИСЫВАЕМ РЕЗУЛЬТАТ
        write_file(args.output, output_data)
        
    except Exception as e:
        print(f"Ошибка операции: {e}", file=sys.stderr)
        sys.exit(1)


def handle_hmac(args):
    """Обработка HMAC"""
    if not args.key:
        print("Ошибка: Для HMAC нужен ключ (--key)", file=sys.stderr)
        sys.exit(1)
    
    if args.algorithm != 'sha256':
        print("Ошибка: HMAC поддерживает только SHA-256", file=sys.stderr)
        sys.exit(1)
    
    try:
        hmac = HMAC(args.key, args.algorithm)
        
        if args.input == '-':
            message = sys.stdin.buffer.read()
            hmac_value = hmac.compute(message)
        else:
            if not os.path.exists(args.input):
                print(f"Ошибка: Файл '{args.input}' не найден", file=sys.stderr)
                sys.exit(1)
            hmac_value = hmac.compute_file(args.input)
        
        output_text = f"{hmac_value}  {args.input}"
        
        if args.verify:
            if not os.path.exists(args.verify):
                print(f"Ошибка: Файл проверки '{args.verify}' не найден", file=sys.stderr)
                sys.exit(1)
                
            try:
                with open(args.verify, 'r') as f:
                    expected_line = f.read().strip()
                
                expected_parts = expected_line.split()
                if not expected_parts:
                    print("Ошибка: Файл проверки пуст", file=sys.stderr)
                    sys.exit(1)
                
                expected_hmac = expected_parts[0]
                
                if hmac_value == expected_hmac:
                    print("[OK] HMAC проверка прошла")
                    sys.exit(0)
                else:
                    print("[ERROR] HMAC проверка не прошла")
                    sys.exit(1)
                    
            except Exception as e:
                print(f"Ошибка чтения файла проверки: {e}", file=sys.stderr)
                sys.exit(1)
        
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write(output_text)
                print(f"HMAC записан в: {args.output}")
            except Exception as e:
                print(f"Ошибка записи файла: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            print(output_text)
            
    except Exception as e:
        print(f"Ошибка HMAC: {e}", file=sys.stderr)
        sys.exit(1)


def handle_derive(args):
    """Обработка ключевой деривации"""
    try:
        # 1. Чтение пароля - ТОЛЬКО ДЛЯ PBKDF2
        password = None
        if args.algorithm == 'pbkdf2':
            if args.password:
                password = args.password
            elif args.password_file:
                try:
                    with open(args.password_file, 'r', encoding='utf-8') as f:
                        password = f.read().strip()
                except Exception as e:
                    print(f"Ошибка чтения файла пароля: {e}", file=sys.stderr)
                    sys.exit(1)
            elif args.password_env:
                password = os.environ.get(args.password_env)
                if not password:
                    print(f"Ошибка: Переменная окружения '{args.password_env}' не установлена", file=sys.stderr)
                    sys.exit(1)
            else:
                print("Ошибка: Для PBKDF2 нужен пароль (используйте --password, --password-file или --password-env)", file=sys.stderr)
                sys.exit(1)
        
        # 2. Генерация/чтение соли
        salt_bytes = None
        if args.salt:
            try:
                salt_bytes = bytes.fromhex(args.salt)
            except ValueError:
                # Если не hex, используем как есть (как в тестовых векторах RFC)
                salt_bytes = args.salt.encode('utf-8')
        else:
            # Генерация случайной соли (только для PBKDF2)
            if args.algorithm == 'pbkdf2':
                salt_bytes = secrets.token_bytes(16)
                print(f"[INFO] Сгенерирована соль: {salt_bytes.hex()}", file=sys.stderr)
            else:
                # Для HKDF соль не обязательна, можно пустую
                salt_bytes = b''
                print(f"[INFO] HKDF: соль не используется", file=sys.stderr)
        
        # 3. Валидация параметров
        if args.iterations <= 0:
            print("Ошибка: Количество итераций должно быть положительным", file=sys.stderr)
            sys.exit(1)
        
        if args.length <= 0 or args.length > 1024:
            print("Ошибка: Длина ключа должна быть от 1 до 1024 байт", file=sys.stderr)
            sys.exit(1)
        
        # 4. Выполнение деривации
        derived_key = None
        
        if args.algorithm == 'pbkdf2':
            # Для PBKDF2 нужен пароль
            derived_key = pbkdf2_hmac_sha256(
                password,
                salt_bytes,
                args.iterations,
                args.length
            )
        
        elif args.algorithm == 'hkdf':
            # Для HKDF нужен ТОЛЬКО мастер-ключ, НЕ пароль
            if not args.master_key:
                print("Ошибка: Для HKDF нужен мастер-ключ (--master-key)", file=sys.stderr)
                sys.exit(1)
            
            try:
                master_key_bytes = bytes.fromhex(args.master_key)
            except ValueError:
                print("Ошибка: Мастер-ключ должен быть hex-строкой", file=sys.stderr)
                sys.exit(1)
            
            if not args.context:
                print("Ошибка: Для HKDF нужен контекст (--context)", file=sys.stderr)
                sys.exit(1)
            
            print(f"[INFO] HKDF: параметр iterations игнорируется", file=sys.stderr)
            
            derived_key = derive_key(
                master_key_bytes,
                args.context,
                args.length
            )
        
        # 5. Вывод результата
        if args.output:
            # Запись ключа в файл (бинарный формат)
            try:
                with open(args.output, 'wb') as f:
                    f.write(derived_key)
                print(f"Ключ записан в файл: {args.output}")
                
                # Если нужно сохранить соль в отдельный файл (только для PBKDF2)
                if args.salt_output and args.algorithm == 'pbkdf2':
                    with open(args.salt_output, 'w', encoding='utf-8') as f:
                        f.write(salt_bytes.hex())
                    print(f"Соль записана в файл: {args.salt_output}")
                elif args.salt_output and args.algorithm == 'hkdf':
                    print(f"[INFO] Для HKDF соль не сохраняется", file=sys.stderr)
            
            except Exception as e:
                print(f"Ошибка записи файла: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            # Вывод в stdout в формате KEY_HEX SALT_HEX
            print(f"{derived_key.hex()} {salt_bytes.hex()}")
        
        # 6. Очистка памяти
        if args.algorithm == 'pbkdf2' and password:
            # Перезаписываем чувствительные данные
            import gc
            password = None
            gc.collect()
        
        print(f"[INFO] Деривация завершена: алгоритм={args.algorithm}, длина={args.length} байт", file=sys.stderr)
        
    except Exception as e:
        print(f"Ошибка деривации ключа: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='CryptoCore - Инструмент шифрования, хеширования, MAC и деривации ключей')
    subparsers = parser.add_subparsers(dest='command', help='Команда', required=True)
    
    # ПАРСЕР ДЛЯ ШИФРОВАНИЯ
    encrypt_parser = subparsers.add_parser('encrypt', help='Шифрование/расшифрование')
    encrypt_parser.add_argument('--algorithm', required=True, choices=['aes'], help='Алгоритм')
    encrypt_parser.add_argument('--mode', required=True, 
                               choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr', 'gcm'], 
                               help='Режим работы')
    encrypt_parser.add_argument('--encrypt', action='store_true', help='Режим шифрования')
    encrypt_parser.add_argument('--decrypt', action='store_true', help='Режим расшифрования')
    encrypt_parser.add_argument('--key', help='Ключ (hex строка)')
    encrypt_parser.add_argument('--input', required=True, help='Входной файл')
    encrypt_parser.add_argument('--output', required=True, help='Выходной файл')
    encrypt_parser.add_argument('--iv', help='IV/Nonce (hex строка)')
    encrypt_parser.add_argument('--aad', help='Дополнительные данные для GCM (hex строка)')
    
    # ПАРСЕР ДЛЯ ХЕШИРОВАНИЯ
    hash_parser = subparsers.add_parser('dgst', help='Вычисление хеша или HMAC')
    hash_parser.add_argument('--algorithm', required=True, choices=['sha256', 'sha3-256'], help='Алгоритм')
    hash_parser.add_argument('--input', required=True, help='Входной файл (используйте "-" для stdin)')
    hash_parser.add_argument('--output', help='Выходной файл для хеша')
    hash_parser.add_argument('--hmac', action='store_true', help='Включить режим HMAC')
    hash_parser.add_argument('--key', help='Ключ для HMAC (hex строка)')
    hash_parser.add_argument('--verify', help='Проверить HMAC с файлом')
    
    # НОВЫЙ ПАРСЕР ДЛЯ ДЕРИВАЦИИ КЛЮЧЕЙ
    derive_parser = subparsers.add_parser('derive', help='Деривация ключей из паролей или мастер-ключей')
    
    # Группа для пароля (обязательно только для PBKDF2, проверяем в функции)
    password_group = derive_parser.add_mutually_exclusive_group(required=False)
    password_group.add_argument('--password', help='Пароль (строка, обязателен для PBKDF2)')
    password_group.add_argument('--password-file', help='Файл с паролем (для PBKDF2)')
    password_group.add_argument('--password-env', help='Переменная окружения с паролем (для PBKDF2)')
    
    # Общие параметры
    derive_parser.add_argument('--salt', help='Соль (hex строка, опционально, по умолчанию генерируется для PBKDF2)')
    derive_parser.add_argument('--iterations', type=int, default=100000, help='Количество итераций (по умолчанию: 100000, для PBKDF2)')
    derive_parser.add_argument('--length', type=int, default=32, help='Длина ключа в байтах (по умолчанию: 32)')
    derive_parser.add_argument('--algorithm', default='pbkdf2', choices=['pbkdf2', 'hkdf'], help='Алгоритм KDF (по умолчанию: pbkdf2)')
    
    # Параметры специфичные для HKDF
    derive_parser.add_argument('--master-key', help='Мастер-ключ для HKDF (hex строка, обязателен для HKDF)')
    derive_parser.add_argument('--context', help='Контекст для HKDF (строка, обязателен для HKDF)')
    
    # Параметры вывода
    derive_parser.add_argument('--output', help='Выходной файл для ключа')
    derive_parser.add_argument('--salt-output', help='Выходной файл для соли (если была сгенерирована)')
    
    args = parser.parse_args()
    
    # Обработка команд
    if args.command == 'dgst':
        if args.hmac:
            handle_hmac(args)
        else:
            compute_hash(args)
    
    elif args.command == 'encrypt':
        if args.encrypt == args.decrypt:
            print("Ошибка: Укажите --encrypt ИЛИ --decrypt", file=sys.stderr)
            sys.exit(1)
        handle_encryption(args)
    
    elif args.command == 'derive':
        handle_derive(args)
    
    else:
        print(f"Ошибка: Неизвестная команда '{args.command}'", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":

    main()

