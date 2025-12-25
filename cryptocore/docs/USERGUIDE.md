# Руководство пользователя CryptoCore

## Быстрый старт

### Установка
```bash
# Clone repository
git clone https://github.com/Dashylikjopka/Cryptocore.git
cd cryptocore

# Установка зависимостей
pip install -r requirements.txt

Основные команды
1. Шифрование файлов

# Encrypt file with AES-256 CBC
python src/main.py encrypt --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input plain.txt --output encrypted.bin

# Дешифрование файлов
python src/main.py encrypt --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input encrypted.bin --output decrypted.txt
2. Хеширование

# SHA-256 hash
python src/main.py dgst --algorithm sha256 --input document.pdf

# SHA3-256 hash with output file
python src/main.py dgst --algorithm sha3-256 --input backup.tar --output backup.sha3
3. HMAC (Message Authentication)

# Генерация HMAC
python src/main.py dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff --input message.txt

# Проверить HMAC
python src/main.py dgst --algorithm sha256 --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input message.txt --verify hmac.txt
4.Производное получение ключа (PBKDF2)

# Получить ключ из пароля
python src/main.py derive --password "MyPassword123" \
  --salt 1234567890abcdef --iterations 100000 --length 32
5. Аутентифицированное шифрование GCM

# Шифровать с аутентификацией
python src/main.py encrypt --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input data.txt --output encrypted.bin --aad metadata123

## Расшифровать с проверкой подлинности
python src/main.py encrypt --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input encrypted.bin --output decrypted.txt --aad metadata123
Справочник команд
Шифрование/Дешифрование

python src/main.py encrypt
  --algorithm aes
  --mode [ecb|cbc|cfb|ofb|ctr|gcm]
  --encrypt|--decrypt
  --key HEX_STRING
  --input FILE
  --output FILE
  [--iv HEX_STRING]    # For modes requiring IV
  [--aad HEX_STRING]   # For GCM mode only
Хеширование
python src/main.py dgst
  --algorithm [sha256|sha3-256]
  --input FILE
  [--output FILE]
  [--hmac]             # Enable HMAC mode
  [--key HEX_STRING]   # Required for HMAC
  [--verify FILE]      # Verify against stored hash
Вывод ключа

python src/main.py derive
  --password STRING
  [--salt HEX_STRING]  # Auto-generated if not provided
  [--iterations N]     # Default: 100000
  [--length N]         # Default: 32 bytes
  [--output FILE]
Сравнение с другими инструментами
CryptoCore против OpenSSL
Операция CryptoCore Эквивалент OpenSSL
AES-256 CBC Encryption	python src/main.py encrypt --algorithm aes --mode cbc --encrypt --key <hex> --input file	openssl enc -aes-256-cbc -K <key> -iv <iv> -in file -out file.enc
SHA-256 Hash	python src/main.py dgst --algorithm sha256 --input file	openssl dgst -sha256 file
HMAC-SHA256	python src/main.py dgst --algorithm sha256 --hmac --key <key> --input file	openssl dgst -sha256 -hmac <key> file
PBKDF2 Key Derivation	python src/main.py derive --password "pwd" --salt <salt> --iterations 100000	openssl kdf -keylen 32 -kdfopt pass:"pwd" -kdfopt salt:<salt> -kdfopt iter:100000 PBKDF2
GCM Encryption	python src/main.py encrypt --algorithm aes --mode gcm --encrypt --key <key> --aad <data>	openssl enc -aes-256-gcm -K <key> -iv <iv> -aad <data> -in file
CryptoCore против GPG
Функция CryptoCore GPG (GnuPG)
Симметричное шифрование ✅ AES-256, все режимы ✅ AES, Twofish и др.
Асимметричное шифрование ❌ Не поддерживается ✅ RSA, ECC и др.
Цифровые подписи ❌ Не поддерживается ✅ Полная поддержка
Управление ключами Базовое (пароли/файлы ключей) Продвинутое (ключевой ринг, сеть доверия)
Форматы файлов Пользовательский бинарный формат Стандартный формат OpenPGP
Простота команд Простые, целенаправленные команды Сложные, много опций
Когда использовать тот или иной инструмент
Используйте CryptoCore, когда:

Используйте легковесное симметричное шифрование, если:

- Вы хотите избежать сложных зависимостей
- Вам нужен простой, специализированный инструмент
- Вы работаете в средах Python
- Вам нужна образовательная/прозрачная реализация

Используйте OpenSSL, если:

- Вам нужна совместимость с отраслевыми стандартами
- Требуется асимметричное шифрование
- Необходимо управление сертификатами
- Вы интегрируетесь с существующими системами
- Вам нужна максимальная производительность

Используйте GPG, если:

- Вам нужна шифровка/подпись электронной почты
- Вы хотите совместимость с OpenPGP
- Необходимо управление ключами с использованием сети доверия
- Вы шифруете для нескольких получателей

Шпаргалка (Быстрая справка)
Основные команды
Шифрование
bash
# Авто-генирация ключа
python src/main.py encrypt --algorithm aes --mode gcm --encrypt --input file.txt --output file.enc

# С определённым ключом
python src/main.py encrypt --algorithm aes --mode cbc --encrypt --key $(head -c 32 /dev/urandom | xxd -p) --input data.bin

# С IV
python src/main.py encrypt --algorithm aes --mode ctr --encrypt --key <key> --iv $(head -c 16 /dev/urandom | xxd -p) --input file
Хеширование
bash
# Quick hash check
python src/main.py dgst --algorithm sha256 --input downloaded_file.iso

# Сохранение хеша
python src/main.py dgst --algorithm sha3-256 --input backup.tar.gz --output backup.sha3
HMAC
bash
# Создать и сохранить
python src/main.py dgst --algorithm sha256 --hmac --key <secret> --input message.txt --output message.hmac

# Быстрая проверка
python src/main.py dgst --algorithm sha256 --hmac --key <secret> --input message.txt --verify message.hmac
Управление ключами
bash
# Генерация сильного ключа из пароля
python src/main.py derive --password "$(pwgen 20 1)" --salt $(head -c 16 /dev/urandom | xxd -p) --iterations 210000

# Сохранить в файл
python src/main.py derive --password "MyPass" --output keyfile.bin
Распространённые длины ключей (шестнадцатеричный формат)
Алгоритм  Длина в hex  Байты  Пример
AES-128	32 chars	16	00112233445566778899aabbccddeeff
AES-192	48 chars	24	00112233445566778899aabbccddeeff0011223344556677
AES-256	64 chars	32	00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
IV	32 chars	16	aabbccddeeff00112233445566778899
SHA-256	64 chars	32	e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Руководство по выбору режима
Режим Конфиденциальность Целостность Применение
ECB ✅ ❌ Никогда не использовать для реальных данных - только для тестирования
CBC ✅ ❌ Устаревшие системы, с HMAC
CFB ✅ ❌ Потоковая передача, с HMAC
OFB ✅ ❌ Потоковая передача, с HMAC
CTR ✅ ❌ Параллельное шифрование, с HMAC
GCM ✅ ✅ Рекомендуется - современные приложения
Короткие команды для часто выполняемых задач

# Шифровать случайным ключом (показывает ключ)
python src/main.py encrypt --algorithm aes --mode gcm --encrypt --input secret.txt

# Проверить, что файл не изменился
python src/main.py dgst --algorithm sha256 --input important.doc --verify important.doc.sha256

# Создать резервную копию с паролем
echo -n "Enter password: " && read PASS && python src/main.py derive --password "$PASS" --iterations 210000 | python src/main.py encrypt --algorithm aes --mode gcm --encrypt --key-stdin --input data.tar

# Пакетная обработка файлов
for file in *.txt; do python src/main.py encrypt --algorithm aes --mode gcm --encrypt --input "$file" --output "${file}.enc"; done

# Проверка нескольких хэшей
for file in *; do python src/main.py dgst --algorithm sha256 --input "$file" >> checksums.txt; done
Каталог примеров
Смотрите папку examples/ для полноценных рабочих примеров:
examples/backup_script.py - Автоматическое шифрование резервных копий
examples/file_integrity.py - Контроль целостности файлов
examples/password_manager.py - Простой менеджер паролей
examples/secure_archive.py - Создание зашифрованных архивов

Устранение неполадок
Распространенные проблемы "Неверная длина ключа"

Ключ должен быть 16, 24 или 32 байта в шестнадцатеричном формате (32, 48 или 64 шестнадцатеричных символа)

Пример допустимого ключа: 00112233445566778899aabbccddeeff (32 символа = 16 байт)

"Файл не найден"

Проверьте путь к файлу и права доступа

Используйте абсолютные пути при необходимости: --input /home/user/file.txt

"Ошибка аутентификации" (GCM)

Неверные AAD (Дополнительные аутентифицированные данные)

Искажённый шифротекст

Для расшифровки использован неверный ключ

Убедитесь, что AAD полностью совпадает при шифровании и расшифровке

"Проверка HMAC не выполнена"

Файл был изменен

Неверный ключ HMAC

Поврежденный HMAC файл

"Для этого режима требуется IV"

Режимы CBC, CFB, OFB, CTR требуют IV

Либо укажите с помощью --iv, либо позвольте сгенерировать автоматически

Режим отладки
Добавьте флаг --verbose для подробного вывода:


python src/main.py encrypt --algorithm aes --mode gcm --encrypt --input test.txt --verbose
Советы по производительности
Большие файлы: CryptoCore автоматически использует обработку по частям (куски по 1 МБ)

PBKDF2: >100 000 итераций могут быть медленными – настройте в зависимости от требований к безопасности

SHA3-256: Медленнее, чем SHA-256, но более безопасен против некоторых атак

GCM: Самый быстрый аутентифицированный режим, рекомендуется для большинства случаев

Память: Обработка не загружает весь файл в память

Лучшие практики
Всегда используйте GCM для шифрования файлов (обеспечивает как конфиденциальность, так и целостность)

Никогда не используйте ECB для реальных данных (только для тестирования/обучения)

Генерируйте случайные IV для каждой операции шифрования

Используйте надежные пароли для PBKDF2 (минимум 12 символов, смешанные)

Проверяйте хэши загруженных/переданных файлов

Храните ключи безопасно — никогда не добавляйте их в систему управления версиями

Периодически меняйте ключи для конфиденциальных данных

Проверяйте расшифровку после шифрования, чтобы убедиться, что оно работает

Меры безопасности
Управление ключами
Генерируйте ключи с помощью python src/main.py derive или внешнего CSPRNG

Храните ключи в безопасных системах управления ключами

Никогда не внедряйте ключи напрямую в исходный код

Используйте разные ключи для разных целей

Выбор алгоритмов
Рекомендуется: AES-256-GCM для шифрования
Рекомендуется: SHA3-256 для хэширования

Рекомендуется: более 210 000 итераций для PBKDF2

Избегайте: режима ECB для всего, кроме тестирования

Избегайте: SHA-1, MD5 (устаревшие)

Операционная безопасность
Очищайте конфиденциальные данные из памяти после использования

Используйте безопасное удаление для временных файлов

Реализуйте контроль доступа к зашифрованным данным

Регулярно проводите аудит безопасности вашей реализации

Получение помощи
Проверьте python src/main.py --help для справки по командам

Просмотрите примеры в каталоге examples/

См. docs/API.md для документации для разработчиков

Создавайте задачи на GitHub

Вклад в проект
См. CONTRIBUTING.md для получения инструкций по участию в разработке CryptoCore.

Проблемы с безопасностью
Пожалуйста, сообщайте о уязвимостях безопасности согласно SECURITY.md.
