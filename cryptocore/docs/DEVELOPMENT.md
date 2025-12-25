```markdown
# CryptoCore Development Guide

## Структура проекта
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

### 1. Настройка окружения
```bash
git clone https://github.com/Dashylikjopka/Cryptocore.git
cd cryptocore
pip install -r requirements.txt
2. Запуск тестов
bash
# Run all tests
python tests/run_tests.py

# Run specific test module
python -m pytest tests/unit/test_hash.py -v

# Check test coverage
pip install pytest-cov
pytest --cov=src --cov-report=html
3. Стиль кода
PEP 8
Говорящие имена
Docstring для публичных функций
Юнит-тесты

Добавление новых функций
1. Новый хеш-алгоритм
Создать файл
Реализовать update() и digest()
Добавить в CLI
Написать тесты
Обновить документацию

2. Новый режим шифрования
Реализовать encrypt() и decrypt()
Тестировать с OpenSSL

Обновить руководство пользователя
Testing Strategy
Стратегия тестирования
Юнит-тесты
Тестировать отдельные функции
Использовать известные тестовые векторы (NIST, RFC)
Тестировать крайние случаи (пустые файлы, большие файлы)

Интеграционные тесты
Тестировать команды CLI полностью
Тестировать операции ввода/вывода файлов
Тестировать совместимость с OpenSSL

Тесты безопасности
Тестировать генерацию случайных чисел
Тестировать уникальность ключей/IV
Тестировать сбои аутентификации


Зависимости
pycryptodome>=3.19.0 - для примитивов AES

Python 3.7+

Версионирование
Использовать семантическое версионирование: MAJOR.MINOR.PATCH
