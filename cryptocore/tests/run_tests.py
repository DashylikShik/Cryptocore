#!/usr/bin/env python3
import sys
import os

# Добавляем src в путь
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Запускаем каждый тест отдельно
test_files = [
    'tests/unit/test_hash.py',
    'tests/unit/test_gcm.py',
    'tests/unit/test_gcm_security.py',
    'tests/unit/test_gcm_vectors.py',
    'tests/unit/test_kdf.py',
    'tests/unit/test_csprng.py',
    'tests/unit/test_mac.py',
    'tests/unit/test_hmac_vectors.py',
    'tests/unit/test_avalanche.py',
]

passed = 0
failed = 0

for test_file in test_files:
    if os.path.exists(test_file):
        print(f"\nRunning {test_file}...")
        result = os.system(f'python {test_file}')
        if result == 0:
            passed += 1
        else:
            failed += 1

print(f"\n{'='*50}")
print(f"Total: {passed} passed, {failed} failed")
print(f"{'='*50}")

if failed == 0:
    print(" All tests passed!")
    sys.exit(0)
else:
    print(" Some tests failed")
    sys.exit(1)