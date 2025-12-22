import sys
import os
import tempfile
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.mac.hmac import HMAC

def test_hmac_basic():
    """Basic HMAC test"""
    print("Testing basic HMAC functionality...")
    
    key = "secretkey"
    message = b"Hello, world!"
    
    hmac = HMAC(key, 'sha256')
    result = hmac.compute(message)
    
    print(f"HMAC: {result}")
    print(f"Length: {len(result)} characters")
    
    assert len(result) == 64, "HMAC should be 64 hex characters"
    print("Basic test passed")
    return True


def test_file_hmac():
    """Test HMAC with files"""
    print("\nTesting HMAC with files...")
    
    # Создаем временный файл
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b"This is a test file for HMAC calculation.")
        temp_file = f.name
    
    try:
        key = "test_key_123"
        hmac = HMAC(key, 'sha256')
        
        # Вычисляем HMAC для файла
        result = hmac.compute_file(temp_file)
        
        print(f"File HMAC: {result}")
        assert len(result) == 64, "File HMAC should be 64 hex characters"
        print("File HMAC test passed")
        return True
        
    finally:
        # Удаляем временный файл
        os.unlink(temp_file)


def test_tamper_detection():
    """Test that HMAC detects file tampering"""
    print("\nTesting tamper detection...")
    
    # Создаем оригинальный файл
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b"Original content")
        temp_file = f.name
    
    try:
        key = "secret"
        hmac = HMAC(key, 'sha256')
        
        # Вычисляем оригинальный HMAC
        original_hmac = hmac.compute_file(temp_file)
        
        # Изменяем файл
        with open(temp_file, 'wb') as f:
            f.write(b"Modified content")
        
        # Вычисляем HMAC для измененного файла
        modified_hmac = hmac.compute_file(temp_file)
        
        # Проверяем, что HMAC изменился
        assert original_hmac != modified_hmac, "HMAC should change when file is modified"
        print("✓ Tamper detection test passed")
        return True
        
    finally:
        os.unlink(temp_file)


def test_key_sensitivity():
    """Test that HMAC is sensitive to key changes"""
    print("\nTesting key sensitivity...")
    
    message = b"Same message, different keys"
    
    # Ключ 1
    hmac1 = HMAC("key1", 'sha256')
    result1 = hmac1.compute(message)
    
    # Ключ 2
    hmac2 = HMAC("key2", 'sha256')
    result2 = hmac2.compute(message)
    
    assert result1 != result2, "Different keys should produce different HMACs"
    print("Key sensitivity test passed")
    return True


def test_empty_file():
    """Test HMAC with empty file"""
    print("\nTesting HMAC with empty file...")
    
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        # Пустой файл
        temp_file = f.name
    
    try:
        key = "key"
        hmac = HMAC(key, 'sha256')
        
        result = hmac.compute_file(temp_file)
        
        print(f"Empty file HMAC: {result}")
        assert len(result) == 64, "Empty file HMAC should be 64 hex characters"
        print("✓ Empty file test passed")
        return True
        
    finally:
        os.unlink(temp_file)


if __name__ == "__main__":
    print("=" * 60)
    print("MAC Implementation Tests")
    print("=" * 60)
    
    tests = [
        ("Basic HMAC", test_hmac_basic),
        ("File HMAC", test_file_hmac),
        ("Tamper Detection", test_tamper_detection),
        ("Key Sensitivity", test_key_sensitivity),
        ("Empty File", test_empty_file)
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ {test_name}: ERROR - {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("ALL TESTS PASSED!")
        sys.exit(0)
    else:
        print("SOME TESTS FAILED!")
        sys.exit(1)