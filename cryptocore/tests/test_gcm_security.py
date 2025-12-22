"""
Тесты безопасности GCM (TEST-2 to TEST-7)
"""

import os
import sys
import unittest

# Добавляем путь к src для импортов
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from modes.gcm import gcm_encrypt, gcm_decrypt, AuthenticationError

class TestGCMSecurity(unittest.TestCase):
    
    def test_round_trip(self):
        """TEST-2: Round-trip test (шифрование -> расшифрование)"""
        print("TEST-2: Round-trip test")
        
        key = os.urandom(16)
        plaintext = b"This is a test message for round-trip verification"
        aad = b"additional authentication data"
        
        # Шифруем
        ciphertext = gcm_encrypt(key, plaintext, aad)
        
        # Расшифровываем
        decrypted = gcm_decrypt(key, ciphertext, aad)
        
        self.assertEqual(decrypted, plaintext)
        print("Round-trip successful")
        return True
    
    def test_aad_tamper(self):
        """TEST-3: Wrong AAD should fail"""
        print("\nTEST-3: AAD tamper test")
        
        key = os.urandom(16)
        plaintext = b"Secret message"
        aad_correct = b"correct_aad"
        aad_wrong = b"wrong_aad"
        
        # Шифруем с правильным AAD
        ciphertext = gcm_encrypt(key, plaintext, aad_correct)
        
        # Пробуем расшифровать с неправильным AAD
        try:
            gcm_decrypt(key, ciphertext, aad_wrong)
            self.fail("Should have raised AuthenticationError for wrong AAD")
        except AuthenticationError:
            print("Correctly failed with wrong AAD")
            return True
    
    def test_ciphertext_tamper(self):
        """TEST-4: Tampered ciphertext should fail"""
        print("\nTEST-4: Ciphertext tamper test")
        
        key = os.urandom(16)
        plaintext = b"Important data"
        aad = b"associated data"
        
        ciphertext = gcm_encrypt(key, plaintext, aad)
        
        # Подменяем один байт в ciphertext (не в nonce и не в tag!)
        tampered = bytearray(ciphertext)
        # Меняем байт в середине ciphertext (после 12 байт nonce)
        if len(tampered) > 30:
            tampered[20] ^= 0x01
        
        try:
            gcm_decrypt(key, bytes(tampered), aad)
            self.fail("Should have raised AuthenticationError for tampered ciphertext")
        except AuthenticationError:
            print("Correctly failed with tampered ciphertext")
            return True
    
    def test_nonce_uniqueness(self):
        """TEST-5: Nonce should be unique for each encryption"""
        print("\nTEST-5: Nonce uniqueness test")
        
        key = os.urandom(16)
        plaintext = b"Same message"
        aad = b""
        
        nonces = set()
        
        # Генерируем 100 шифротекстов
        for i in range(100):
            ciphertext = gcm_encrypt(key, plaintext, aad)
            nonce = ciphertext[:12]  # Первые 12 байт
            nonces.add(nonce.hex())
        
        # Все nonce должны быть уникальны
        self.assertEqual(len(nonces), 100)
        print(f"Generated {len(nonces)} unique nonces")
        return True
    
    def test_empty_aad(self):
        """TEST-6: Empty AAD should work"""
        print("\nTEST-6: Empty AAD test")
        
        key = os.urandom(16)
        plaintext = b"Message with empty AAD"
        aad = b""  # Пустой AAD
        
        ciphertext = gcm_encrypt(key, plaintext, aad)
        decrypted = gcm_decrypt(key, ciphertext, aad)
        
        self.assertEqual(decrypted, plaintext)
        print("Empty AAD works correctly")
        return True
    
    def test_large_file_simulation(self):
        """TEST-7: Simulate large file (больше доступной памяти)"""
        print("\nTEST-7: Large data test")
        
        key = os.urandom(16)
        # Создаем "большие" данные (1MB)
        plaintext = b"X" * (1024 * 1024)  # 1MB данных
        aad = b"large file metadata"
        
        ciphertext = gcm_encrypt(key, plaintext, aad)
        decrypted = gcm_decrypt(key, ciphertext, aad)
        
        self.assertEqual(decrypted, plaintext)
        print(f"Successfully processed {len(plaintext)} bytes")
        return True
    
    def test_tag_tamper(self):
        """Дополнительный тест: подмена тега"""
        print("\nExtra: Tag tamper test")
        
        key = os.urandom(16)
        plaintext = b"Message"
        aad = b""
        
        ciphertext = gcm_encrypt(key, plaintext, aad)
        
        # Подменяем последний байт тега
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0x01  # Меняем последний байт тега
        
        try:
            gcm_decrypt(key, bytes(tampered), aad)
            self.fail("Should have raised AuthenticationError for tampered tag")
        except AuthenticationError:
            print("Correctly failed with tampered tag")
            return True


def run_security_tests():
    """Запуск всех тестов безопасности"""
    print("RUNNING GCM SECURITY TESTS (TEST-2 to TEST-7)")
    print()
    
    test = TestGCMSecurity()
    
    # Запускаем каждый тест
    tests = [
        test.test_round_trip,
        test.test_aad_tamper,
        test.test_ciphertext_tamper,
        test.test_nonce_uniqueness,
        test.test_empty_aad,
        test.test_large_file_simulation,
        test.test_tag_tamper,
    ]
    
    passed = 0
    total = len(tests)
    
    for test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"{test_func.__name__} failed: {e}")
    
    print()
    print(f"RESULTS: {passed}/{total} tests passed")
    
    if passed == total:
        print("ALL SECURITY TESTS PASSED")
        return True
    else:
        print("SOME TESTS FAILED")
        return False


if __name__ == '__main__':
    run_security_tests()