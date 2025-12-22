"""
Тесты для GCM режима
"""

import os
import sys
import unittest

# Добавляем путь к src для импортов
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from modes.gcm import gcm_encrypt, gcm_decrypt, AuthenticationError


class TestGCM(unittest.TestCase):
    
    def test_1_encrypt_decrypt(self):
        """Test 1: Simple encrypt-decrypt"""
        print("Test 1: Encryption -> Decryption")
        
        key = os.urandom(16)
        plaintext = b"Hello, this is a test message!"
        aad = b"additional data"
        
        # Шифруем
        ciphertext = gcm_encrypt(key, plaintext, aad)
        print(f"Encrypted: {len(ciphertext)} bytes")
        
        # Расшифровываем
        decrypted = gcm_decrypt(key, ciphertext, aad)
        
        # Проверяем
        self.assertEqual(decrypted, plaintext)
        print("OK: data matches")
    
    def test_2_wrong_aad(self):
        """Test 2: Wrong AAD -> error"""
        print("\nTest 2: Wrong AAD check")
        
        key = os.urandom(16)
        plaintext = b"Secret data"
        aad_correct = b"correct aad"
        aad_wrong = b"wrong aad"
        
        # Шифруем с правильным AAD
        ciphertext = gcm_encrypt(key, plaintext, aad_correct)
        
        # Пробуем расшифровать с неправильным AAD
        with self.assertRaises(AuthenticationError):
            gcm_decrypt(key, ciphertext, aad_wrong)
        
        print("OK: wrong AAD causes error")
    
    def test_3_tampered_ciphertext(self):
        """Test 3: Modified ciphertext -> error"""
        print("\nTest 3: Tampered ciphertext check")
        
        key = os.urandom(16)
        plaintext = b"Important data for verification"
        aad = b""
        
        # Шифруем
        ciphertext = gcm_encrypt(key, plaintext, aad)
        
        # Меняем один байт в середине
        tampered = bytearray(ciphertext)
        if len(tampered) > 30:
            tampered[20] ^= 0x01
        
        # Должна быть ошибка
        with self.assertRaises(AuthenticationError):
            gcm_decrypt(key, bytes(tampered), aad)
        
        print("OK: modified data causes error")
    
    def test_4_empty_data(self):
        """Test 4: Empty data"""
        print("\nTest 4: Empty data handling")
        
        key = os.urandom(16)
        plaintext = b""
        aad = b""
        
        ciphertext = gcm_encrypt(key, plaintext, aad)
        decrypted = gcm_decrypt(key, ciphertext, aad)
        
        self.assertEqual(decrypted, plaintext)
        print("OK: empty data handled")
    
    def test_5_different_key_sizes(self):
        """Test 5: Different key sizes"""
        print("\nTest 5: Different key sizes check")
        
        test_cases = [(16, "AES-128"), (24, "AES-192"), (32, "AES-256")]
        
        for key_size, name in test_cases:
            key = os.urandom(key_size)
            plaintext = b"Test for " + name.encode()
            aad = b"aad"
            
            ciphertext = gcm_encrypt(key, plaintext, aad)
            decrypted = gcm_decrypt(key, ciphertext, aad)
            
            self.assertEqual(decrypted, plaintext)
            print(f"OK: {name} works")
    
    def test_6_large_aad(self):
        """Test 6: Large AAD"""
        print("\nTest 6: Large AAD handling")
        
        key = os.urandom(16)
        plaintext = b"Short message"
        aad = b"A" * 1000
        
        ciphertext = gcm_encrypt(key, plaintext, aad)
        decrypted = gcm_decrypt(key, ciphertext, aad)
        
        self.assertEqual(decrypted, plaintext)
        print("OK: large AAD handled")


def run_tests():
    """Запуск всех тестов"""
    print("Running GCM tests")
    print()
    
    suite = unittest.TestLoader().loadTestsFromTestCase(TestGCM)
    runner = unittest.TextTestRunner(verbosity=0)  # verbosity=0 убирает лишний вывод
    result = runner.run(suite)
    
    print()
    if result.wasSuccessful():
        print("ALL TESTS PASSED")
    else:
        print("THERE ARE TEST FAILURES")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    run_tests()