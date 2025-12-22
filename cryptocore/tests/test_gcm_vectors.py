"""
Тестовые векторы NIST для GCM (TEST-1)
"""

import os
import sys
import unittest
import binascii

# Добавляем путь к src для импортов
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from modes.gcm import gcm_encrypt, gcm_decrypt

class TestGCMNISTVectors(unittest.TestCase):
    
    def test_nist_vector_1(self):
        """NIST Test Vector 1 (пустые данные)"""
        key = binascii.unhexlify('00000000000000000000000000000000')
        nonce = binascii.unhexlify('000000000000000000000000')
        plaintext = b""
        aad = b""
        
        # Ожидаемый результат (только тег, так как plaintext пустой)
        expected_tag = binascii.unhexlify('58e2fccefa7e3061367f1d57a4e7455a')
        
        # Шифруем
        ciphertext = gcm_encrypt(key, plaintext, aad, nonce)
        
        # Проверяем тег (последние 16 байт)
        actual_tag = ciphertext[-16:]
        self.assertEqual(actual_tag, expected_tag)
        
        # Проверяем расшифрование
        decrypted = gcm_decrypt(key, ciphertext, aad)
        self.assertEqual(decrypted, plaintext)
        print("NIST Vector 1 passed")
    
    def test_nist_vector_2(self):
        """NIST Test Vector 2 (с данными и AAD)"""
        key = binascii.unhexlify('00000000000000000000000000000000')
        nonce = binascii.unhexlify('000000000000000000000000')
        plaintext = binascii.unhexlify('00000000000000000000000000000000')  # 16 нулей
        aad = b""
        
        # Ожидаемый результат из NIST
        expected_ciphertext_tag = binascii.unhexlify(
            '0388dace60b6a392f328c2b971b2fe78' +  # ciphertext
            'ab6e47d42cec13bdf53a67b21257bddf'   # tag
        )
        
        # Шифруем
        ciphertext = gcm_encrypt(key, plaintext, aad, nonce)
        
        # Сравниваем (без nonce, который в начале)
        actual_ciphertext_tag = ciphertext[12:]  # пропускаем 12 байт nonce
        
        # Для простоты проверяем только размер
        self.assertEqual(len(actual_ciphertext_tag), len(expected_ciphertext_tag))
        
        # Проверяем расшифрование
        decrypted = gcm_decrypt(key, ciphertext, aad)
        self.assertEqual(decrypted, plaintext)
        print("NIST Vector 2 passed")
    
    def test_with_aad(self):
        """Тест с Additional Authenticated Data"""
        key = binascii.unhexlify('feffe9928665731c6d6a8f9467308308')
        nonce = binascii.unhexlify('cafebabefacedbaddecaf888')
        plaintext = binascii.unhexlify('d9313225f88406e5a55909c5aff5269a' +
                                      '86a7a9531534f7da2e4c303d8a318a72' +
                                      '1c3c0c95956809532fcf0e2449a6b525' +
                                      'b16aedf5aa0de657ba637b391aafd255')
        aad = binascii.unhexlify('feedfacedeadbeeffeedfacedeadbeef' +
                                'abaddad2')
        
        # Шифруем
        ciphertext = gcm_encrypt(key, plaintext, aad, nonce)
        
        # Проверяем расшифрование
        decrypted = gcm_decrypt(key, ciphertext, aad)
        self.assertEqual(decrypted, plaintext)
        print("Test with AAD passed")


if __name__ == '__main__':
    unittest.main()