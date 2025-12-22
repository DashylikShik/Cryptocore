from src.hash.sha256 import SHA256

class HMAC:
    def __init__(self, key, hash_function='sha256'):
        if hash_function.lower() != 'sha256':
            raise ValueError("Only SHA-256 is supported in this implementation")
        
        self.hash_function = SHA256()
        self.block_size = 64  # Размер блока для SHA-256
        
        # Преобразуем ключ в bytes если нужно
        if isinstance(key, str):
            try:
                # Пробуем интерпретировать как hex
                key = bytes.fromhex(key)
            except ValueError:
                # Если не hex, то как строку
                key = key.encode('utf-8')
        elif not isinstance(key, bytes):
            raise TypeError("Key must be bytes or hex string")
        
        self.key = self._process_key(key)
    
    def _process_key(self, key):
        """Обработка ключа согласно RFC 2104"""
        # Если ключ длиннее размера блока, хешируем его
        if len(key) > self.block_size:
            key_hex = self.hash_function.hash(key)  # Возвращает hex строку
            key = bytes.fromhex(key_hex)  # Конвертируем в байты
        
        # Если ключ короче размера блока, дополняем нулями
        if len(key) < self.block_size:
            key = key + b'\x00' * (self.block_size - len(key))
        
        return key
    
    def _xor_bytes(self, a, b):
        """Побитовое XOR двух байтовых строк одинаковой длины"""
        return bytes(x ^ y for x, y in zip(a, b))
    
    def compute(self, message):
        """Вычисление HMAC(K, m) = H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ m))"""
        # Внутренняя паддинг-константа
        ipad = b'\x36' * self.block_size
        # Внешняя паддинг-константа
        opad = b'\x5c' * self.block_size
        
        # Вычисляем K ⊕ ipad
        k_ipad = self._xor_bytes(self.key, ipad)
        
        # Вычисляем H((K ⊕ ipad) ∥ message)
        inner_hash = self.hash_function.hash(k_ipad + message)
        inner_hash_bytes = bytes.fromhex(inner_hash)
        
        # Вычисляем K ⊕ opad
        k_opad = self._xor_bytes(self.key, opad)
        
        # Вычисляем H((K ⊕ opad) ∥ inner_hash)
        outer_hash = self.hash_function.hash(k_opad + inner_hash_bytes)
        
        return outer_hash  # Возвращает HEX строку!
    
    def compute_bytes(self, message):
        """Вычисление HMAC и возврат в виде байтов"""
        # Внутренняя паддинг-константа
        ipad = b'\x36' * self.block_size
        # Внешняя паддинг-константа
        opad = b'\x5c' * self.block_size
        
        # Вычисляем K ⊕ ipad
        k_ipad = self._xor_bytes(self.key, ipad)
        
        # Вычисляем H((K ⊕ ipad) ∥ message)
        inner_hash = self.hash_function.hash(k_ipad + message)
        inner_hash_bytes = bytes.fromhex(inner_hash)
        
        # Вычисляем K ⊕ opad
        k_opad = self._xor_bytes(self.key, opad)
        
        # Вычисляем H((K ⊕ opad) ∥ inner_hash)
        outer_hash = self.hash_function.hash(k_opad + inner_hash_bytes)
        
        # Возвращаем байты
        return bytes.fromhex(outer_hash)
    
    def compute_file(self, filepath, chunk_size=8192):
        """Вычисление HMAC для файла с чанкированием"""
        # Внутренняя паддинг-константа
        ipad = b'\x36' * self.block_size
        # Внешняя паддинг-константа
        opad = b'\x5c' * self.block_size
        
        # Вычисляем K ⊕ ipad
        k_ipad = self._xor_bytes(self.key, ipad)
        
        # Инициализируем хеш для внутреннего вычисления
        inner_hasher = SHA256()
        inner_hasher.update(k_ipad)
        
        # Читаем файл частями и обновляем хеш
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                inner_hasher.update(chunk)
        
        # Получаем внутренний хеш
        inner_hash = inner_hasher.digest()  # Используем digest() для байтов
        
        # Вычисляем K ⊕ opad
        k_opad = self._xor_bytes(self.key, opad)
        
        # Вычисляем внешний хеш
        outer_hasher = SHA256()
        outer_hasher.update(k_opad)
        outer_hasher.update(inner_hash)
        
        return outer_hasher.hexdigest()