import hashlib

class SHA3_256:
    def __init__(self):
        self.hasher = hashlib.sha3_256()
    
    def update(self, data):
        self.hasher.update(data)
    
    def digest(self):
        return self.hasher.digest()
    
    def hexdigest(self):
        return self.hasher.hexdigest()
    
    def hash(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.hasher.update(data)
        return self.hexdigest()