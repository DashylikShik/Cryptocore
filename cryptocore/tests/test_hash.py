import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.hash.sha256 import SHA256
from src.hash.sha3_256 import SHA3_256

def test_sha256_nist():
    """NIST test vectors for SHA-256"""
    print("Testing SHA-256 NIST vectors...")
    
    test_cases = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ]
    
    for data, expected in test_cases:
        hasher = SHA256()
        result = hasher.hash(data)
        assert result == expected, f"Failed: {data} -> {result}, expected {expected}"
        print(f"{data if data else 'empty'}")
    
    print("SHA-256 NIST tests PASSED")

def test_sha3_256_nist():
    """NIST test vectors for SHA3-256"""
    print("Testing SHA3-256 NIST vectors...")
    
    test_cases = [
        (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    ]
    
    for data, expected in test_cases:
        hasher = SHA3_256()
        result = hasher.hash(data)
        assert result == expected, f"Failed: {data} -> {result}, expected {expected}"
        print(f"{data if data else 'empty'}")
    
    print("SHA3-256 NIST tests PASSED")

if __name__ == "__main__":
    test_sha256_nist()
    print()
    test_sha3_256_nist()
    print("\nALL HASH TESTS PASSED!")