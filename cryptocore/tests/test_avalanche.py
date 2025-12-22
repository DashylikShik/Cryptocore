import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.hash.sha256 import SHA256

def test_avalanche_effect():
    """Test avalanche effect - small input change should produce completely different hash"""
    print("Testing Avalanche Effect...")
    
    original_data = b"Hello, world!"
    modified_data = b"Hello, world?" 

    sha256 = SHA256()
    hash1 = sha256.hash(original_data)
    
    sha256 = SHA256()  # Reset
    hash2 = sha256.hash(modified_data)

    print(f"Original: {hash1}")
    print(f"Modified: {hash2}")
    
    bin1 = bin(int(hash1, 16))[2:].zfill(256)
    bin2 = bin(int(hash2, 16))[2:].zfill(256)

    diff_count = sum(bit1 != bit2 for bit1, bit2 in zip(bin1, bin2))

    print(f"Bits changed: {diff_count}/256")
    
    if 100 < diff_count < 156:
        print("Avalanche effect test PASSED - good diffusion")
    else:
        print(f"Avalanche effect weak: only {diff_count} bits changed")
    
    return diff_count

if __name__ == "__main__":
    test_avalanche_effect()