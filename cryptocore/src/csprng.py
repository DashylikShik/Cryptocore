import os

def generate_random_bytes(num_bytes):
    """
    Generates a cryptographically secure random byte string.
    
    Args:
        num_bytes (int): Number of random bytes to generate
        
    Returns:
        bytes: Random byte string
        
    Raises:
        OSError: If the operating system's RNG fails
    """
    if num_bytes <= 0:
        raise ValueError("Number of bytes must be positive")
    
    try:
        return os.urandom(num_bytes)
    except Exception as e:
        raise OSError(f"Failed to generate random bytes: {e}")