def read_file(filename):
    try:
        with open(filename, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        exit(1)

def write_file(filename, data):
    try:
        with open(filename, 'wb') as f:
            f.write(data)
    except Exception as e:
        print(f"Error writing file: {e}")
        exit(1)

def read_file_chunks(filename, chunk_size=8192):
    """Generator for reading file in chunks"""
    try:
        with open(filename, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        exit(1)