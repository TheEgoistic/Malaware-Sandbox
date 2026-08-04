import hashlib

def get_hashes(file_path):
    """Generate MD5, SHA1, and SHA256 hashes of a file."""
    hashes = {"md5": "", "sha1": "", "sha256": ""}
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
    except Exception as e:
        print(f"Error generating hashes: {e}")
    return hashes
