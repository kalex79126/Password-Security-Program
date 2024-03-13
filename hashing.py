import hashlib

class SHA256Hasher:
    def __init__(self):
        # Create a SHA-256 hash object
        self.sha256_hash = hashlib.sha256()

    def hash_string(self, input_string):
        # Update the hash object with the input string
        self.sha256_hash.update(input_string.encode('utf-8'))

    def hash_byte(self, input_byte):
        # Update the hash object with the input bytes
        self.sha256_hash.update(input_byte)
        
    def get_hashed_string(self):
        # Get the hexadecimal representation of the hash
        return self.sha256_hash.hexdigest()

    def reset_hasher(self):
        # Reset the hash object to its initial state
        self.sha256_hash = hashlib.sha256()


