from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

class AESCipher:
    def __init__(self):
        # Generate a random 16-byte key
        self.key = get_random_bytes(16)

    def _pad(self, data):
        # Add PKCS7 padding to the data
        block_size = AES.block_size
        pad_size = block_size - (len(data) % block_size)
        return data + bytes([pad_size] * pad_size)

    def _unpad(self, data):
        # Remove PKCS7 padding from the data
        pad_size = data[-1]
        return data[:-pad_size]

    def encrypt_bytes(self, plaintext_bytes):
        # Encrypt bytes using AES in CBC mode with PKCS7 padding
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(self._pad(plaintext_bytes))
        return iv + ciphertext

    def decrypt_bytes(self, ciphertext_bytes):
        # Decrypt bytes using AES in CBC mode with PKCS7 padding
        iv = ciphertext_bytes[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_bytes = self._unpad(cipher.decrypt(ciphertext_bytes[AES.block_size:]))
        return decrypted_bytes

    def encrypt_string(self, plaintext_string):
        # Encrypt string using AES in CBC mode with PKCS7 padding
        return b64encode(self.encrypt_bytes(plaintext_string.encode('utf-8'))).decode('utf-8')

    def decrypt_string(self, ciphertext_string):
        # Decrypt string using AES in CBC mode with PKCS7 padding
        ciphertext_bytes = b64decode(ciphertext_string.encode('utf-8'))
        decrypted_bytes = self.decrypt_bytes(ciphertext_bytes)
        return decrypted_bytes.decode('utf-8')