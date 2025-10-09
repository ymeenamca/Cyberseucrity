import os
import base64
from Cryptography.Cipher import AES
from Cryptography.Util.Padding import pad, unpad

def encrypt_aes_cbc(key: bytes, plaintext: bytes) -> str:
    iv = os.urandom(16)  # 128-bit IV for AES
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return base64.b64encode(iv + ct).decode()

def decrypt_aes_cbc(key: bytes, b64_message: str) -> bytes:
    data = base64.b64decode(b64_message)
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# Example usage
if __name__ == "__main__":
    key = os.urandom(32)  # 256-bit key
    plaintext = b"Secret message for AES-CBC"
    ciphertext_b64 = encrypt_aes_cbc(key, plaintext)
    print("Ciphertext (base64):", ciphertext_b64)
    recovered = decrypt_aes_cbc(key, ciphertext_b64)
    print("Recovered plaintext:", recovered)
