import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_key() -> bytes:
    # 256-bit key (recommended)
    return AESGCM.generate_key(bit_length=256)

def encrypt_aes_gcm(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> str:
    """
    Returns base64(nonce + ciphertext + tag)
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce is recommended for GCM
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    # ct already includes the auth tag appended by library; store nonce + ct
    out = nonce + ct
    return base64.b64encode(out).decode()

def decrypt_aes_gcm(key: bytes, b64_message: str, associated_data: bytes | None = None) -> bytes:
    data = base64.b64decode(b64_message)
    nonce = data[:12]
    ct_and_tag = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct_and_tag, associated_data)

# Example usage
if __name__ == "__main__":
    key = generate_key()
    print("Key (base64):", base64.b64encode(key).decode())

    plaintext = b"Secret message for AES-GCM"
    aad = b"optional-associated-data"  # can be None
    ciphertext_b64 = encrypt_aes_gcm(key, plaintext, aad)
    print("Ciphertext (base64):", ciphertext_b64)

    recovered = decrypt_aes_gcm(key, ciphertext_b64, aad)
    print("Recovered plaintext:", recovered)
