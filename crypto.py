import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def load_or_create_key(key_file):
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    else:
        key = AESGCM.generate_key(bit_length=128)
        with open(key_file, "wb") as f:
            f.write(key)
        return key


def encrypt_password(password: str, key_file: str) -> str:
    key = load_or_create_key(key_file)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, password.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_password(token: str, key_file: str) -> str:
    key = load_or_create_key(key_file)
    aesgcm = AESGCM(key)
    data = base64.b64decode(token.encode("utf-8"))
    nonce, ciphertext = data[:12], data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
