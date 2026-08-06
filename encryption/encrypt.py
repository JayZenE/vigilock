import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key() -> bytes:
    return os.urandom(32)


def _normalize_key(key: bytes | str) -> bytes:
    if isinstance(key, str):
        key = key.encode("utf-8")
    return hashlib.sha256(key).digest()


def encrypt_data(key: bytes | str, data: bytes) -> bytes:
    key_bytes = _normalize_key(key)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key_bytes).encrypt(nonce, data, None)
    return b"VIGLOCK1" + nonce + ciphertext
