import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _normalize_key(key: bytes | str) -> bytes:
    if isinstance(key, str):
        key = key.encode("utf-8")
    return hashlib.sha256(key).digest()


def decrypt_data(key: bytes | str, token: bytes) -> bytes:
    if not token.startswith(b"VIGLOCK1"):
        raise ValueError("Unsupported file format.")

    nonce = token[8:20]
    ciphertext = token[20:]
    key_bytes = _normalize_key(key)
    return AESGCM(key_bytes).decrypt(nonce, ciphertext, None)
