import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key() -> bytes:
    return os.urandom(32)


def _normalize_key(key: bytes | str) -> bytes:
    if isinstance(key, str):
        key = key.encode("utf-8")
    return hashlib.sha256(key).digest()


def encrypt_data(
    key: bytes | str,
    data: bytes,
    filename: str | None = None,
    recovery_key: bytes | str | None = None,
    recovery_question: str | None = None,
) -> bytes:
    nonce = os.urandom(12)
    ciphertext = AESGCM(_normalize_key(key)).encrypt(nonce, data, None)

    if recovery_key is not None:
        recovery_nonce = os.urandom(12)
        recovery_ciphertext = AESGCM(_normalize_key(recovery_key)).encrypt(
            recovery_nonce, data, None
        )
        name_bytes = (filename or '').encode('utf-8')
        question_bytes = (recovery_question or '').encode('utf-8')
        name_length = len(name_bytes).to_bytes(4, byteorder='big')
        question_length = len(question_bytes).to_bytes(2, byteorder='big')
        ciphertext_length = len(ciphertext).to_bytes(4, byteorder='big')
        return (
            b'VIGLOCK4'
            + name_length
            + name_bytes
            + question_length
            + question_bytes
            + ciphertext_length
            + nonce
            + ciphertext
            + recovery_nonce
            + recovery_ciphertext
        )

    if filename:
        name_bytes = filename.encode("utf-8")
        name_length = len(name_bytes).to_bytes(4, byteorder="big")
        return b"VIGLOCK2" + nonce + name_length + name_bytes + ciphertext

    return b"VIGLOCK1" + nonce + ciphertext
