import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _normalize_key(key: bytes | str) -> bytes:
    if isinstance(key, str):
        key = key.encode("utf-8")
    return hashlib.sha256(key).digest()


def decrypt_data(
    key: bytes | str | tuple[bytes | str, ...] | list[bytes | str],
    token: bytes,
) -> tuple[bytes, str | None]:
    keys = key if isinstance(key, (tuple, list)) else (key,)

    if token.startswith(b'VIGLOCK3'):
        name_length = int.from_bytes(token[8:12], byteorder='big')
        name_start = 12
        name_end = name_start + name_length
        original_name = token[name_start:name_end].decode('utf-8') or None
        ciphertext_length_start = name_end
        ciphertext_length = int.from_bytes(
            token[ciphertext_length_start:ciphertext_length_start + 4],
            byteorder='big',
        )
        first_nonce_start = ciphertext_length_start + 4
        first_ciphertext_start = first_nonce_start + 12
        second_nonce_start = first_ciphertext_start + ciphertext_length
        second_ciphertext_start = second_nonce_start + 12
        first_nonce = token[first_nonce_start:first_ciphertext_start]
        first_ciphertext = token[first_ciphertext_start:second_nonce_start]
        second_nonce = token[second_nonce_start:second_ciphertext_start]
        second_ciphertext = token[second_ciphertext_start:]

        for candidate_key in keys:
            try:
                return (
                    AESGCM(_normalize_key(candidate_key)).decrypt(
                        first_nonce, first_ciphertext, None
                    ),
                    original_name,
                )
            except Exception:
                try:
                    return (
                        AESGCM(_normalize_key(candidate_key)).decrypt(
                            second_nonce, second_ciphertext, None
                        ),
                        original_name,
                    )
                except Exception:
                    continue
        raise ValueError('Unable to decrypt file with the supplied credentials.')

    if token.startswith(b"VIGLOCK1"):
        nonce = token[8:20]
        ciphertext = token[20:]
        for candidate_key in keys:
            try:
                return AESGCM(_normalize_key(candidate_key)).decrypt(nonce, ciphertext, None), None
            except Exception:
                continue
        raise ValueError('Unable to decrypt file with the supplied credentials.')

    if token.startswith(b"VIGLOCK2"):
        nonce = token[8:20]
        name_length = int.from_bytes(token[20:24], byteorder="big")
        name_start = 24
        name_end = name_start + name_length
        original_name = token[name_start:name_end].decode("utf-8")
        ciphertext = token[name_end:]
        for candidate_key in keys:
            try:
                return AESGCM(_normalize_key(candidate_key)).decrypt(nonce, ciphertext, None), original_name
            except Exception:
                continue
        raise ValueError('Unable to decrypt file with the supplied credentials.')

    raise ValueError("Unsupported file format.")
