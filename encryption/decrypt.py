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

    if token.startswith((b'VIGLOCK3', b'VIGLOCK4')):
        name_length = int.from_bytes(token[8:12], byteorder='big')
        name_start = 12
        name_end = name_start + name_length
        original_name = token[name_start:name_end].decode('utf-8') or None
        ciphertext_length_start = name_end
        if token.startswith(b'VIGLOCK4'):
            question_length = int.from_bytes(token[ciphertext_length_start:ciphertext_length_start + 2], byteorder='big')
            ciphertext_length_start += 2 + question_length
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


def decrypt_recovery_data(
    recovery_key: bytes | str,
    token: bytes,
    recovery_question: str | None = None,
) -> tuple[bytes, str | None]:
    if not token.startswith((b'VIGLOCK3', b'VIGLOCK4')):
        raise ValueError('Recovery is only available for files with a recovery question.')

    name_length = int.from_bytes(token[8:12], byteorder='big')
    name_start = 12
    name_end = name_start + name_length
    original_name = token[name_start:name_end].decode('utf-8') or None
    ciphertext_length_start = name_end
    if token.startswith(b'VIGLOCK4'):
        question_length = int.from_bytes(token[ciphertext_length_start:ciphertext_length_start + 2], byteorder='big')
        question_start = ciphertext_length_start + 2
        stored_question = token[question_start:question_start + question_length].decode('utf-8')
        if stored_question != recovery_question:
            raise ValueError('The selected recovery question is incorrect.')
        ciphertext_length_start = question_start + question_length
    ciphertext_length = int.from_bytes(
        token[ciphertext_length_start:ciphertext_length_start + 4],
        byteorder='big',
    )
    first_nonce_start = ciphertext_length_start + 4
    first_ciphertext_start = first_nonce_start + 12
    second_nonce_start = first_ciphertext_start + ciphertext_length
    second_ciphertext_start = second_nonce_start + 12
    second_nonce = token[second_nonce_start:second_ciphertext_start]
    second_ciphertext = token[second_ciphertext_start:]

    try:
        return (
            AESGCM(_normalize_key(recovery_key)).decrypt(
                second_nonce, second_ciphertext, None
            ),
            original_name,
        )
    except Exception as exc:
        raise ValueError('Unable to decrypt file with the supplied recovery answer.') from exc


def decrypt_password_data(
    password: bytes | str,
    token: bytes,
) -> tuple[bytes, str | None]:
    if token.startswith((b'VIGLOCK3', b'VIGLOCK4')):
        name_length = int.from_bytes(token[8:12], byteorder='big')
        name_start = 12
        name_end = name_start + name_length
        original_name = token[name_start:name_end].decode('utf-8') or None
        ciphertext_length_start = name_end
        if token.startswith(b'VIGLOCK4'):
            question_length = int.from_bytes(token[ciphertext_length_start:ciphertext_length_start + 2], byteorder='big')
            ciphertext_length_start += 2 + question_length
        ciphertext_length = int.from_bytes(
            token[ciphertext_length_start:ciphertext_length_start + 4],
            byteorder='big',
        )
        first_nonce_start = ciphertext_length_start + 4
        first_ciphertext_start = first_nonce_start + 12
        first_nonce = token[first_nonce_start:first_ciphertext_start]
        first_ciphertext = token[first_ciphertext_start:first_ciphertext_start + ciphertext_length]
    elif token.startswith(b'VIGLOCK1'):
        first_nonce = token[8:20]
        first_ciphertext = token[20:]
        original_name = None
    elif token.startswith(b'VIGLOCK2'):
        first_nonce = token[8:20]
        name_length = int.from_bytes(token[20:24], byteorder='big')
        name_start = 24
        name_end = name_start + name_length
        original_name = token[name_start:name_end].decode('utf-8')
        first_ciphertext = token[name_end:]
    else:
        raise ValueError('Unsupported file format.')

    try:
        return AESGCM(_normalize_key(password)).decrypt(
            first_nonce, first_ciphertext, None
        ), original_name
    except Exception as exc:
        raise ValueError('Unable to decrypt file with the supplied password.') from exc
