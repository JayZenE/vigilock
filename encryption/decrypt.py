from cryptography.fernet import Fernet


def decrypt_data(key: bytes, token: bytes) -> bytes:
    f = Fernet(key)
    return f.decrypt(token)
