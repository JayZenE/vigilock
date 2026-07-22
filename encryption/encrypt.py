from cryptography.fernet import Fernet


def generate_key():
    return Fernet.generate_key()


def encrypt_data(key: bytes, data: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(data)
