from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import sha256
import getpass

def load_api_key(password: str, infile="secret.bin") -> str:
    with open(infile, "rb") as f:
        data = f.read()

    # [nonce(12 bytes)] + [ciphertext...]
    nonce = data[:12]
    ciphertext = data[12:]

    # password → 32-byte AES key
    key = sha256(password.encode()).digest()

    # AES-GCM decryption
    aes = AESGCM(key)
    try:
        api_key = aes.decrypt(nonce, ciphertext, None).decode()
        return api_key
    except Exception as e:
        raise ValueError("Wrong password or corrupted file") from e
