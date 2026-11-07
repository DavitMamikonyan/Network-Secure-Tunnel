import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_aes_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Network3 AES-GCM session key",
    ).derive(shared_secret)


def fingerprint(key):
    return hashlib.sha256(key).hexdigest()


def encrypt_payload(key, plaintext, aad=None):
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def decrypt_payload(key, encrypted, aad=None):
    if len(encrypted) < 28:
        raise ValueError("Encrypted payload is too short")

    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
