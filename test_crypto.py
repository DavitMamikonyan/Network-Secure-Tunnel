from crypto_utils import derive_aes_key, encrypt_payload, decrypt_payload
from cryptography.hazmat.primitives.asymmetric import x25519

# Create a test shared secret using X25519
a = x25519.X25519PrivateKey.generate()
b = x25519.X25519PrivateKey.generate()

secret_a = a.exchange(b.public_key())
secret_b = b.exchange(a.public_key())

assert secret_a == secret_b

key_a = derive_aes_key(secret_a)
key_b = derive_aes_key(secret_b)

message = b"Network3 AES-GCM protected payload"
encrypted = encrypt_payload(key_a, message)
decrypted = decrypt_payload(key_b, encrypted)

assert decrypted == message
print("AES-GCM encrypt/decrypt: OK")
print("Original:", message.decode())
print("Encrypted length:", len(encrypted))
print("Decrypted:", decrypted.decode())
