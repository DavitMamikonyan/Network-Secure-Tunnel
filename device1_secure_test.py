import socket
from crypto_utils import derive_aes_key, encrypt_payload
from cryptography.hazmat.primitives.asymmetric import x25519

HOST = "10.0.12.2"
PORT = 4445

def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data.extend(chunk)
    return bytes(data)

def recv_blob(sock):
    size = int.from_bytes(recv_exact(sock, 4), "big")
    if not 1 <= size <= 65536:
        raise ValueError("Invalid message size")
    return recv_exact(sock, size)

def send_blob(sock, data):
    sock.sendall(len(data).to_bytes(4, "big") + data)

private_key = x25519.X25519PrivateKey.generate()
public_bytes = private_key.public_key().public_bytes_raw()
message = b"Network3 encrypted Device1-to-Device2 test"

with socket.create_connection((HOST, PORT), timeout=10) as sock:
    send_blob(sock, public_bytes)
    peer_bytes = recv_blob(sock)

    if len(peer_bytes) != 32:
        raise ValueError("Invalid X25519 public key")

    peer_public = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
    key = derive_aes_key(private_key.exchange(peer_public))

    encrypted = encrypt_payload(key, message)
    send_blob(sock, encrypted)

    response = recv_blob(sock)
    print("Encrypted transmission: OK")
    print("Original message:", message.decode())
    print("Encrypted bytes sent:", len(encrypted))
    print("Device2 response:", response.decode())
