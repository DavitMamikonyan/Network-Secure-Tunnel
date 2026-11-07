
import socket
import hashlib

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from crypto_utils import derive_aes_key, fingerprint

HOST = "10.0.12.2"
PORT = 4444


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Peer disconnected")
        data.extend(chunk)
    return bytes(data)


def send_blob(sock, data):
    sock.sendall(len(data).to_bytes(4, "big") + data)


def recv_blob(sock):
    size = int.from_bytes(recv_exact(sock, 4), "big")
    if not 1 <= size <= 8192:
        raise ValueError("Invalid public-key size")
    return recv_exact(sock, size)


private_key = x25519.X25519PrivateKey.generate()
public_bytes = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"Device2 waiting on {HOST}:{PORT}", flush=True)

    conn, address = server.accept()
    with conn:
        print(f"Connected by {address}", flush=True)
        peer_bytes = recv_blob(conn)

        if len(peer_bytes) != 32:
            raise ValueError("Invalid X25519 public key")

        send_blob(conn, public_bytes)
        peer_public = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
        shared_secret = private_key.exchange(peer_public)
        aes_key = derive_aes_key(shared_secret)
        with open("/tmp/network3_device2.key", "wb") as key_file:
            key_file.write(aes_key)
        import os
        os.chmod("/tmp/network3_device2.key", 0o600)

        print("Key exchange completed on Device2", flush=True)
        print("Shared-secret SHA-256:", hashlib.sha256(shared_secret).hexdigest(), flush=True)
        print("AES key fingerprint:", fingerprint(aes_key), flush=True)

