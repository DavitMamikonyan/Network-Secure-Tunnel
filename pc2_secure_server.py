import socket
from crypto_utils import derive_aes_key, decrypt_payload
from cryptography.hazmat.primitives.asymmetric import x25519

HOST = "10.0.2.2"
PORT = 5002

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

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"PC2 secure test server listening on {HOST}:{PORT}", flush=True)

    conn, address = server.accept()
    with conn:
        print("Connected by:", address, flush=True)
        peer_bytes = recv_blob(conn)
        if len(peer_bytes) != 32:
            raise ValueError("Invalid X25519 public key")

        send_blob(conn, public_bytes)
        peer_public = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
        key = derive_aes_key(private_key.exchange(peer_public))

        encrypted = recv_blob(conn)
        plaintext = decrypt_payload(key, encrypted)
        print("AES-GCM decryption: OK", flush=True)
        print("Received plaintext:", plaintext.decode(), flush=True)

        send_blob(conn, b"PC2 decrypted the message successfully")
