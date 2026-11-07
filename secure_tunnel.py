import socket
import struct
import threading
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEVICE1 = ("10.0.1.1", 5001)
DEVICE2 = ("10.0.12.2", 4446)
PC2 = ("10.0.2.2", 5001)
MAX_FRAME = 65536

def recv_exact(sock, size):
data = bytearray()
while len(data) < size:
part = sock.recv(size - len(data))
if not part:
if not data:
return None
raise ConnectionError("Incomplete frame")
data.extend(part)
return bytes(data)

def send_encrypted(sock, aes, plaintext):
nonce = import("os").urandom(12)
ciphertext = aes.encrypt(nonce, plaintext, None)
frame = nonce + ciphertext
sock.sendall(struct.pack("!I", len(frame)) + frame)

def recv_decrypted(sock, aes):
header = recv_exact(sock, 4)
if header is None:
return None
size = struct.unpack("!I", header)[0]
if not 28 <= size <= MAX_FRAME:
raise ValueError(f"Invalid encrypted frame size: {size}")
frame = recv_exact(sock, size)
if frame is None:
raise ConnectionError("Missing encrypted frame")
return aes.decrypt(frame[:12], frame[12:], None)

def pump(src, dst, mode, aes):
try:
while True:
if mode == "decrypt":
data = recv_decrypted(src, aes)
if data is None:
break
else:
data = src.recv(16384)
if not data:
break
if mode == "encrypt":
send_encrypted(dst, aes, data)
continue
dst.sendall(data)
except (OSError, ValueError) as exc:
print(f"Tunnel stream ended: {exc}", flush=True)
finally:
try:
dst.shutdown(socket.SHUT_WR)
except OSError:
pass

def relay(sock_a, sock_b, mode_a_to_b, mode_b_to_a, aes):
threads = [
threading.Thread(
target=pump, args=(sock_a, sock_b, mode_a_to_b, aes), daemon=True
),
threading.Thread(
target=pump, args=(sock_b, sock_a, mode_b_to_a, aes), daemon=True
),
]
for thread in threads:
thread.start()
for thread in threads:
thread.join()
sock_a.close()
sock_b.close()

def handle_device2(tunnel_sock, aes):
try:
pc2_sock = socket.create_connection(PC2, timeout=10)
pc2_sock.settimeout(None)
print("Device2 connected to PC2", flush=True)
# Tunnel -> PC2 is decrypted; PC2 -> tunnel is encrypted.
relay(tunnel_sock, pc2_sock, "decrypt", "encrypt", aes)
except OSError as exc:
print(f"Device2 connection error: {exc}", flush=True)
tunnel_sock.close()

def main():
if len(sys.argv) != 2 or sys.argv[1] not in ("device1", "device2"):
raise SystemExit("Usage: secure_tunnel.py device1|device2")

role = sys.argv[1]
key_path = Path(
    "/tmp/network3_device1.key" if role == "device1"
    else "/tmp/network3_device2.key"
)
key = key_path.read_bytes()
if len(key) != 32:
    raise ValueError(f"Expected a 32-byte session key in {key_path}")
aes = AESGCM(key)

if role == "device1":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(DEVICE1)
    server.listen(5)
    print(f"Device1 proxy listening on {DEVICE1[0]}:{DEVICE1[1]}", flush=True)

    while True:
        client, address = server.accept()
        print(f"PC1 connected: {address}", flush=True)
        try:
            tunnel = socket.create_connection(DEVICE2, timeout=10)
            tunnel.settimeout(None)
            print("Secure tunnel connected to Device2", flush=True)
            # Local PC1 -> tunnel is encrypted; reverse tunnel data is decrypted.
            threading.Thread(
                target=relay,
                args=(client, tunnel, "encrypt", "decrypt", aes),
                daemon=True,
            ).start()
        except OSError as exc:
            print(f"Device2 connection error: {exc}", flush=True)
            client.close()

else:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(DEVICE2)
    server.listen(5)
    print(f"Device2 tunnel listening on {DEVICE2[0]}:{DEVICE2[1]}", flush=True)

    while True:
        tunnel, address = server.accept()
        print(f"Device1 tunnel connected: {address}", flush=True)
        threading.Thread(
            target=handle_device2, args=(tunnel, aes), daemon=True
        ).start()

if name == "main":
main()
