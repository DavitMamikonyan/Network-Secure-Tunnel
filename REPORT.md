# Network3 — Secure Inline Communication Prototype

## 1. Architecture
The prototype uses four Linux network namespaces:
PC1 -> Device1 -> Device2 -> PC2.

Device1 and Device2 forward selected IPv4/TCP traffic. The tested protected
flow is PC1 (10.0.1.2) to PC2 (10.0.2.2), TCP destination port 5001.

## 2. Session establishment
Device1 and Device2 perform an X25519 Diffie-Hellman key exchange.
HKDF-SHA256 derives a 256-bit AES session key. The handshake test showed
matching session-key fingerprints on both devices.

## 3. Packet protection
Device1 encrypts the selected TCP payload with AES-GCM. A 12-byte nonce
and a 16-byte authentication tag accompany the ciphertext inside the TCP
payload. The IP and TCP headers are retained, with packet lengths and
checksums recalculated.

Device2 authenticates and decrypts the protected payload, restores the
original payload, recalculates lengths and checksums, and forwards the packet.
Packets that fail authentication are dropped.

## 4. Test evidence
- Both devices derived matching session keys.
- Device1 logged payload growth from 25 to 53 bytes.
- Device2 logged payload restoration from 53 to 25 bytes.
- Packet capture on the Device1–Device2 link showed ciphertext bytes.
- PC2 received the original plaintext test message.
- NFQUEUE rules were removed and handler processes stopped after testing.
- A separate AES-GCM test rejected modified ciphertext and successfully
  decrypted the original ciphertext.

## 5. Limitations
The demonstrated protected flow is one-way: PC1 to PC2 on TCP port 5001.
Large packets, MTU/fragmentation behavior, and sustained traffic have not
been fully tested. This is a prototype rather than a production-ready VPN.

## 6. Main implementation files
- device1_handshake.py
- device2_handshake.py
- crypto_utils.py
- packet_crypto.py
- nfqueue_secure_device.py
