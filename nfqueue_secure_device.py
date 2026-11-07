import argparse
import logging
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from netfilterqueue import NetfilterQueue

from crypto_utils import fingerprint
from packet_crypto import parse_ipv4_tcp, replace_tcp_payload, decrypt_payload

KEY_PATHS = {
    "device1": Path("/tmp/network3_device1.key"),
    "device2": Path("/tmp/network3_device2.key"),
}

PC1 = "10.0.1.2"
PC2 = "10.0.2.2"
TARGET_PORT = 5001
DEFAULT_QUEUE = 10


class NonceSequence:
    """Unique 96-bit nonces within this handler process."""
    def __init__(self):
        self.prefix = os.urandom(4)
        self.counter = 0

    def next(self):
        if self.counter >= 2**64:
            raise RuntimeError("AES-GCM nonce counter exhausted")
        nonce = self.prefix + self.counter.to_bytes(8, "big")
        self.counter += 1
        return nonce


def load_key(path):
    key = path.read_bytes()
    if len(key) != 32:
        raise ValueError(f"Expected a 32-byte AES key: {path}")
    return key


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", choices=("device1", "device2"), required=True)
    parser.add_argument("--queue", type=int, default=DEFAULT_QUEUE)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    key = load_key(KEY_PATHS[args.device])
    aes = AESGCM(key)
    nonces = NonceSequence()

    logging.info(
        "%s ready; key fingerprint=%s; queue=%d",
        args.device, fingerprint(key)[:16], args.queue,
    )

    def handle_packet(packet):
        raw = packet.get_payload()

        try:
            fields = parse_ipv4_tcp(raw)
            if fields is None:
                packet.accept()
                return

            # Protect only PC1 -> PC2 TCP traffic addressed to port 5001.
            if (
                raw[12:16] != bytes((10, 0, 1, 2))
                or raw[16:20] != bytes((10, 0, 2, 2))
                or fields["dst_port"] != TARGET_PORT
            ):
                packet.accept()
                return

            start = fields["payload_start"]
            end = fields["total_len"]
            payload = raw[start:end]

            # TCP SYN/ACK/FIN packets without application data need no crypto.
            if not payload:
                packet.accept()
                return

            if args.device == "device1":
                nonce = nonces.next()
                protected = nonce + aes.encrypt(nonce, payload, None)
                updated = replace_tcp_payload(raw[:end], protected)
                packet.set_payload(updated)
                packet.accept()
                logging.info(
                    "ENCRYPTED id=%s payload=%d->%d",
                    packet.id, len(payload), len(protected),
                )
                return

            # Device2 expects every non-empty payload in this selected flow
            # to be protected. Do not pass unauthenticated data to PC2.
            if len(payload) < 28:
                logging.error("DROP: protected payload too short; id=%s", packet.id)
                packet.drop()
                return

            try:
                plaintext = decrypt_payload(key, payload)
            except (InvalidTag, ValueError):
                logging.error("DROP: AES-GCM authentication failed; id=%s", packet.id)
                packet.drop()
                return

            updated = replace_tcp_payload(raw[:end], plaintext)
            packet.set_payload(updated)
            packet.accept()
            logging.info(
                "DECRYPTED id=%s payload=%d->%d",
                packet.id, len(payload), len(plaintext),
            )

        except Exception:
            logging.exception("Packet processing error; dropping queued packet")
            packet.drop()

    queue = NetfilterQueue()
    try:
        queue.bind(args.queue, handle_packet)
        logging.info("%s listening on NFQUEUE %d", args.device, args.queue)
        queue.run()
    except KeyboardInterrupt:
        logging.info("Stopping %s", args.device)
    finally:
        try:
            queue.unbind()
        except Exception:
            pass


if __name__ == "__main__":
    main()
