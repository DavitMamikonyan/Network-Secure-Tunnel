import socket
import struct
from pathlib import Path
from netfilterqueue import NetfilterQueue

TARGET_PORT = 5001
KEY_PATH = Path("/tmp/network3_device1.key")


def handle_packet(packet):
    raw = packet.get_payload()

    try:
        if len(raw) < 20 or raw[0] >> 4 != 4:
            packet.accept()
            return

        ip_header_len = (raw[0] & 0x0F) * 4
        if len(raw) < ip_header_len + 20 or raw[9] != socket.IPPROTO_TCP:
            packet.accept()
            return

        total_len = struct.unpack("!H", raw[2:4])[0]
        tcp_start = ip_header_len
        src_port, dst_port = struct.unpack("!HH", raw[tcp_start:tcp_start + 4])
        tcp_header_len = (raw[tcp_start + 12] >> 4) * 4
        payload_start = tcp_start + tcp_header_len
        payload_end = min(total_len, len(raw))
        payload_len = max(0, payload_end - payload_start)

        if src_port == TARGET_PORT or dst_port == TARGET_PORT:
            src_ip = socket.inet_ntoa(raw[12:16])
            dst_ip = socket.inet_ntoa(raw[16:20])
            key_status = "present" if KEY_PATH.is_file() and KEY_PATH.stat().st_size == 32 else "missing/invalid"
            print(
                f"TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                f"payload={payload_len}; session key: {key_status}",
                flush=True,
            )
    except (IndexError, struct.error, OSError, ValueError) as exc:
        print(f"Probe error: {exc}", flush=True)
    finally:
        packet.accept()


nfqueue = NetfilterQueue()
try:
    nfqueue.bind(10, handle_packet)
    print("Secure probe listening on NFQUEUE 10; packets are NOT modified.", flush=True)
    nfqueue.run()
except KeyboardInterrupt:
    print("Stopping secure probe", flush=True)
finally:
    nfqueue.unbind()
