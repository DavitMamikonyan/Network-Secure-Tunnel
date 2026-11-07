import socket
import struct
from netfilterqueue import NetfilterQueue

TARGET_PORT = 5001

def handle_packet(packet):
    raw = packet.get_payload()

    try:
        if len(raw) < 20:
            print(f"Skip short packet: {len(raw)} bytes", flush=True)
            packet.accept()
            return

        version = raw[0] >> 4
        if version != 4:
            packet.accept()
            return

        ip_header_len = (raw[0] & 0x0F) * 4
        if len(raw) < ip_header_len + 20:
            packet.accept()
            return

        protocol = raw[9]
        if protocol != socket.IPPROTO_TCP:
            packet.accept()
            return

        total_len = struct.unpack("!H", raw[2:4])[0]
        src_ip = socket.inet_ntoa(raw[12:16])
        dst_ip = socket.inet_ntoa(raw[16:20])

        tcp_start = ip_header_len
        src_port, dst_port = struct.unpack("!HH", raw[tcp_start:tcp_start + 4])
        tcp_header_len = (raw[tcp_start + 12] >> 4) * 4
        payload_start = tcp_start + tcp_header_len
        payload_len = max(0, min(total_len, len(raw)) - payload_start)

        if src_port == TARGET_PORT or dst_port == TARGET_PORT:
            print(
                f"TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                f"packet={len(raw)} payload={payload_len}",
                flush=True,
            )

    except (IndexError, struct.error, OSError, ValueError) as exc:
        print(f"Packet inspection error: {exc}", flush=True)
    finally:
        packet.accept()

nfqueue = NetfilterQueue()

try:
    nfqueue.bind(10, handle_packet)
    print("Inspecting IPv4/TCP packets on NFQUEUE 10...", flush=True)
    nfqueue.run()
except KeyboardInterrupt:
    print("Stopping inspection handler", flush=True)
finally:
    nfqueue.unbind()
