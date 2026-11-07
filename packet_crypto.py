import socket
import struct

from crypto_utils import encrypt_payload, decrypt_payload


IPPROTO_TCP = socket.IPPROTO_TCP
TARGET_PORT = 5001


def parse_ipv4_tcp(packet):
    """Return parsed IPv4/TCP fields, or None for unsupported packets."""
    if len(packet) < 40 or packet[0] >> 4 != 4:
        return None

    ip_header_len = (packet[0] & 0x0F) * 4
    if ip_header_len < 20 or len(packet) < ip_header_len + 20:
        return None

    total_len = struct.unpack("!H", packet[2:4])[0]
    if total_len < ip_header_len + 20 or total_len > len(packet):
        return None

    if packet[9] != IPPROTO_TCP:
        return None

    # Skip fragmented IPv4 packets in this first implementation.
    frag_field = struct.unpack("!H", packet[6:8])[0]
    if frag_field & 0x3FFF:
        return None

    tcp_start = ip_header_len
    tcp_header_len = (packet[tcp_start + 12] >> 4) * 4
    if tcp_header_len < 20 or tcp_start + tcp_header_len > total_len:
        return None

    src_port, dst_port = struct.unpack("!HH", packet[tcp_start:tcp_start + 4])
    payload_start = tcp_start + tcp_header_len

    return {
        "ip_header_len": ip_header_len,
        "total_len": total_len,
        "tcp_start": tcp_start,
        "tcp_header_len": tcp_header_len,
        "payload_start": payload_start,
        "src_port": src_port,
        "dst_port": dst_port,
    }


def internet_checksum(data):
    """Compute the standard Internet checksum."""
    if len(data) & 1:
        data += b"\x00"

    words = struct.unpack("!" + "H" * (len(data) // 2), data)
    total = sum(words)

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def replace_tcp_payload(packet, new_payload):
    """Replace TCP payload and recalculate IPv4/TCP lengths and checksums."""
    fields = parse_ipv4_tcp(packet)
    if fields is None:
        raise ValueError("Unsupported or malformed IPv4/TCP packet")

    ip_len = fields["ip_header_len"]
    tcp_start = fields["tcp_start"]
    payload_start = fields["payload_start"]
    old_total_len = fields["total_len"]

    # Preserve the original IP and TCP headers byte-for-byte except for
    # fields that must change when payload length changes.
    result = bytearray(
        packet[:payload_start] + new_payload + packet[old_total_len:]
    )
    new_total_len = old_total_len + len(new_payload) - (old_total_len - payload_start)
    if new_total_len > 65535:
        raise ValueError("IPv4 packet would exceed maximum length")

    struct.pack_into("!H", result, 2, new_total_len)

    # IPv4 header checksum.
    struct.pack_into("!H", result, 10, 0)
    ip_checksum = internet_checksum(bytes(result[:ip_len]))
    struct.pack_into("!H", result, 10, ip_checksum)

    # TCP checksum covers pseudo-header plus TCP header and payload.
    struct.pack_into("!H", result, tcp_start + 16, 0)
    src_ip = bytes(result[12:16])
    dst_ip = bytes(result[16:20])
    tcp_segment = bytes(result[tcp_start:new_total_len])
    pseudo_header = (
        src_ip + dst_ip + b"\x00" + bytes([IPPROTO_TCP])
        + struct.pack("!H", len(tcp_segment))
    )
    tcp_checksum = internet_checksum(pseudo_header + tcp_segment)
    struct.pack_into("!H", result, tcp_start + 16, tcp_checksum)

    return bytes(result)


def encrypt_packet_payload(packet, key):
    fields = parse_ipv4_tcp(packet)
    if fields is None or fields["dst_port"] != TARGET_PORT:
        return packet, False

    start = fields["payload_start"]
    end = fields["total_len"]
    payload = packet[start:end]
    if not payload:
        return packet, False

    encrypted = encrypt_payload(key, payload)
    return replace_tcp_payload(packet[:fields["total_len"]], encrypted), True


def decrypt_packet_payload(packet, key):
    fields = parse_ipv4_tcp(packet)
    if fields is None or fields["dst_port"] != TARGET_PORT:
        return packet, False

    start = fields["payload_start"]
    end = fields["total_len"]
    payload = packet[start:end]
    if len(payload) < 28:
        return packet, False

    try:
        plaintext = decrypt_payload(key, payload)
    except Exception:
        return packet, False

    return replace_tcp_payload(packet[:fields["total_len"]], plaintext), True
