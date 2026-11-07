from netfilterqueue import NetfilterQueue

def handle_packet(packet):
    print(f"Packet received: id={packet.id}, length={len(packet.get_payload())}", flush=True)
    packet.accept()

nfqueue = NetfilterQueue()

try:
    nfqueue.bind(10, handle_packet)
    print("Listening on NFQUEUE 10...", flush=True)
    nfqueue.run()
except KeyboardInterrupt:
    print("Stopping NFQUEUE handler", flush=True)
finally:
    nfqueue.unbind()
