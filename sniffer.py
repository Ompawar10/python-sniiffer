# sniffer.py
import scapy.all as scapy

captured_packets = []
filter_ip = None
filter_protocol = None
callback_func = None  # GUI callback

def set_filters(ip=None, protocol=None):
    global filter_ip, filter_protocol
    filter_ip = ip
    filter_protocol = protocol

def register_callback(func):
    global callback_func
    callback_func = func

def packet_callback(packet):
    if scapy.IP in packet:
        src = packet[scapy.IP].src
        dst = packet[scapy.IP].dst
        proto = packet[scapy.IP].proto

        if filter_ip and filter_ip not in (src, dst):
            return
        if filter_protocol and not packet.haslayer(filter_protocol):
            return

        captured_packets.append(packet)
        if callback_func:
            callback_func(src, dst, proto, packet.summary())

def start_sniffing():
    scapy.sniff(prn=packet_callback, store=False)

def save_packets(filepath):
    if filepath.endswith(".pcap"):
        scapy.wrpcap(filepath, captured_packets)
    else:
        with open(filepath, "w") as f:
            for pkt in captured_packets:
                f.write(pkt.summary() + "\n")

def get_packet(index):
    return captured_packets[index] if 0 <= index < len(captured_packets) else None
