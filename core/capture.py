from scapy.all import ARP, ICMP, IP, TCP, UDP, sniff


INTERFACE = "ens36"


def normalize_packet(packet):
    event = {
        "event_type": "network",
        "protocol": None,
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "tcp_flags": None,
        "packet_length": len(packet),
    }

    if packet.haslayer(ARP):
        arp_layer = packet[ARP]

        return {
            "event_type": "network",
            "protocol": "ARP",
            "src_ip": arp_layer.psrc,
            "src_port": None,
            "dst_ip": arp_layer.pdst,
            "dst_port": None,
            "tcp_flags": None,
            "packet_length": len(packet),
        }

    if not packet.haslayer(IP):
        event["protocol"] = "OTHER"
        return event

    ip_layer = packet[IP]

    event["src_ip"] = ip_layer.src
    event["dst_ip"] = ip_layer.dst

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        event["protocol"] = "TCP"
        event["src_port"] = tcp_layer.sport
        event["dst_port"] = tcp_layer.dport
        event["tcp_flags"] = str(tcp_layer.flags)

    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        event["protocol"] = "UDP"
        event["src_port"] = udp_layer.sport
        event["dst_port"] = udp_layer.dport

    elif packet.haslayer(ICMP):
        event["protocol"] = "ICMP"

    else:
        event["protocol"] = ip_layer.proto

    return event


def packet_callback(packet):
    event = normalize_packet(packet)
    print(event)


def start_capture():
    print(f"[+] Starting packet capture on {INTERFACE}")

    sniff(
        iface=INTERFACE,
        prn=packet_callback,
        store=False,
    )


if __name__ == "__main__":
    start_capture()