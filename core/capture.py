import uuid
from datetime import datetime, timezone

from scapy.all import ARP, ICMP, IP, TCP, UDP, sniff

from core.config import load_config
from core.detection_pipeline import DetectionPipeline
from core.network_volume_detector import NetworkVolumeAnomalyDetector
from core.signature_engine import SignatureEngine


INTERFACE = "ens36"


def normalize_packet(packet):
    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": "network",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": None,
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "tcp_flags": None,
        "packet_length": len(packet),
        "payload": None,
    }

    if packet.haslayer(ARP):
        arp_layer = packet[ARP]

        return {
            "event_id": str(uuid.uuid4()),
            "event_type": "network",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": "ARP",
            "src_ip": arp_layer.psrc,
            "src_port": None,
            "dst_ip": arp_layer.pdst,
            "dst_port": None,
            "tcp_flags": None,
            "packet_length": len(packet),
            "payload": None,
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
        if tcp_layer.dport == 80 and bytes(tcp_layer.payload):
            event["protocol"] = "HTTP"
            event["payload"] = bytes(tcp_layer.payload).decode(
                "utf-8",
                errors="replace",
            )

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


def packet_callback(packet, event_handler):
    event = normalize_packet(packet)
    event_handler(event)


def print_event(event):
    print(event)


def handle_event(event, detection_pipeline):
    print_event(event)

    alerts = detection_pipeline.process_event(event)

    for alert in alerts:
        print(f"[ALERT] {alert}")


def start_capture(event_handler):
    print(f"[+] Starting packet capture on {INTERFACE}")
    sniff(
        iface=INTERFACE,
        prn=lambda packet: packet_callback(packet, event_handler),
        store=False,
    )


if __name__ == "__main__":
    config = load_config()
    anomaly_config = config["anomaly"]

    signature_engine = SignatureEngine()

    anomaly_detector = NetworkVolumeAnomalyDetector(
        window_seconds=anomaly_config["window_seconds"],
        baseline_samples=anomaly_config["baseline_samples"],
        threshold_multiplier=anomaly_config["threshold_multiplier"],
    )

    detection_pipeline = DetectionPipeline(
        signature_engine=signature_engine,
        anomaly_detector=anomaly_detector,
    )

    start_capture(
        lambda event: handle_event(
            event,
            detection_pipeline,
        )
    )
