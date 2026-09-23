from datetime import datetime, timezone

from core.signature_engine import SignatureEngine


def build_syn_event(destination_port):
    return {
        "event_id": f"test-{destination_port}",
        "event_type": "network",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": "TCP",
        "src_ip": "192.168.56.128",
        "src_port": 40000,
        "dst_ip": "192.168.56.129",
        "dst_port": destination_port,
        "tcp_flags": "S",
        "packet_length": 60,
    }


def test_tcp_syn_scan_detection():
    engine = SignatureEngine()

    alerts = []

    for port in range(20, 30):
        event = build_syn_event(port)
        alerts.extend(engine.process_event(event))

    assert alerts

    alert = alerts[-1]

    assert alert["signature_id"] == "NET-001"
    assert alert["signature_name"] == "TCP SYN Scan"
    assert alert["severity"] == "medium"
    assert alert["src_ip"] == "192.168.56.128"
    assert alert["dst_ip"] == "192.168.56.129"
    assert alert["evidence"]["unique_destination_ports"] >= 10

def test_normal_tcp_traffic_does_not_trigger_syn_scan():
    engine = SignatureEngine()

    alerts = []

    event = build_syn_event(22)

    alerts.extend(engine.process_event(event))

    assert alerts == []