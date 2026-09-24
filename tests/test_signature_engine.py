import uuid
from datetime import datetime, timedelta, timezone

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
    assert len(alerts) == 1

def test_normal_tcp_traffic_does_not_trigger_syn_scan():
    engine = SignatureEngine()

    alerts = []

    event = build_syn_event(22)

    alerts.extend(engine.process_event(event))

    assert alerts == []

def build_ssh_attempt_event(timestamp, source_port):
    return {
        "event_id": str(uuid.uuid4()),
        "event_type": "network",
        "timestamp": timestamp.isoformat(),
        "protocol": "TCP",
        "src_ip": "192.168.56.128",
        "src_port": source_port,
        "dst_ip": "192.168.56.129",
        "dst_port": 22,
        "tcp_flags": "S",
        "packet_length": 60,
    }


def test_ssh_brute_force_detection():
    engine = SignatureEngine()

    start_time = datetime.now(timezone.utc)

    alerts = []

    for index in range(5):
        event = build_ssh_attempt_event(
            start_time + timedelta(seconds=index),
            40000 + index,
        )
        alerts.extend(engine.process_event(event))

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["signature_id"] == "NET-002"
    assert alert["signature_name"] == "SSH Brute Force"
    assert alert["severity"] == "high"
    assert alert["src_ip"] == "192.168.56.128"
    assert alert["dst_ip"] == "192.168.56.129"
    assert alert["evidence"]["connection_attempts"] >= 5
    assert alert["evidence"]["destination_port"] == 22
    assert alert["evidence"]["time_window_seconds"] == 10

def test_normal_ssh_connection_does_not_trigger_brute_force():
    engine = SignatureEngine()

    event = build_ssh_attempt_event(
        datetime.now(timezone.utc),
        40000,
    )

    alerts = engine.process_event(event)

    assert alerts == []