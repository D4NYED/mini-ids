import json
from unittest.mock import Mock

from scapy.all import IP, TCP, Raw

from core.capture import create_alert_manager, handle_event, normalize_packet


def test_http_payload_normalization():
    payload = b"GET /search?q=test HTTP/1.1\r\nHost: 192.168.56.129\r\n\r\n"

    packet = (
        IP(src="192.168.56.128", dst="192.168.56.129")
        / TCP(sport=40000, dport=80, flags="PA")
        / Raw(load=payload)
    )

    event = normalize_packet(packet)

    assert event["protocol"] == "HTTP"
    assert event["src_ip"] == "192.168.56.128"
    assert event["dst_ip"] == "192.168.56.129"
    assert event["src_port"] == 40000
    assert event["dst_port"] == 80
    assert event["payload"] == payload.decode("utf-8")


def test_handle_event_forwards_results_to_alert_manager():
    event = {
        "event_type": "network",
    }

    result = {
        "alerts": [
            {"signature_id": "NET-001"},
        ],
        "incidents": [
            {"correlation_id": "COR-001"},
        ],
    }

    security_pipeline = Mock()
    security_pipeline.process_event.return_value = result

    alert_manager = Mock()

    handle_event(event, security_pipeline, alert_manager)

    security_pipeline.process_event.assert_called_once_with(event)
    alert_manager.process_result.assert_called_once_with(result)


def test_create_alert_manager_with_storage_disabled(tmp_path):
    log_file = tmp_path / "security_events.jsonl"

    config = {
        "storage": {
            "enabled": False,
            "path": str(log_file),
        }
    }

    manager = create_alert_manager(config)

    manager.process_result({
        "alerts": [{"signature_id": "NET-001"}],
        "incidents": [],
    })

    assert not log_file.exists()


def test_create_alert_manager_with_storage_enabled(tmp_path):
    log_file = tmp_path / "security_events.jsonl"

    config = {
        "storage": {
            "enabled": True,
            "path": str(log_file),
        }
    }

    manager = create_alert_manager(config)

    manager.process_result({
        "alerts": [{"signature_id": "NET-001"}],
        "incidents": [{"correlation_id": "COR-001"}],
    })

    records = [
        json.loads(line)
        for line in log_file.read_text(encoding="utf-8").splitlines()
    ]

    assert records == [
        {
            "record_type": "alert",
            "data": {"signature_id": "NET-001"},
        },
        {
            "record_type": "incident",
            "data": {"correlation_id": "COR-001"},
        },
    ]
