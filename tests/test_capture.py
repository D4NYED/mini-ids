from scapy.all import IP, TCP, Raw

from core.capture import normalize_packet


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