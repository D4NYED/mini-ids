from datetime import datetime, timedelta, timezone

from core.correlation_engine import CorrelationEngine


def build_signature_alert(
    signature_id,
    timestamp,
    src_ip="192.168.56.128",
    dst_ip="192.168.56.129",
):
    return {
        "signature_id": signature_id,
        "timestamp": timestamp.isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }


def test_syn_scan_followed_by_ssh_brute_force_creates_incident():
    engine = CorrelationEngine(window_seconds=60)

    start = datetime(2026, 10, 10, 18, 0, 0, tzinfo=timezone.utc)

    scan_alert = build_signature_alert(
        signature_id="NET-001",
        timestamp=start,
    )

    brute_force_alert = build_signature_alert(
        signature_id="NET-002",
        timestamp=start + timedelta(seconds=30),
    )

    incident = engine.process_alert(scan_alert)

    assert incident is None

    incident = engine.process_alert(brute_force_alert)

    assert incident is not None
    assert incident["correlation_id"] == "COR-001"
    assert incident["name"] == "Reconnaissance Followed by SSH Brute Force"
    assert incident["severity"] == "high"
    assert incident["src_ip"] == "192.168.56.128"
    assert incident["dst_ip"] == "192.168.56.129"
    assert incident["first_seen"] == start.isoformat()
    assert incident["last_seen"] == (
        start + timedelta(seconds=30)
    ).isoformat()
    assert incident["alerts"] == ["NET-001", "NET-002"]


def test_incident_is_not_created_outside_correlation_window():
    engine = CorrelationEngine(window_seconds=60)

    start = datetime(2026, 10, 10, 18, 0, 0, tzinfo=timezone.utc)

    scan_alert = build_signature_alert(
        signature_id="NET-001",
        timestamp=start,
    )

    brute_force_alert = build_signature_alert(
        signature_id="NET-002",
        timestamp=start + timedelta(seconds=61),
    )

    incident = engine.process_alert(scan_alert)

    assert incident is None

    incident = engine.process_alert(brute_force_alert)

    assert incident is None

def test_incident_is_not_created_for_different_destination():
    engine = CorrelationEngine(window_seconds=60)

    start = datetime(2026, 10, 10, 18, 0, 0, tzinfo=timezone.utc)

    scan_alert = build_signature_alert(
        signature_id="NET-001",
        timestamp=start,
        dst_ip="192.168.56.129",
    )

    brute_force_alert = build_signature_alert(
        signature_id="NET-002",
        timestamp=start + timedelta(seconds=30),
        dst_ip="192.168.56.130",
    )

    incident = engine.process_alert(scan_alert)

    assert incident is None

    incident = engine.process_alert(brute_force_alert)

    assert incident is None

def test_incident_is_not_created_for_different_source():
    engine = CorrelationEngine(window_seconds=60)

    start = datetime(2026, 10, 10, 18, 0, 0, tzinfo=timezone.utc)

    scan_alert = build_signature_alert(
        signature_id="NET-001",
        timestamp=start,
        src_ip="192.168.56.128",
    )

    brute_force_alert = build_signature_alert(
        signature_id="NET-002",
        timestamp=start + timedelta(seconds=30),
        src_ip="192.168.56.130",
    )

    incident = engine.process_alert(scan_alert)

    assert incident is None

    incident = engine.process_alert(brute_force_alert)

    assert incident is None

def test_incident_is_not_created_when_brute_force_happens_before_scan():
    engine = CorrelationEngine(window_seconds=60)

    start = datetime(2026, 10, 10, 18, 0, 0, tzinfo=timezone.utc)

    brute_force_alert = build_signature_alert(
        signature_id="NET-002",
        timestamp=start,
    )

    scan_alert = build_signature_alert(
        signature_id="NET-001",
        timestamp=start + timedelta(seconds=30),
    )

    incident = engine.process_alert(brute_force_alert)

    assert incident is None

    incident = engine.process_alert(scan_alert)

    assert incident is None
