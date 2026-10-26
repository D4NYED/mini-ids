import json

from core.jsonl_storage import JsonlStorage


def test_jsonl_storage_appends_alerts_and_incidents(tmp_path):
    log_file = tmp_path / "logs" / "security_events.jsonl"

    storage = JsonlStorage(log_file)

    alert = {
        "signature_id": "NET-001",
        "severity": "medium",
    }

    incident = {
        "correlation_id": "COR-001",
        "severity": "high",
    }

    storage.write_record("alert", alert)
    storage.write_record("incident", incident)

    records = [
        json.loads(line)
        for line in log_file.read_text(encoding="utf-8").splitlines()
    ]

    assert records == [
        {"record_type": "alert", "data": alert},
        {"record_type": "incident", "data": incident},
    ]
