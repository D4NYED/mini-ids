from core.alert_manager import AlertManager


def test_alert_manager_prints_alerts_and_incidents(capsys):
    manager = AlertManager()

    result = {
        "alerts": [
            {
                "signature_id": "NET-001",
            }
        ],
        "incidents": [
            {
                "correlation_id": "COR-001",
            }
        ],
    }

    manager.process_result(result)

    captured = capsys.readouterr()

    assert "[ALERT]" in captured.out
    assert "NET-001" in captured.out
    assert "[INCIDENT]" in captured.out
    assert "COR-001" in captured.out


def test_alert_manager_forwards_results_to_storage(capsys):
    class FakeStorage:
        def __init__(self):
            self.records = []

        def write_record(self, record_type, data):
            self.records.append((record_type, data))

    storage = FakeStorage()
    manager = AlertManager(storage=storage)

    alert = {"signature_id": "NET-001"}
    incident = {"correlation_id": "COR-001"}

    manager.process_result({
        "alerts": [alert],
        "incidents": [incident],
    })

    assert storage.records == [
        ("alert", alert),
        ("incident", incident),
    ]

    captured = capsys.readouterr()

    assert "[ALERT]" in captured.out
    assert "[INCIDENT]" in captured.out
