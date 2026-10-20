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
