from core.security_pipeline import SecurityPipeline


class FakeDetectionPipeline:
    def process_event(self, event):
        return [
            {
                "signature_id": "NET-001",
            },
            {
                "signature_id": "NET-002",
            },
        ]


class FakeCorrelationEngine:
    def process_alert(self, alert):
        if alert["signature_id"] == "NET-002":
            return {
                "correlation_id": "COR-001",
            }

        return None


def test_security_pipeline_returns_alerts_and_incidents():
    pipeline = SecurityPipeline(
        detection_pipeline=FakeDetectionPipeline(),
        correlation_engine=FakeCorrelationEngine(),
    )

    event = {
        "event_type": "network",
    }

    result = pipeline.process_event(event)

    assert len(result["alerts"]) == 2
    assert result["alerts"][0]["signature_id"] == "NET-001"
    assert result["alerts"][1]["signature_id"] == "NET-002"

    assert len(result["incidents"]) == 1
    assert result["incidents"][0]["correlation_id"] == "COR-001"
