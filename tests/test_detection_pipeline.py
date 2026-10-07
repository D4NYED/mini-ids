from core.detection_pipeline import DetectionPipeline


class FakeSignatureEngine:
    def process_event(self, event):
        return [
            {
                "type": "signature",
                "signature_id": "TEST-001",
            }
        ]


class FakeAnomalyDetector:
    def process_event(self, event):
        return {
            "type": "anomaly",
            "current_value": 20,
        }


class FakeAnomalyDetectorWithoutAlert:
    def process_event(self, event):
        return None


def test_pipeline_combines_signature_and_anomaly_alerts():
    pipeline = DetectionPipeline(
        signature_engine=FakeSignatureEngine(),
        anomaly_detector=FakeAnomalyDetector(),
    )

    event = {
        "event_type": "network",
    }

    alerts = pipeline.process_event(event)

    assert len(alerts) == 2
    assert alerts[0]["type"] == "signature"
    assert alerts[0]["signature_id"] == "TEST-001"
    assert alerts[1]["type"] == "anomaly"
    assert alerts[1]["current_value"] == 20


def test_pipeline_returns_signature_alerts_when_no_anomaly_exists():
    pipeline = DetectionPipeline(
        signature_engine=FakeSignatureEngine(),
        anomaly_detector=FakeAnomalyDetectorWithoutAlert(),
    )

    event = {
        "event_type": "network",
    }

    alerts = pipeline.process_event(event)

    assert len(alerts) == 1
    assert alerts[0]["signature_id"] == "TEST-001"
