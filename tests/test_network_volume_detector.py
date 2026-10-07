from datetime import datetime, timedelta, timezone

from core.network_volume_detector import NetworkVolumeAnomalyDetector


def build_event(timestamp):
    return {
        "timestamp": timestamp.isoformat(),
    }


def test_network_volume_anomaly_is_detected():
    detector = NetworkVolumeAnomalyDetector(
        window_seconds=10,
        baseline_samples=3,
        threshold_multiplier=3,
    )

    start = datetime(2026, 10, 7, 18, 0, 0, tzinfo=timezone.utc)

    normal_event_offsets = [
        0, 1,
        10, 11,
        20, 21,
        30,
    ]

    for seconds in normal_event_offsets:
        alert = detector.process_event(
            build_event(start + timedelta(seconds=seconds))
        )
        assert alert is None

    assert detector.anomaly_engine.baseline == 2

    anomaly_event_offsets = [31, 32, 33, 34, 35, 36]

    for seconds in anomaly_event_offsets:
        alert = detector.process_event(
            build_event(start + timedelta(seconds=seconds))
        )
        assert alert is None

    alert = detector.process_event(
        build_event(start + timedelta(seconds=40))
    )

    assert alert is not None
    assert alert["type"] == "anomaly"
    assert alert["baseline"] == 2
    assert alert["current_value"] == 7
    assert alert["threshold"] == 6
