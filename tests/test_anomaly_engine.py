from core.anomaly_engine import AnomalyEngine


def test_baseline_is_created_after_enough_measurements():
    engine = AnomalyEngine(
        baseline_samples=5,
        threshold_multiplier=3,
    )

    measurements = [8, 11, 10, 9, 12]

    for value in measurements:
        engine.add_measurement(value)

    assert engine.baseline == 10


def test_anomaly_is_detected_when_threshold_is_exceeded():
    engine = AnomalyEngine(
        baseline_samples=5,
        threshold_multiplier=3,
    )

    measurements = [8, 11, 10, 9, 12]

    for value in measurements:
        engine.add_measurement(value)

    alert = engine.check_anomaly(31)

    assert alert is not None
    assert alert["type"] == "anomaly"
    assert alert["baseline"] == 10
    assert alert["current_value"] == 31
    assert alert["threshold"] == 30


def test_normal_value_does_not_trigger_anomaly():
    engine = AnomalyEngine(
        baseline_samples=5,
        threshold_multiplier=3,
    )

    measurements = [8, 11, 10, 9, 12]

    for value in measurements:
        engine.add_measurement(value)

    alert = engine.check_anomaly(25)

    assert alert is None


def test_no_anomaly_is_checked_during_learning_phase():
    engine = AnomalyEngine(
        baseline_samples=5,
        threshold_multiplier=3,
    )

    measurements = [8, 11, 10]

    for value in measurements:
        engine.add_measurement(value)

    alert = engine.check_anomaly(100)

    assert engine.baseline is None
    assert alert is None
