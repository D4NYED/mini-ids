from datetime import datetime, timedelta, timezone

from core.measurement_window import MeasurementWindow


def test_events_inside_window_are_counted():
    window = MeasurementWindow(window_seconds=10)

    start = datetime(2026, 10, 1, 18, 0, 0, tzinfo=timezone.utc)

    assert window.add_event(start) is None
    assert window.add_event(start + timedelta(seconds=2)) is None
    assert window.add_event(start + timedelta(seconds=5)) is None

    assert window.event_count == 3


def test_measurement_is_generated_when_window_ends():
    window = MeasurementWindow(window_seconds=10)

    start = datetime(2026, 10, 1, 18, 0, 0, tzinfo=timezone.utc)

    window.add_event(start)
    window.add_event(start + timedelta(seconds=2))
    window.add_event(start + timedelta(seconds=5))

    measurement = window.add_event(start + timedelta(seconds=10))

    assert measurement == 3
    assert window.event_count == 1


def test_new_window_starts_after_previous_window_ends():
    window = MeasurementWindow(window_seconds=10)

    start = datetime(2026, 10, 1, 18, 0, 0, tzinfo=timezone.utc)

    window.add_event(start)
    window.add_event(start + timedelta(seconds=5))

    measurement = window.add_event(start + timedelta(seconds=10))

    assert measurement == 2

    assert window.add_event(start + timedelta(seconds=12)) is None
    assert window.event_count == 2
