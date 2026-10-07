from datetime import datetime

from core.anomaly_engine import AnomalyEngine
from core.measurement_window import MeasurementWindow


class NetworkVolumeAnomalyDetector:
    def __init__(
        self,
        window_seconds=10,
        baseline_samples=10,
        threshold_multiplier=3,
    ):
        self.measurement_window = MeasurementWindow(
            window_seconds=window_seconds,
        )

        self.anomaly_engine = AnomalyEngine(
            baseline_samples=baseline_samples,
            threshold_multiplier=threshold_multiplier,
        )

    def process_event(self, event):
        timestamp = datetime.fromisoformat(event["timestamp"])

        measurement = self.measurement_window.add_event(timestamp)

        if measurement is None:
            return None

        if self.anomaly_engine.baseline is None:
            self.anomaly_engine.add_measurement(measurement)
            return None

        return self.anomaly_engine.check_anomaly(measurement)
