from collections import deque


class AnomalyEngine:
    def __init__(self, baseline_samples=10, threshold_multiplier=3):
        self.baseline_samples = baseline_samples
        self.threshold_multiplier = threshold_multiplier
        self.measurements = deque(maxlen=baseline_samples)
        self.baseline = None

    def add_measurement(self, value):
        if self.baseline is not None:
            return

        self.measurements.append(value)

        if len(self.measurements) < self.baseline_samples:
            return

        self.baseline = sum(self.measurements) / len(self.measurements)

    def check_anomaly(self, value):
        if self.baseline is None:
            return None

        threshold = self.baseline * self.threshold_multiplier

        if value > threshold:
            return {
                "type": "anomaly",
                "baseline": self.baseline,
                "current_value": value,
                "threshold": threshold,
            }

        return None
