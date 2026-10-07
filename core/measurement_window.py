from datetime import timedelta


class MeasurementWindow:
    def __init__(self, window_seconds=10):
        self.window_duration = timedelta(seconds=window_seconds)
        self.start_time = None
        self.event_count = 0

    def add_event(self, timestamp):
        if self.start_time is None:
            self.start_time = timestamp

        if timestamp - self.start_time < self.window_duration:
            self.event_count += 1
            return None

        measurement = self.event_count

        self.start_time = timestamp
        self.event_count = 1

        return measurement
