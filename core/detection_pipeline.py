class DetectionPipeline:
    def __init__(self, signature_engine, anomaly_detector):
        self.signature_engine = signature_engine
        self.anomaly_detector = anomaly_detector

    def process_event(self, event):
        alerts = self.signature_engine.process_event(event)

        anomaly_alert = self.anomaly_detector.process_event(event)

        if anomaly_alert is not None:
            alerts.append(anomaly_alert)

        return alerts
