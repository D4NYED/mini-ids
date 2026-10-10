class SecurityPipeline:
    def __init__(self, detection_pipeline, correlation_engine):
        self.detection_pipeline = detection_pipeline
        self.correlation_engine = correlation_engine

    def process_event(self, event):
        alerts = self.detection_pipeline.process_event(event)
        incidents = []

        for alert in alerts:
            incident = self.correlation_engine.process_alert(alert)

            if incident is not None:
                incidents.append(incident)

        return {
            "alerts": alerts,
            "incidents": incidents,
        }
