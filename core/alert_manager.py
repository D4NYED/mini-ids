class AlertManager:
    def __init__(self, storage=None):
        self.storage = storage

    def process_result(self, result):
        alerts = result.get("alerts", [])
        incidents = result.get("incidents", [])

        for alert in alerts:
            print(f"[ALERT] {alert}")

            if self.storage is not None:
                self.storage.write_record("alert", alert)

        for incident in incidents:
            print(f"[INCIDENT] {incident}")

            if self.storage is not None:
                self.storage.write_record("incident", incident)
