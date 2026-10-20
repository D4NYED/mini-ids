class AlertManager:
    def process_result(self, result):
        alerts = result.get("alerts", [])
        incidents = result.get("incidents", [])

        for alert in alerts:
            print(f"[ALERT] {alert}")

        for incident in incidents:
            print(f"[INCIDENT] {incident}")
