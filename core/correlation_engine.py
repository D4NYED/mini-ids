from datetime import datetime


class CorrelationEngine:
    def __init__(self, window_seconds=60):
        self.window_seconds = window_seconds
        self.recent_scans = {}

    def process_alert(self, alert):
        signature_id = alert.get("signature_id")

        if signature_id == "NET-001":
            key = (
                alert.get("src_ip"),
                alert.get("dst_ip"),
            )

            self.recent_scans[key] = alert

            return None

        if signature_id != "NET-002":
            return None

        key = (
            alert.get("src_ip"),
            alert.get("dst_ip"),
        )

        scan_alert = self.recent_scans.get(key)

        if scan_alert is None:
            return None

        scan_time = datetime.fromisoformat(
            scan_alert["timestamp"]
        )
        brute_force_time = datetime.fromisoformat(
            alert["timestamp"]
        )

        elapsed_seconds = (
            brute_force_time - scan_time
        ).total_seconds()

        if elapsed_seconds < 0:
            return None

        if elapsed_seconds > self.window_seconds:
            return None

        return {
            "correlation_id": "COR-001",
            "name": "Reconnaissance Followed by SSH Brute Force",
            "severity": "high",
            "src_ip": alert.get("src_ip"),
            "dst_ip": alert.get("dst_ip"),
            "first_seen": scan_alert["timestamp"],
            "last_seen": alert["timestamp"],
            "alerts": [
                "NET-001",
                "NET-002",
            ],
        }
