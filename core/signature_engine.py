from collections import defaultdict, deque
from curses import window
from curses import window
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml


RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "signatures.yaml"


class SignatureEngine:
    """Load and evaluate Mini-IDS signature rules."""

    def __init__(self, rules_file=RULES_FILE):
        self.rules_file = Path(rules_file)
        self.signatures = self._load_rules()
        self._events = defaultdict(deque)
        self._alerted = set()

    def _detect_ssh_brute_force(self, signature, event):
        if event.get("protocol") != "TCP":
            return None

        if event.get("tcp_flags") != "S":
            return None

        if event.get("dst_port") != 22:
            return None

        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        timestamp = self._parse_timestamp(event.get("timestamp"))

        if not src_ip or not dst_ip or not timestamp:
            return None

        key = (src_ip, dst_ip)

        if not hasattr(self, "_ssh_attempts"):
            self._ssh_attempts = defaultdict(deque)

        if not hasattr(self, "_ssh_alerted"):
            self._ssh_alerted = set()

        attempts = self._ssh_attempts[key]

        window = signature["detection"]["threshold"]["time_window_seconds"]
        minimum_attempts = signature["detection"]["threshold"]["connection_attempts"]

        cutoff = timestamp - timedelta(seconds=window)

        attempts.append(timestamp)

        while attempts and attempts[0] < cutoff:
            attempts.popleft()

        if len(attempts) < minimum_attempts:
            self._ssh_alerted.discard(key)
            return None

        if key in self._ssh_alerted:
            return None

        self._ssh_alerted.add(key)

        return {
            "signature_id": signature["id"],
            "signature_name": signature["name"],
            "severity": signature["severity"],
            "timestamp": timestamp.isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "evidence": {
                "connection_attempts": len(attempts),
                "destination_port": 22,
                "time_window_seconds": window,
            },
        }

    def _load_rules(self):
        """Load signature definitions from the YAML rules file."""
        if not self.rules_file.exists():
            raise FileNotFoundError(
                f"Signature rules file not found: {self.rules_file}"
            )

        with self.rules_file.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}

        signatures = data.get("signatures")

        if not isinstance(signatures, list):
            raise ValueError(
                "Invalid signature rules format: 'signatures' must be a list"
            )

        return signatures

    def get_signatures(self):
        """Return all loaded signature definitions."""
        return self.signatures

    def process_event(self, event):
        """Evaluate a normalized network event against loaded signatures."""
        alerts = []

        for signature in self.signatures:
            if not signature.get("enabled", True):
                continue

            alert = None

            if signature.get("id") == "NET-001":
                alert = self._detect_tcp_syn_scan(event, signature)

            elif signature.get("id") == "NET-002":
                alert = self._detect_ssh_brute_force(signature, event)

            if alert:
                alerts.append(alert)

        return alerts

    def _detect_tcp_syn_scan(self, event, signature):
        """Detect multiple TCP SYN packets targeting different ports."""
        detection = signature["detection"]

        if event.get("protocol") != detection["protocol"]:
            return None

        if event.get("tcp_flags") != detection["tcp_flags"]:
            return None

        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        dst_port = event.get("dst_port")

        if not src_ip or not dst_ip or dst_port is None:
            return None

        timestamp = self._parse_timestamp(event.get("timestamp"))

        key = (src_ip, dst_ip)
        events = self._events[key]

        window = detection["threshold"]["time_window_seconds"]
        minimum_ports = detection["threshold"]["unique_destination_ports"]

        cutoff = timestamp - timedelta(seconds=window)

        events.append((timestamp, dst_port))

        while events and events[0][0] < cutoff:
            events.popleft()

        unique_ports = {port for _, port in events}

        if len(unique_ports) < minimum_ports:
            self._alerted.discard(key)
            return None
        if key in self._alerted:
            return None

        self._alerted.add(key)

        return {
            "signature_id": signature["id"],
            "signature_name": signature["name"],
            "severity": signature["severity"],
            "timestamp": timestamp.isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "evidence": {
                "unique_destination_ports": len(unique_ports),
                "time_window_seconds": window,
            },
        }

    @staticmethod
    def _parse_timestamp(timestamp):
        """Parse an event timestamp into an aware UTC datetime."""
        if not timestamp:
            return datetime.now(timezone.utc)

        parsed = datetime.fromisoformat(timestamp)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)


if __name__ == "__main__":
    engine = SignatureEngine()

    print(f"[+] Loaded {len(engine.get_signatures())} signature(s)")

    for signature in engine.get_signatures():
        print(f"    - {signature['id']}: {signature['name']}")