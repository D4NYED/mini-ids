import json
from pathlib import Path


class JsonlStorage:
    """Persist security alerts and incidents as JSON Lines."""

    def __init__(self, file_path):
        self.file_path = Path(file_path)

    def write_record(self, record_type, data):
        record = {
            "record_type": record_type,
            "data": data,
        }

        self.file_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self.file_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(record, ensure_ascii=False) + "\n")
