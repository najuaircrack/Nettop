from __future__ import annotations

import csv
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path


def write_snapshot_json(path: str, snapshot: dict) -> None:
    Path(path).write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")


def write_top_csv(path: str, snapshot: dict) -> None:
    rows = snapshot.get("ips", [])
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "ip",
                "packets",
                "bytes",
                "pps",
                "pps_10s",
                "pps_60s",
                "peak_pps",
                "low_pps",
                "first_ns",
                "last_ns",
            ],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)


class JsonlEventWriter:
    def __init__(self, path: str | None):
        self.path = path
        self._handle = None
        if path:
            self._handle = open(path, "a", encoding="utf-8")

    def write(self, event) -> None:
        if not self._handle:
            return
        payload = asdict(event) if is_dataclass(event) else event
        self._handle.write(json.dumps(payload, separators=(",", ":")) + "\n")

    def close(self) -> None:
        if self._handle:
            self._handle.close()
            self._handle = None
