from __future__ import annotations


class AlertEngine:
    def __init__(self, high_pps: float = 1000.0):
        self.high_pps = high_pps
        self._seen_ips: set[str] = set()
        self._seen_macs: set[str] = set()

    def evaluate(self, snapshot: dict) -> list[dict]:
        alerts: list[dict] = []
        for row in snapshot.get("ips", [])[:200]:
            ip = row["ip"]
            if ip not in self._seen_ips:
                self._seen_ips.add(ip)
                alerts.append({"level": "info", "kind": "new-ip", "message": f"New source IP {ip}"})
            if row.get("pps", 0.0) >= self.high_pps:
                alerts.append(
                    {
                        "level": "warn",
                        "kind": "high-pps",
                        "message": f"{ip} is sending {row['pps']:.0f} pps",
                    }
                )
        for row in snapshot.get("macs", [])[:200]:
            mac = row["mac"]
            if mac and mac not in self._seen_macs:
                self._seen_macs.add(mac)
                alerts.append({"level": "info", "kind": "new-mac", "message": f"New MAC {mac}"})
        return alerts[-12:]

