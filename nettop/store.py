from __future__ import annotations

import json
import time
from collections import Counter, defaultdict, deque
from dataclasses import asdict
from threading import Lock
from typing import Iterable

from .models import IpStats, PacketEvent


class TrafficStore:
    def __init__(self, max_events: int = 5000, rate_window: int = 60):
        self._lock = Lock()
        self.max_events = max_events
        self.rate_window = rate_window
        self.started_ns = time.time_ns()
        self.total_packets = 0
        self.total_bytes = 0
        self.filtered_packets = 0
        self.ip_stats: dict[str, IpStats] = {}
        self.dst_ip_counts: Counter[str] = Counter()
        self.proto_counts: Counter[str] = Counter()
        self.dst_port_counts: Counter[int] = Counter()
        self.src_port_counts: Counter[int] = Counter()
        self.mac_counts: Counter[str] = Counter()
        self.tcp_flags: Counter[str] = Counter()
        self.packet_sizes: Counter[str] = Counter()
        self.events: deque[PacketEvent] = deque(maxlen=max_events)
        self._ip_seconds: dict[str, Counter[int]] = defaultdict(Counter)
        self._mac_seconds: dict[str, Counter[int]] = defaultdict(Counter)
        self._total_seconds: Counter[int] = Counter()

    def record(self, event: PacketEvent) -> None:
        sec = event.ts_ns // 1_000_000_000
        bucket_floor = sec - self.rate_window
        with self._lock:
            self.total_packets += 1
            self.total_bytes += event.size
            self.events.append(event)
            self.dst_ip_counts[event.dst_ip] += 1
            self.proto_counts[event.proto] += 1
            self.dst_port_counts[event.dst_port] += 1
            self.src_port_counts[event.src_port] += 1
            if event.src_mac:
                self.mac_counts[event.src_mac] += 1
                self._mac_seconds[event.src_mac][sec] += 1
            if event.dst_mac:
                self.mac_counts[event.dst_mac] += 1
            if event.tcp_flags:
                self.tcp_flags[event.tcp_flags] += 1
            self.packet_sizes[self._size_bucket(event.size)] += 1
            self._total_seconds[sec] += 1

            stats = self.ip_stats.get(event.src_ip)
            if stats is None:
                stats = IpStats(ip=event.src_ip, first_ns=event.ts_ns)
                self.ip_stats[event.src_ip] = stats
            stats.packets += 1
            stats.bytes += event.size
            stats.last_ns = event.ts_ns
            stats.protocols[event.proto] = stats.protocols.get(event.proto, 0) + 1
            stats.dst_ports[event.dst_port] = stats.dst_ports.get(event.dst_port, 0) + 1
            stats.src_ports[event.src_port] = stats.src_ports.get(event.src_port, 0) + 1
            if event.src_mac:
                stats.macs[event.src_mac] = stats.macs.get(event.src_mac, 0) + 1
            if event.tcp_flags:
                stats.tcp_flags[event.tcp_flags] = stats.tcp_flags.get(event.tcp_flags, 0) + 1
            self._ip_seconds[event.src_ip][sec] += 1

            for counter in (self._ip_seconds[event.src_ip], self._total_seconds):
                for old in list(counter):
                    if old < bucket_floor:
                        del counter[old]
            if event.src_mac:
                for old in list(self._mac_seconds[event.src_mac]):
                    if old < bucket_floor:
                        del self._mac_seconds[event.src_mac][old]

            rates = list(self._ip_seconds[event.src_ip].values())
            if rates:
                stats.peak_pps = max(stats.peak_pps, float(max(rates)))
                positives = [v for v in rates if v > 0]
                stats.low_pps = float(min(positives)) if positives else 0.0

    @staticmethod
    def _size_bucket(size: int) -> str:
        if size < 128:
            return "<128B"
        if size < 512:
            return "128-511B"
        if size < 1500:
            return "512-1499B"
        return ">=1500B"

    def mark_filtered(self) -> None:
        with self._lock:
            self.filtered_packets += 1

    def reset(self) -> None:
        with self._lock:
            self.__init__(self.max_events, self.rate_window)

    def snapshot(self) -> dict:
        now_ns = time.time_ns()
        now_sec = now_ns // 1_000_000_000
        with self._lock:
            elapsed = max((now_ns - self.started_ns) / 1_000_000_000, 0.001)
            ip_rows = []
            for ip, stats in self.ip_stats.items():
                seconds = self._ip_seconds.get(ip, {})
                pps_1s = float(seconds.get(now_sec, seconds.get(now_sec - 1, 0)))
                pps_10s = sum(v for s, v in seconds.items() if s >= now_sec - 9) / 10.0
                pps_60s = sum(seconds.values()) / max(min(self.rate_window, max(1, int(elapsed))), 1)
                row = asdict(stats)
                row.update({"pps": pps_1s, "pps_10s": pps_10s, "pps_60s": pps_60s})
                ip_rows.append(row)

            mac_rows = []
            for mac, count in self.mac_counts.items():
                seconds = self._mac_seconds.get(mac, {})
                mac_rows.append(
                    {
                        "mac": mac,
                        "packets": count,
                        "pps": float(seconds.get(now_sec, seconds.get(now_sec - 1, 0))),
                        "pps_60s": sum(seconds.values()) / max(min(self.rate_window, max(1, int(elapsed))), 1),
                    }
                )

            return {
                "started_ns": self.started_ns,
                "now_ns": now_ns,
                "elapsed": elapsed,
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "avg_pps": self.total_packets / elapsed,
                "avg_bps": self.total_bytes / elapsed,
                "current_pps": float(self._total_seconds.get(now_sec, self._total_seconds.get(now_sec - 1, 0))),
                "unique_ips": len(self.ip_stats),
                "filtered_packets": self.filtered_packets,
                "ips": sorted(ip_rows, key=lambda r: r["packets"], reverse=True),
                "macs": sorted(mac_rows, key=lambda r: r["packets"], reverse=True),
                "protocols": dict(self.proto_counts),
                "dst_ports": dict(self.dst_port_counts),
                "src_ports": dict(self.src_port_counts),
                "dst_ips": dict(self.dst_ip_counts),
                "tcp_flags": dict(self.tcp_flags),
                "packet_sizes": dict(self.packet_sizes),
                "last_events": [asdict(e) for e in list(self.events)[-50:]],
            }

    def iter_events_json(self) -> Iterable[str]:
        with self._lock:
            events = list(self.events)
        for event in events:
            yield json.dumps(asdict(event), separators=(",", ":"))

