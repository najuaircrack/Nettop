from __future__ import annotations

import os
import signal
import sys
import threading
import time

from .alerts import AlertEngine
from .capture import CaptureEngine, SCAPY_OK
from .config import AppConfig
from .control import ControlServer, RuntimeState
from .exporters import write_snapshot_json, write_top_csv
from .geo import OfflineGeoResolver, geo_status
from .store import TrafficStore
from .tui import Dashboard


def run_monitor(config: AppConfig) -> int:
    stop_event = threading.Event()
    store = TrafficStore(max_events=config.max_events)
    runtime = RuntimeState(config.filter, config.top)
    resolver = OfflineGeoResolver(config.location_db, disabled=config.no_geo)
    alerts = AlertEngine(config.high_pps)

    def get_filter():
        if runtime.status()["paused"]:
            paused = runtime.get_filter()
            paused.dst = "__paused__"
            return paused
        return runtime.get_filter()

    capture = CaptureEngine(store, get_filter, stop_event, config.export_jsonl)
    controller = ControlServer(config.control_socket, runtime, store.snapshot, store.reset, stop_event)
    controller.start()

    def handle_signal(_sig, _frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    if config.demo:
        capture.start_demo()
    elif config.pcap_file:
        capture.replay_pcap(config.pcap_file)
    else:
        if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
            print("Root privileges are required for live capture. Try: sudo nettop run ... or nettop demo", file=sys.stderr)
            return 1
        capture.start_live()

    try:
        if config.quiet:
            while not stop_event.is_set():
                time.sleep(config.interval)
        else:
            Dashboard(resolver, alerts).run(store.snapshot, runtime, stop_event, config.interval, store.reset)
    finally:
        stop_event.set()
        capture.close()
        snapshot = store.snapshot()
        if config.export_jsonl:
            base = config.export_jsonl.rsplit(".", 1)[0]
            write_snapshot_json(f"{base}.snapshot.json", snapshot)
            write_top_csv(f"{base}.top.csv", snapshot)
        print_summary(snapshot, resolver)
    return 0


def print_summary(snapshot: dict, resolver: OfflineGeoResolver) -> None:
    print("\nNettop session summary")
    print(f"  packets:     {snapshot['total_packets']:,}")
    print(f"  bytes:       {snapshot['total_bytes']:,}")
    print(f"  unique IPs:  {snapshot['unique_ips']:,}")
    print(f"  avg pps:     {snapshot['avg_pps']:.2f}")
    print(f"  geo:         {geo_status(resolver)}")
    if snapshot["ips"]:
        print("  top IPs:")
        for row in snapshot["ips"][:10]:
            geo = resolver.lookup(row["ip"])
            where = geo.country if geo.country != "Unknown" else geo.source
            print(f"    {row['ip']:<16} {row['packets']:>8,} pkts {row['pps']:>6.0f} pps {where}")
