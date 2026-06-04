from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .app import run_monitor
from .config import config_from_args
from .control import send_control
from .features import feature_text
from .utils import default_control_socket


def add_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dst", default="0.0.0.0", help="Destination IP to monitor, default any")
    parser.add_argument("--src", default="", help="Source IP to monitor")
    parser.add_argument("--port", default="0", help="Destination port list/range, example 80,443,8000-8100")
    parser.add_argument("--proto", default="", help="Protocol list, example tcp,udp,icmp")
    parser.add_argument("--iface", default=None, help="Network interface")
    parser.add_argument("--top", type=int, default=20, help="Rows in top-IP table")
    parser.add_argument("--interval", type=float, default=1.0, help="Dashboard refresh interval")
    parser.add_argument("--no-geo", action="store_true", help="Disable offline geo lookup")
    parser.add_argument("--location-db", default=None, help="Path to Nettop location.csv IP range database")
    parser.add_argument("--control-socket", default=default_control_socket(), help="Unix socket path for nettopctl")
    parser.add_argument("--jsonl", default=None, help="Append accepted packet events to JSONL")
    parser.add_argument("--pcap", default=None, help="Replay a PCAP file instead of live capture")
    parser.add_argument("--max-events", type=int, default=5000, help="Recent event ring size")
    parser.add_argument("--high-pps", type=float, default=1000.0, help="High PPS alert threshold")
    parser.add_argument("--quiet", action="store_true", help="Run without live TUI")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nettop", description="Offline-first network monitoring TUI and CLI controller")
    parser.add_argument("--version", action="version", version=f"nettop {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    run = sub.add_parser("run", help="Start live monitor")
    add_run_args(run)

    demo = sub.add_parser("demo", help="Start rootless demo monitor")
    add_run_args(demo)
    demo.set_defaults(demo=True)

    ctl = sub.add_parser("ctl", help="Send a command to a running monitor")
    ctl.add_argument("--control-socket", default=default_control_socket())
    ctl_sub = ctl.add_subparsers(dest="ctl_cmd")
    ctl_sub.add_parser("status")
    setp = ctl_sub.add_parser("set")
    setp.add_argument("--dst")
    setp.add_argument("--src")
    setp.add_argument("--port")
    setp.add_argument("--iface")
    setp.add_argument("--proto")
    top = ctl_sub.add_parser("top")
    top.add_argument("top", type=int)
    ctl_sub.add_parser("pause")
    ctl_sub.add_parser("resume")
    ctl_sub.add_parser("reset")
    ctl_sub.add_parser("snapshot")
    ctl_sub.add_parser("stop")

    sub.add_parser("features", help="Print the feature catalog")
    sub.add_parser("doctor", help="Check optional dependencies and runtime hints")
    upd = sub.add_parser("update-db", help="Download DB-IP Lite and rebuild location.csv")
    upd.add_argument("--output", default=None, help="Output location.csv path")
    upd.add_argument("--kind", default="city", choices=["city", "country"], help="DB-IP Lite source")
    upd.add_argument("--workdir", default=None, help="Temporary download directory")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd is None:
        args = parser.parse_args(["run", *(argv or [])])

    if args.cmd in {"run", "demo"}:
        config = config_from_args(args)
        config.demo = args.cmd == "demo" or getattr(args, "demo", False)
        return run_monitor(config)
    if args.cmd == "ctl":
        return run_ctl(args)
    if args.cmd == "features":
        print(feature_text())
        return 0
    if args.cmd == "doctor":
        return doctor()
    if args.cmd == "update-db":
        from .dbip_update import update_location

        update_location(args.output, args.kind, args.workdir)
        return 0
    parser.print_help()
    return 2


def run_ctl(args) -> int:
    cmd = args.ctl_cmd or "status"
    payload: dict = {"cmd": cmd}
    if cmd == "set":
        for key in ("dst", "src", "port", "iface", "proto"):
            value = getattr(args, key, None)
            if value is not None:
                payload[key] = value
    elif cmd == "top":
        payload["top"] = args.top
    try:
        response = send_control(args.control_socket, payload)
    except FileNotFoundError:
        print(f"No running nettop controller at {args.control_socket}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Controller error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(response, indent=2, sort_keys=True))
    return 0 if response.get("ok") else 1


def doctor() -> int:
    checks = []
    try:
        import rich  # noqa: F401

        checks.append(("rich", True, "dashboard available"))
    except Exception:
        checks.append(("rich", False, "install python3-rich or pip install rich"))
    try:
        import scapy  # noqa: F401

        checks.append(("scapy", True, "full packet capture available"))
    except Exception:
        checks.append(("scapy", False, "install python3-scapy for best capture"))
    location_paths = [
        "/var/lib/nettop/location.csv",
        os.path.join(os.path.dirname(__file__), "location.csv"),
        "/usr/share/nettop/nettop-geo.csv",
        "/usr/share/nettop/location.csv",
        "/usr/local/share/nettop/nettop-geo.csv",
        "/usr/local/share/nettop/location.csv",
        "/etc/nettop/nettop-geo.csv",
        "/etc/nettop/location.csv",
        "nettop/location.csv",
        "location.csv",
    ]
    location_found = [p for p in location_paths if os.path.exists(p)]
    checks.append(("location", bool(location_found), ", ".join(location_found) if location_found else "embedded fallback active"))
    for name, ok, note in checks:
        marker = "OK" if ok else "--"
        print(f"{marker:>2} {name:<8} {note}")
    return 0


def nettopctl() -> int:
    return main(["ctl", *sys.argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
