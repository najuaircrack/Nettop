from __future__ import annotations

import os
import select
import sys
import threading
from collections import Counter, defaultdict
from datetime import datetime

from .alerts import AlertEngine
from .geo import OfflineGeoResolver, geo_status
from .utils import parse_ports
from .utils import country_flag, fmt_bytes, fmt_rate, service_name

try:
    from rich import box
    from rich.align import Align
    from rich.columns import Columns
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except Exception:  # pragma: no cover
    Console = None


def bar(value: float, maximum: float, width: int = 12) -> str:
    if maximum <= 0:
        return "." * width
    filled = int(min(width, max(0, round(width * value / maximum))))
    return "#" * filled + "." * (width - filled)


class Dashboard:
    def __init__(self, resolver: OfflineGeoResolver, alert_engine: AlertEngine):
        if Console is None:
            raise RuntimeError("rich is required for the live dashboard")
        self.console = Console()
        self.resolver = resolver
        self.alert_engine = alert_engine
        self._input_lock = threading.Lock()
        self._mode: str | None = None
        self._buffer = ""
        self._hint = "d dst | p ports | s src | y proto | t top | space pause | r reset | q quit"

    def run(self, snapshot_fn, runtime, stop_event, interval: float, reset_fn=None) -> None:
        threading.Thread(target=self._keyboard_loop, args=(runtime, stop_event, reset_fn), daemon=True).start()
        with Live(console=self.console, screen=True, refresh_per_second=max(1, 1 / max(interval, 0.1))) as live:
            while not stop_event.is_set():
                snapshot = snapshot_fn()
                live.update(self.render(snapshot, runtime.status()))
                stop_event.wait(interval)

    def render(self, snapshot: dict, runtime_status: dict):
        width = self.console.size.width
        if snapshot["total_packets"] == 0:
            return self._waiting(runtime_status)
        header = self._header(snapshot, runtime_status)
        ips = self._ip_table(snapshot, runtime_status, compact=width < 110)
        stats = self._stats(snapshot)
        macs = self._mac_table(snapshot)
        countries = self._countries(snapshot)
        alerts = self._alerts(snapshot)
        footer = self._footer(snapshot)
        command = self._command_panel(runtime_status)
        if width < 95:
            return Group(header, ips, stats, macs, alerts, command, footer)
        return Group(header, ips, Columns([countries, stats, macs], expand=True), alerts, command, footer)

    def _waiting(self, runtime_status: dict) -> Panel:
        f = runtime_status["filter"]
        text = Text(justify="center")
        text.append("Nettop is listening\n\n", style="bold bright_cyan")
        text.append(f"dst={f['dst']} ports={f['ports'] or 'ANY'} iface={f['iface'] or 'auto'}\n", style="white")
        text.append(f"geo={geo_status(self.resolver)}  controller=ready\n", style="dim")
        text.append("Use nettopctl set --dst IP --port 443 to retarget while running.", style="dim")
        return Panel(Align.center(text, vertical="middle"), title="NETTOP", border_style="cyan", height=16)

    def _header(self, snapshot: dict, runtime_status: dict) -> Panel:
        f = runtime_status["filter"]
        elapsed = int(snapshot["elapsed"])
        uptime = f"{elapsed // 3600:02d}:{(elapsed % 3600) // 60:02d}:{elapsed % 60:02d}"
        paused = " PAUSED " if runtime_status.get("paused") else " LIVE "
        text = Text()
        text.append(paused, style="black on yellow" if runtime_status.get("paused") else "black on green")
        text.append("  dst ", style="dim")
        text.append(f"{f['dst']}:{','.join(map(str, f['ports'])) if f['ports'] else 'ANY'}", style="bold cyan")
        text.append("  iface ", style="dim")
        text.append(f"{f['iface'] or 'auto'}", style="white")
        text.append("  uptime ", style="dim")
        text.append(uptime, style="green")
        text.append("  packets ", style="dim")
        text.append(f"{snapshot['total_packets']:,}", style="yellow")
        text.append("  unique ", style="dim")
        text.append(f"{snapshot['unique_ips']:,}", style="cyan")
        text.append("  pps ", style="dim")
        text.append(f"{snapshot['current_pps']:.0f}", style="magenta")
        text.append("  avg ", style="dim")
        text.append(f"{snapshot['avg_pps']:.1f}pps {fmt_rate(snapshot['avg_bps'])}", style="white")
        text.append("  geo ", style="dim")
        text.append(geo_status(self.resolver), style="green")
        return Panel(text, title="NETTOP NETWORK MONITOR", border_style="bright_blue")

    def _ip_table(self, snapshot: dict, runtime_status: dict, compact: bool) -> Panel:
        top = runtime_status.get("top", 20)
        rows = snapshot["ips"][:top]
        max_packets = rows[0]["packets"] if rows else 1
        table = Table(box=box.SIMPLE_HEAVY, expand=True, show_edge=False, padding=(0, 1))
        table.add_column("#", width=3, justify="right", style="dim")
        table.add_column("IP", min_width=14, style="cyan")
        if not compact:
            table.add_column("Geo", min_width=16)
        table.add_column("Pkts", justify="right", style="yellow")
        table.add_column("PPS", justify="right", style="magenta")
        table.add_column("Low/Peak", justify="right", style="green")
        table.add_column("Bytes", justify="right", style="bright_magenta")
        table.add_column("Last ns", justify="right", style="dim")
        table.add_column("Share", min_width=14)
        for idx, row in enumerate(rows, 1):
            geo = self.resolver.lookup(row["ip"])
            geo_label = f"{country_flag(geo.country_code)} {geo.country}"[:22]
            values = [
                str(idx),
                row["ip"],
            ]
            if not compact:
                values.append(geo_label)
            values.extend(
                [
                    f"{row['packets']:,}",
                    f"{row['pps']:.0f}",
                    f"{row['low_pps']:.0f}/{row['peak_pps']:.0f}",
                    fmt_bytes(row["bytes"]),
                    str(row["last_ns"]),
                    bar(row["packets"], max_packets, 12),
                ]
            )
            table.add_row(*values, style="on grey7" if idx % 2 == 0 else "")
        return Panel(table, title=f"Top Source IPs ({top})", border_style="cyan")

    def _countries(self, snapshot: dict) -> Panel:
        packets: Counter[str] = Counter()
        unique: dict[str, set[str]] = defaultdict(set)
        for row in snapshot["ips"]:
            geo = self.resolver.lookup(row["ip"])
            label = f"{country_flag(geo.country_code)} {geo.country}"
            packets[label] += row["packets"]
            unique[label].add(row["ip"])
        table = Table(box=box.SIMPLE, expand=True, show_edge=False)
        table.add_column("Country")
        table.add_column("IPs", justify="right", style="cyan")
        table.add_column("Pkts", justify="right", style="yellow")
        for country, count in packets.most_common(8):
            table.add_row(country[:24], str(len(unique[country])), f"{count:,}")
        return Panel(table, title="Countries", border_style="yellow")

    def _stats(self, snapshot: dict) -> Panel:
        table = Table(box=box.SIMPLE, expand=True, show_edge=False)
        table.add_column("Metric")
        table.add_column("Value", justify="right")
        proto = ", ".join(f"{k}:{v:,}" for k, v in sorted(snapshot["protocols"].items()))
        top_ports = []
        for raw_port, count in Counter(snapshot["dst_ports"]).most_common(8):
            port = int(raw_port)
            if port == 0:
                label = "none"
            else:
                svc = service_name(port)
                label = f"{port}/{svc}" if svc else str(port)
            top_ports.append(f"{label}:{count:,}")
        table.add_row("Protocols", proto or "-")
        table.add_row("Top dst ports", ", ".join(top_ports) or "-")
        table.add_row("TCP flags", ", ".join(f"{k}:{v:,}" for k, v in snapshot["tcp_flags"].items()) or "-")
        table.add_row("Packet sizes", ", ".join(f"{k}:{v:,}" for k, v in snapshot["packet_sizes"].items()) or "-")
        table.add_row("Filtered", f"{snapshot['filtered_packets']:,}")
        return Panel(table, title="Traffic Stats", border_style="magenta")

    def _mac_table(self, snapshot: dict) -> Panel:
        table = Table(box=box.SIMPLE, expand=True, show_edge=False)
        table.add_column("MAC")
        table.add_column("Pkts", justify="right", style="yellow")
        table.add_column("PPS", justify="right", style="magenta")
        for row in snapshot["macs"][:8]:
            table.add_row(row["mac"] or "-", f"{row['packets']:,}", f"{row['pps']:.0f}")
        return Panel(table, title="MACs", border_style="green")

    def _alerts(self, snapshot: dict) -> Panel:
        alerts = self.alert_engine.evaluate(snapshot)
        if not alerts:
            body = Text("No alerts", style="dim")
        else:
            body = Text()
            for alert in alerts[-8:]:
                style = "yellow" if alert["level"] == "warn" else "cyan"
                body.append(f"{alert['kind']}: {alert['message']}\n", style=style)
        return Panel(body, title="Alerts", border_style="red" if alerts else "grey50")

    def _command_panel(self, runtime_status: dict) -> Panel:
        with self._input_lock:
            mode = self._mode
            buffer = self._buffer
            hint = self._hint
        f = runtime_status["filter"]
        if mode:
            body = Text()
            body.append(f"{mode}> ", style="bold yellow")
            body.append(buffer or " ", style="white")
            body.append("  Enter apply | Esc cancel | Backspace edit", style="dim")
            return Panel(body, title="Live Control", border_style="yellow")
        body = Text()
        body.append(hint, style="dim")
        body.append("\ncurrent ", style="dim")
        body.append(f"dst={f['dst']} ports={f['ports'] or 'ANY'} src={f['src'] or 'ANY'} proto={f['protocols'] or 'ANY'}", style="cyan")
        return Panel(body, title="Live Control", border_style="blue")

    @staticmethod
    def _footer(snapshot: dict) -> Text:
        text = Text()
        text.append(" nettopctl: status | set --dst IP --port 443 | top 50 | pause | resume | snapshot | reset | stop", style="dim")
        text.append(f"   {datetime.now().strftime('%H:%M:%S')}", style="dim")
        return text

    def _keyboard_loop(self, runtime, stop_event, reset_fn) -> None:
        if os.name == "nt":
            self._keyboard_loop_windows(runtime, stop_event, reset_fn)
        else:
            self._keyboard_loop_posix(runtime, stop_event, reset_fn)

    def _keyboard_loop_windows(self, runtime, stop_event, reset_fn) -> None:
        try:
            import msvcrt
        except Exception:
            return
        while not stop_event.is_set():
            if not msvcrt.kbhit():
                stop_event.wait(0.05)
                continue
            key = msvcrt.getwch()
            self._handle_key(key, runtime, stop_event, reset_fn)

    def _keyboard_loop_posix(self, runtime, stop_event, reset_fn) -> None:
        if not sys.stdin.isatty():
            return
        try:
            import termios
            import tty

            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            tty.setcbreak(fd)
            try:
                while not stop_event.is_set():
                    readable, _, _ = select.select([sys.stdin], [], [], 0.05)
                    if readable:
                        self._handle_key(sys.stdin.read(1), runtime, stop_event, reset_fn)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except Exception:
            return

    def _handle_key(self, key: str, runtime, stop_event, reset_fn) -> None:
        if key in ("\x00", "\xe0"):
            return
        with self._input_lock:
            mode = self._mode
        if mode:
            self._handle_edit_key(key, runtime)
            return
        lowered = key.lower()
        if lowered == "q":
            stop_event.set()
        elif key == " ":
            runtime.set_paused(not runtime.status()["paused"])
        elif lowered == "r" and reset_fn:
            reset_fn()
            with self._input_lock:
                self._hint = "session counters reset"
        elif lowered in {"d", "p", "s", "y", "t"}:
            labels = {"d": "dst", "p": "ports", "s": "src", "y": "proto", "t": "top"}
            with self._input_lock:
                self._mode = labels[lowered]
                self._buffer = ""

    def _handle_edit_key(self, key: str, runtime) -> None:
        if key in ("\x1b", "\x03"):
            with self._input_lock:
                self._mode = None
                self._buffer = ""
                self._hint = "edit cancelled"
            return
        if key in ("\b", "\x7f"):
            with self._input_lock:
                self._buffer = self._buffer[:-1]
            return
        if key in ("\r", "\n"):
            with self._input_lock:
                mode = self._mode
                value = self._buffer.strip()
                self._mode = None
                self._buffer = ""
            self._apply_command(mode, value, runtime)
            return
        if key.isprintable():
            with self._input_lock:
                self._buffer += key

    def _apply_command(self, mode: str | None, value: str, runtime) -> None:
        if not mode:
            return
        try:
            if mode == "dst":
                runtime.update_filter(dst=value or "0.0.0.0")
            elif mode == "ports":
                parse_ports(value)
                runtime.update_filter(port=value or "0")
            elif mode == "src":
                runtime.update_filter(src=value)
            elif mode == "proto":
                runtime.update_filter(proto=value)
            elif mode == "top":
                runtime.set_top(int(value))
            with self._input_lock:
                self._hint = f"{mode} updated"
        except Exception as exc:
            with self._input_lock:
                self._hint = f"{mode} error: {exc}"
