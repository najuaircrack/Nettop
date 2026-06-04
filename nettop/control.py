from __future__ import annotations

import json
import os
import socket
import threading
from pathlib import Path
from typing import Callable

from .config import FilterConfig
from .utils import parse_ports


class RuntimeState:
    def __init__(self, filter_config: FilterConfig, top: int):
        self._lock = threading.Lock()
        self.filter = filter_config
        self.top = top
        self.paused = False
        self.message = ""

    def get_filter(self) -> FilterConfig:
        with self._lock:
            return FilterConfig(
                dst=self.filter.dst,
                ports=set(self.filter.ports),
                iface=self.filter.iface,
                src=self.filter.src,
                protocols=set(self.filter.protocols),
            )

    def update_filter(self, **kwargs) -> dict:
        with self._lock:
            if "dst" in kwargs and kwargs["dst"] is not None:
                self.filter.dst = kwargs["dst"]
            if "src" in kwargs and kwargs["src"] is not None:
                self.filter.src = kwargs["src"]
            if "port" in kwargs and kwargs["port"] is not None:
                self.filter.ports = parse_ports(kwargs["port"])
            if "ports" in kwargs and kwargs["ports"] is not None:
                self.filter.ports = set(int(p) for p in kwargs["ports"])
            if "iface" in kwargs and kwargs["iface"] is not None:
                self.filter.iface = kwargs["iface"]
            if "proto" in kwargs and kwargs["proto"] is not None:
                self.filter.protocols = {p.strip().upper() for p in kwargs["proto"].split(",") if p.strip()}
            self.message = "filter updated"
            return self.filter.to_dict()

    def set_top(self, top: int) -> int:
        with self._lock:
            self.top = max(1, min(500, int(top)))
            return self.top

    def set_paused(self, paused: bool) -> None:
        with self._lock:
            self.paused = paused
            self.message = "paused" if paused else "running"

    def status(self) -> dict:
        with self._lock:
            return {
                "filter": self.filter.to_dict(),
                "top": self.top,
                "paused": self.paused,
                "message": self.message,
            }


class ControlServer:
    def __init__(
        self,
        socket_path: str,
        runtime: RuntimeState,
        snapshot_fn: Callable[[], dict],
        reset_fn: Callable[[], None],
        stop_event: threading.Event,
    ):
        self.socket_path = socket_path
        self.runtime = runtime
        self.snapshot_fn = snapshot_fn
        self.reset_fn = reset_fn
        self.stop_event = stop_event
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        if _is_tcp_address(self.socket_path) or not hasattr(socket, "AF_UNIX"):
            self._serve_tcp()
            return
        path = Path(self.socket_path)
        if path.exists():
            try:
                path.unlink()
            except OSError:
                return
        path.parent.mkdir(parents=True, exist_ok=True)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            server.listen(8)
            server.settimeout(1.0)
            while not self.stop_event.is_set():
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with conn:
                    conn.settimeout(2.0)
                    data = b""
                    while True:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                        if b"\n" in chunk:
                            break
                    response = self.handle(data.decode("utf-8", errors="replace").strip())
                    conn.sendall((json.dumps(response, indent=2) + "\n").encode("utf-8"))
        try:
            path.unlink()
        except OSError:
            pass

    def _serve_tcp(self) -> None:
        host, port = _parse_tcp_address(self.socket_path)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((host, port))
            server.listen(8)
            server.settimeout(1.0)
            while not self.stop_event.is_set():
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with conn:
                    conn.settimeout(2.0)
                    data = b""
                    while True:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                        if b"\n" in chunk:
                            break
                    response = self.handle(data.decode("utf-8", errors="replace").strip())
                    conn.sendall((json.dumps(response, indent=2) + "\n").encode("utf-8"))

    def handle(self, raw: str) -> dict:
        try:
            request = json.loads(raw or "{}")
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": f"invalid JSON: {exc}"}
        cmd = request.get("cmd", "status")
        try:
            if cmd == "status":
                return {"ok": True, "runtime": self.runtime.status(), "snapshot": self.snapshot_fn()}
            if cmd == "set":
                return {"ok": True, "filter": self.runtime.update_filter(**request)}
            if cmd == "top":
                return {"ok": True, "top": self.runtime.set_top(int(request.get("top", 20)))}
            if cmd == "pause":
                self.runtime.set_paused(True)
                return {"ok": True, "paused": True}
            if cmd == "resume":
                self.runtime.set_paused(False)
                return {"ok": True, "paused": False}
            if cmd == "reset":
                self.reset_fn()
                return {"ok": True, "reset": True}
            if cmd == "snapshot":
                return {"ok": True, "snapshot": self.snapshot_fn()}
            if cmd == "stop":
                self.stop_event.set()
                return {"ok": True, "stopping": True}
            return {"ok": False, "error": f"unknown command: {cmd}"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


def send_control(socket_path: str, payload: dict) -> dict:
    if _is_tcp_address(socket_path) or not hasattr(socket, "AF_UNIX"):
        host, port = _parse_tcp_address(socket_path)
        family = socket.AF_INET
        address = (host, port)
    else:
        family = socket.AF_UNIX
        address = socket_path
    with socket.socket(family, socket.SOCK_STREAM) as client:
        client.settimeout(3.0)
        client.connect(address)
        client.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        data = b""
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            data += chunk
    return json.loads(data.decode("utf-8"))


def _is_tcp_address(value: str) -> bool:
    return value.startswith("tcp://") or (":" in value and not value.startswith("/") and "\\" not in value)


def _parse_tcp_address(value: str) -> tuple[str, int]:
    raw = value.removeprefix("tcp://")
    if ":" not in raw:
        return "127.0.0.1", int(raw)
    host, port = raw.rsplit(":", 1)
    return host or "127.0.0.1", int(port)
