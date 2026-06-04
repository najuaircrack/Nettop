from __future__ import annotations

import os
import random
import socket
import struct
import threading
import time
from typing import Callable

from .config import FilterConfig
from .exporters import JsonlEventWriter
from .models import PacketEvent
from .store import TrafficStore
from .utils import normalize_mac, now_ns

try:
    from scapy.all import Ether, ICMP, IP, TCP, UDP, conf, rdpcap, sniff  # type: ignore

    conf.verb = 0
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False


def build_bpf(filter_config: FilterConfig) -> str:
    parts: list[str] = []
    if filter_config.dst not in ("", "0.0.0.0", "::", "any", "ANY"):
        parts.append(f"dst host {filter_config.dst}")
    if filter_config.src:
        parts.append(f"src host {filter_config.src}")
    if filter_config.ports:
        ports = sorted(filter_config.ports)
        if len(ports) == 1:
            parts.append(f"dst port {ports[0]}")
        else:
            parts.append("(" + " or ".join(f"dst port {p}" for p in ports) + ")")
    if filter_config.protocols:
        proto_parts = [p.lower() for p in filter_config.protocols if p.lower() in {"tcp", "udp", "icmp"}]
        if proto_parts:
            parts.append("(" + " or ".join(proto_parts) + ")")
    return " and ".join(parts)


class CaptureEngine:
    def __init__(
        self,
        store: TrafficStore,
        get_filter: Callable[[], FilterConfig],
        stop_event: threading.Event,
        export_jsonl: str | None = None,
    ):
        self.store = store
        self.get_filter = get_filter
        self.stop_event = stop_event
        self.writer = JsonlEventWriter(export_jsonl)
        self.thread: threading.Thread | None = None

    def start_live(self) -> None:
        if SCAPY_OK:
            self.thread = threading.Thread(target=self._run_scapy, daemon=True)
        else:
            self.thread = threading.Thread(target=self._run_raw_socket, daemon=True)
        self.thread.start()

    def replay_pcap(self, path: str, speed: float = 0.0) -> None:
        if not SCAPY_OK:
            raise RuntimeError("pcap replay requires scapy")
        self.thread = threading.Thread(target=self._run_pcap, args=(path, speed), daemon=True)
        self.thread.start()

    def start_demo(self) -> None:
        self.thread = threading.Thread(target=self._run_demo, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.writer.close()

    def _accept_event(self, event: PacketEvent) -> None:
        if self.get_filter().matches(event.src_ip, event.dst_ip, event.proto, event.dst_port):
            self.store.record(event)
            self.writer.write(event)
        else:
            self.store.mark_filtered()

    def _run_scapy(self) -> None:
        current_bpf = None
        while not self.stop_event.is_set():
            fc = self.get_filter()
            bpf = build_bpf(fc) or None
            current_bpf = bpf
            try:
                sniff(
                    filter=bpf,
                    iface=fc.iface,
                    prn=self._handle_scapy_packet,
                    store=False,
                    timeout=1,
                    stop_filter=lambda _: self.stop_event.is_set() or build_bpf(self.get_filter()) != (current_bpf or ""),
                )
            except Exception:
                time.sleep(1.0)

    def _handle_scapy_packet(self, packet) -> None:
        event = self._packet_from_scapy(packet)
        if event:
            self._accept_event(event)

    def _packet_from_scapy(self, packet) -> PacketEvent | None:
        if not SCAPY_OK or IP not in packet:
            return None
        proto = "OTHER"
        sport = 0
        dport = 0
        flags = ""
        if TCP in packet:
            proto = "TCP"
            sport = int(packet[TCP].sport)
            dport = int(packet[TCP].dport)
            flags = str(packet[TCP].flags)
        elif UDP in packet:
            proto = "UDP"
            sport = int(packet[UDP].sport)
            dport = int(packet[UDP].dport)
        elif ICMP in packet:
            proto = "ICMP"
        src_mac = dst_mac = ""
        if Ether in packet:
            src_mac = normalize_mac(packet[Ether].src)
            dst_mac = normalize_mac(packet[Ether].dst)
        return PacketEvent(
            ts_ns=now_ns(),
            src_ip=packet[IP].src,
            dst_ip=packet[IP].dst,
            proto=proto,
            size=len(packet),
            src_port=sport,
            dst_port=dport,
            src_mac=src_mac,
            dst_mac=dst_mac,
            tcp_flags=flags,
        )

    def _run_pcap(self, path: str, speed: float) -> None:
        packets = rdpcap(path)
        for packet in packets:
            if self.stop_event.is_set():
                break
            event = self._packet_from_scapy(packet)
            if event:
                self._accept_event(event)
            if speed > 0:
                time.sleep(speed)

    def _run_raw_socket(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        except PermissionError:
            return
        except OSError:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            except OSError:
                return
        sock.settimeout(1.0)
        while not self.stop_event.is_set():
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            event = self._packet_from_raw(data)
            if event:
                self._accept_event(event)

    @staticmethod
    def _packet_from_raw(data: bytes) -> PacketEvent | None:
        if len(data) < 20:
            return None
        first = data[0]
        version = first >> 4
        ihl = (first & 0x0F) * 4
        if version != 4 or len(data) < ihl:
            return None
        proto_num = data[9]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])
        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, "OTHER")
        sport = dport = 0
        flags = ""
        if proto in {"TCP", "UDP"} and len(data) >= ihl + 4:
            sport, dport = struct.unpack("!HH", data[ihl : ihl + 4])
        if proto == "TCP" and len(data) >= ihl + 14:
            flag_byte = data[ihl + 13]
            flags = "".join(name for bit, name in [(1, "F"), (2, "S"), (4, "R"), (8, "P"), (16, "A"), (32, "U")] if flag_byte & bit)
        return PacketEvent(
            ts_ns=now_ns(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto=proto,
            size=len(data),
            src_port=sport,
            dst_port=dport,
            tcp_flags=flags,
        )

    def _run_demo(self) -> None:
        demo_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "9.9.9.9",
            "13.107.42.14",
            "34.117.59.81",
            "45.33.32.156",
            "91.108.56.0",
            "104.21.1.1",
            "151.101.1.57",
            "185.199.108.133",
            "192.168.1.10",
            "10.0.0.15",
        ]
        macs = ["00:16:3e:01:02:03", "52:54:00:12:34:56", "ac:de:48:00:11:22", "f0:18:98:aa:bb:cc"]
        ports = [22, 53, 80, 123, 443, 3389, 5432, 6379, 8080]
        while not self.stop_event.is_set():
            proto = random.choices(["TCP", "UDP", "ICMP"], weights=[70, 25, 5], k=1)[0]
            dport = random.choice(ports) if proto != "ICMP" else 0
            event = PacketEvent(
                ts_ns=now_ns(),
                src_ip=random.choice(demo_ips),
                dst_ip="192.168.1.5",
                proto=proto,
                size=random.randint(60, 1514),
                src_port=random.randint(1024, 65535) if dport else 0,
                dst_port=dport,
                src_mac=random.choice(macs),
                dst_mac="ff:ff:ff:ff:ff:ff",
                tcp_flags=random.choice(["S", "A", "PA", "FA", ""]) if proto == "TCP" else "",
            )
            self._accept_event(event)
            time.sleep(random.uniform(0.005, 0.08))
