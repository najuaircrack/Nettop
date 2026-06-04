from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class PacketEvent:
    ts_ns: int
    src_ip: str
    dst_ip: str
    proto: str
    size: int
    src_port: int = 0
    dst_port: int = 0
    src_mac: str = ""
    dst_mac: str = ""
    tcp_flags: str = ""


@dataclass(slots=True)
class GeoResult:
    country: str = "Unknown"
    country_code: str = "??"
    city: str = ""
    asn: str = ""
    org: str = ""
    source: str = "none"


@dataclass(slots=True)
class IpStats:
    ip: str
    packets: int = 0
    bytes: int = 0
    first_ns: int = 0
    last_ns: int = 0
    src_ports: dict[int, int] = field(default_factory=dict)
    dst_ports: dict[int, int] = field(default_factory=dict)
    protocols: dict[str, int] = field(default_factory=dict)
    macs: dict[str, int] = field(default_factory=dict)
    tcp_flags: dict[str, int] = field(default_factory=dict)
    peak_pps: float = 0.0
    low_pps: float = 0.0

