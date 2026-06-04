from __future__ import annotations

from dataclasses import dataclass, field

from .utils import default_control_socket, parse_ports


@dataclass(slots=True)
class FilterConfig:
    dst: str = "0.0.0.0"
    ports: set[int] = field(default_factory=set)
    iface: str | None = None
    src: str = ""
    protocols: set[str] = field(default_factory=set)

    def matches(self, src_ip: str, dst_ip: str, proto: str, dport: int) -> bool:
        if self.dst not in ("", "0.0.0.0", "::", "any", "ANY") and dst_ip != self.dst:
            return False
        if self.src and src_ip != self.src:
            return False
        if self.ports and dport not in self.ports:
            return False
        if self.protocols and proto.upper() not in self.protocols:
            return False
        return True

    @property
    def port_label(self) -> str:
        if not self.ports:
            return "ANY"
        if len(self.ports) <= 5:
            return ",".join(str(p) for p in sorted(self.ports))
        return f"{len(self.ports)} ports"

    def to_dict(self) -> dict:
        return {
            "dst": self.dst,
            "ports": sorted(self.ports),
            "iface": self.iface,
            "src": self.src,
            "protocols": sorted(self.protocols),
        }


@dataclass(slots=True)
class AppConfig:
    filter: FilterConfig = field(default_factory=FilterConfig)
    interval: float = 1.0
    top: int = 20
    no_geo: bool = False
    location_db: str | None = None
    control_socket: str = field(default_factory=default_control_socket)
    export_jsonl: str | None = None
    pcap_file: str | None = None
    max_events: int = 5000
    high_pps: float = 1000.0
    quiet: bool = False
    demo: bool = False


def config_from_args(args) -> AppConfig:
    protocols = {p.strip().upper() for p in getattr(args, "proto", "").split(",") if p.strip()}
    return AppConfig(
        filter=FilterConfig(
            dst=args.dst,
            ports=parse_ports(args.port),
            iface=args.iface,
            src=getattr(args, "src", "") or "",
            protocols=protocols,
        ),
        interval=args.interval,
        top=args.top,
        no_geo=args.no_geo,
        location_db=args.location_db,
        control_socket=args.control_socket,
        export_jsonl=getattr(args, "jsonl", None),
        pcap_file=getattr(args, "pcap", None),
        max_events=args.max_events,
        high_pps=args.high_pps,
        quiet=getattr(args, "quiet", False),
        demo=getattr(args, "demo", False),
    )
