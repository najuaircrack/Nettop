from __future__ import annotations

import ipaddress
import os
import socket
from pathlib import Path


def fmt_bytes(value: float) -> str:
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    n = float(value)
    for unit in units:
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}EB"


def fmt_rate(value: float) -> str:
    return f"{fmt_bytes(value)}/s"


def service_name(port: int) -> str:
    known = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        161: "SNMP",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        514: "SYSLOG",
        587: "SMTP-SUB",
        636: "LDAPS",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "ORACLE",
        2049: "NFS",
        3306: "MYSQL",
        3389: "RDP",
        5432: "POSTGRES",
        5900: "VNC",
        6379: "REDIS",
        8080: "HTTP-ALT",
        8443: "HTTPS-ALT",
        27017: "MONGO",
    }
    if port in known:
        return known[port]
    try:
        return socket.getservbyport(port).upper()
    except OSError:
        return ""


def parse_ports(value: str | int | None) -> set[int]:
    if value in (None, "", 0, "0", "any", "ANY"):
        return set()
    if isinstance(value, int):
        return {value}
    ports: set[int] = set()
    for part in str(value).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = [int(x) for x in part.split("-", 1)]
            if start > end:
                start, end = end, start
            ports.update(range(max(0, start), min(65535, end) + 1))
        else:
            ports.add(int(part))
    return {p for p in ports if 0 <= p <= 65535}


def normalize_mac(value: str | None) -> str:
    if not value:
        return ""
    cleaned = value.replace("-", ":").lower()
    parts = cleaned.split(":")
    if len(parts) == 6:
        return ":".join(p.zfill(2)[-2:] for p in parts)
    return cleaned


def is_special_ip(ip: str) -> tuple[bool, str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True, "Invalid"
    if addr.is_private:
        return True, "Private"
    if addr.is_loopback:
        return True, "Loopback"
    if addr.is_link_local:
        return True, "Link-local"
    if addr.is_multicast:
        return True, "Multicast"
    if addr.is_reserved:
        return True, "Reserved"
    if addr.is_unspecified:
        return True, "Unspecified"
    return False, ""


def default_control_socket() -> str:
    if not hasattr(socket, "AF_UNIX"):
        return "127.0.0.1:8765"
    run_dir = os.environ.get("XDG_RUNTIME_DIR")
    if run_dir:
        return str(Path(run_dir) / "nettop.sock")
    return "/tmp/nettop.sock"


def country_flag(code: str) -> str:
    cc = (code or "").upper()
    if len(cc) != 2 or not cc.isalpha():
        return "--"
    base = 0x1F1E6
    return chr(base + ord(cc[0]) - 65) + chr(base + ord(cc[1]) - 65)


def now_ns() -> int:
    import time

    return time.time_ns()
