from __future__ import annotations

import csv
import ipaddress
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path

from .models import GeoResult
from .utils import is_special_ip


PURE_GEO_PATHS = (
    "/var/lib/nettop/location.csv",
    str(Path(__file__).with_name("location.csv")),
    "./nettop/location.csv",
    "./location.csv",
    "/usr/share/nettop/nettop-geo.csv",
    "/usr/share/nettop/location.csv",
    "/usr/local/share/nettop/nettop-geo.csv",
    "/usr/local/share/nettop/location.csv",
    "/etc/nettop/nettop-geo.csv",
    "/etc/nettop/location.csv",
    "~/nettop-geo.csv",
    "~/location.csv",
)


@dataclass(frozen=True, slots=True)
class GeoRange:
    start: int
    end: int
    country_code: str
    country: str
    city: str = ""
    asn: str = ""
    org: str = ""


EMBEDDED_RANGES = (
    ("1.1.1.0/24", "AU", "Australia", "", "AS13335", "Cloudflare"),
    ("8.8.8.0/24", "US", "United States", "", "AS15169", "Google"),
    ("9.9.9.0/24", "US", "United States", "", "AS19281", "Quad9"),
    ("13.64.0.0/11", "US", "United States", "", "AS8075", "Microsoft"),
    ("34.0.0.0/9", "US", "United States", "", "AS396982", "Google Cloud"),
    ("45.32.0.0/12", "US", "United States", "", "", ""),
    ("91.108.4.0/22", "NL", "Netherlands", "", "", "Telegram"),
    ("104.16.0.0/12", "US", "United States", "", "AS13335", "Cloudflare"),
    ("151.101.0.0/16", "US", "United States", "", "AS54113", "Fastly"),
    ("185.199.108.0/22", "US", "United States", "", "AS54113", "GitHub"),
)


class PureGeoResolver:
    """Dependency-free offline geo resolver.

    The resolver uses nettop/location.csv by default. The embedded table is a
    final safety fallback when the CSV is missing.
    """

    def __init__(self, db_path: str | None = None):
        self.db_path = self._find_file(db_path)
        ranges = self._load_embedded()
        if self.db_path:
            ranges.extend(self._load_csv(self.db_path))
        ranges.sort(key=lambda item: item.start)
        self._ranges = ranges
        self._starts = [item.start for item in ranges]
        self.source = f"location.csv:{self.db_path.name}" if self.db_path else "embedded-location"

    @staticmethod
    def _find_file(explicit: str | None) -> Path | None:
        paths = [explicit] if explicit else []
        paths.extend(PURE_GEO_PATHS)
        for raw in paths:
            if not raw:
                continue
            path = Path(raw).expanduser()
            if path.exists() and path.is_file():
                return path
        return None

    @staticmethod
    def _load_embedded() -> list[GeoRange]:
        rows: list[GeoRange] = []
        for cidr, code, country, city, asn, org in EMBEDDED_RANGES:
            net = ipaddress.ip_network(cidr)
            rows.append(GeoRange(int(net.network_address), int(net.broadcast_address), code, country, city, asn, org))
        return rows

    @staticmethod
    def _load_csv(path: Path) -> list[GeoRange]:
        rows: list[GeoRange] = []
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for raw in reader:
                try:
                    rows.append(_range_from_row(raw))
                except (KeyError, ValueError):
                    continue
        return rows

    def lookup(self, ip: str) -> GeoResult:
        special, label = is_special_ip(ip)
        if special:
            return GeoResult(country=label, country_code="LO", city="Local", source="ipaddress")
        try:
            value = int(ipaddress.ip_address(ip))
        except ValueError:
            return GeoResult(country="Invalid", country_code="LO", city="", source="ipaddress")
        idx = bisect_right(self._starts, value) - 1
        if idx >= 0:
            row = self._ranges[idx]
            if row.start <= value <= row.end:
                return GeoResult(
                    country=row.country,
                    country_code=row.country_code,
                    city=row.city,
                    asn=row.asn,
                    org=row.org,
                    source=self.source,
                )
        return GeoResult(source=self.source)


def _range_from_row(row: dict[str, str]) -> GeoRange:
    cidr = row.get("cidr", "").strip()
    if cidr:
        net = ipaddress.ip_network(cidr, strict=False)
        start = int(net.network_address)
        end = int(net.broadcast_address)
    else:
        start = int(ipaddress.ip_address(row["start"].strip().lstrip("\ufeff")))
        end = int(ipaddress.ip_address(row["end"].strip()))
    return GeoRange(
        start=start,
        end=end,
        country_code=(row.get("country_code") or "??").strip().upper(),
        country=(row.get("country") or "Unknown").strip(),
        city=(row.get("city") or "").strip(),
        asn=(row.get("asn") or "").strip(),
        org=(row.get("org") or "").strip(),
    )
