from __future__ import annotations

import argparse
import csv
import gzip
import ipaddress
import os
import shutil
import tempfile
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path


DBIP_BASE_URL = "https://download.db-ip.com/free"
DEFAULT_OUTPUT = Path(__file__).with_name("location.csv")


def month_candidates(today: date | None = None, count: int = 4) -> list[str]:
    current = today or date.today()
    year = current.year
    month = current.month
    values: list[str] = []
    for _ in range(count):
        values.append(f"{year:04d}-{month:02d}")
        month -= 1
        if month == 0:
            month = 12
            year -= 1
    return values


def download_latest(kind: str, workdir: Path, months: list[str] | None = None) -> Path:
    months = months or month_candidates()
    errors: list[str] = []
    for month in months:
        name = f"dbip-{kind}-lite-{month}.csv.gz"
        url = f"{DBIP_BASE_URL}/{name}"
        dest = workdir / name
        try:
            with urllib.request.urlopen(url, timeout=60) as response, dest.open("wb") as handle:
                shutil.copyfileobj(response, handle)
            return dest
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
            errors.append(f"{url}: {exc}")
    raise RuntimeError("Could not download DB-IP Lite database:\n" + "\n".join(errors))


def convert_dbip(dbip_csv_gz: Path, output: Path) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=str(output.parent))
    os.close(fd)
    tmp = Path(tmp_name)
    count = 0
    try:
        with gzip.open(dbip_csv_gz, "rt", encoding="utf-8-sig", newline="") as source, tmp.open(
            "w", encoding="utf-8", newline=""
        ) as target:
            reader = csv.reader(source)
            writer = csv.writer(target, lineterminator="\n")
            writer.writerow(["start", "end", "country_code", "country", "city", "asn", "org"])
            for row in reader:
                if len(row) >= 8:
                    start, end, _continent, country, stateprov, city, _lat, _lon = row[:8]
                    city_name = city.strip() or stateprov.strip()
                elif len(row) >= 3:
                    start, end, country = row[:3]
                    city_name = ""
                else:
                    continue
                code = country.strip().upper() or "??"
                start = start.strip().lstrip("\ufeff")
                end = end.strip()
                try:
                    ipaddress.ip_address(start)
                    ipaddress.ip_address(end)
                except ValueError:
                    continue
                writer.writerow([start, end, code, code, city_name, "", "DB-IP Lite"])
                count += 1
        tmp.replace(output)
    finally:
        if tmp.exists():
            tmp.unlink()
    return count


def update_location(output: str | None = None, kind: str = "city", workdir: str | None = None) -> Path:
    out = Path(output).expanduser() if output else DEFAULT_OUTPUT
    scratch = Path(workdir).expanduser() if workdir else Path(tempfile.mkdtemp(prefix="nettop-dbip-"))
    scratch.mkdir(parents=True, exist_ok=True)
    source = download_latest(kind, scratch)
    count = convert_dbip(source, out)
    print(f"updated {out} from {source.name} with {count:,} ranges")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Download DB-IP Lite CSV and convert it to Nettop location.csv")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output location.csv path")
    parser.add_argument("--kind", default="city", choices=["city", "country"], help="DB-IP Lite database kind")
    parser.add_argument("--workdir", default=None, help="Temporary download directory")
    args = parser.parse_args(argv)
    update_location(args.output, args.kind, args.workdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
