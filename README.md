# Nettop

Nettop is a lightweight Linux-first network monitoring TUI with a scriptable CLI controller. It captures traffic, ranks source IPs, tracks PPS and byte rates, shows MAC activity, and resolves IP geography from Nettop's own offline `location.csv`.

It does not call online APIs, does not phone home, and does not download geo data at runtime.

## Quick Start

```bash
python3 -m pip install -e .[full]
sudo nettop run --dst 0.0.0.0 --port 0 --iface eth0
```

Rootless demo:

```bash
nettop demo
```

Change a running monitor:

```bash
nettopctl status
nettopctl set --dst 192.168.1.10 --port 80,443
nettopctl top 50
nettopctl pause
nettopctl resume
nettopctl snapshot
nettopctl stop
```

Inside the TUI, use:

```text
d change destination IP
p change destination ports
s change source IP
y change protocol filter
t change top row count
space pause/resume
r reset counters
q quit
```

## Offline Geo

The default geo database is bundled at:

```text
nettop/location.csv
```

The resolver is pure Python standard library code. It loads CIDR or start/end ranges, searches them in memory, and returns country, city, ASN, and organization fields when present.

CSV format:

```csv
cidr,country_code,country,city,asn,org
8.8.8.0/24,US,United States,,AS15169,Google
1.1.1.0/24,AU,Australia,,AS13335,Cloudflare
```

Alternative range format:

```csv
start,end,country_code,country,city,asn,org
8.8.8.0,8.8.8.255,US,United States,,AS15169,Google
```

Use a custom database:

```bash
sudo nettop run --location-db /opt/nettop/location.csv
```

Update from DB-IP Lite:

```bash
sudo nettop update-db --output /var/lib/nettop/location.csv --kind city
```

The systemd timer in `packaging/systemd/nettop-db-update.timer` runs that update weekly. DB-IP Lite downloads are updated monthly, so the weekly job checks for the latest available monthly release and keeps the installed database fresh.

Private, loopback, link-local, multicast, reserved, and invalid IPs are classified locally with Python's `ipaddress` module.

## What It Tracks

Core live metrics include:

- total packets, bytes, current PPS, average PPS, byte rate
- unique source IPs, destination IPs, protocols, ports, TCP flags, packet sizes
- per-IP packets, bytes, current PPS, 10-second PPS, 60-second PPS, low PPS, peak PPS, first/last nanosecond timestamps
- MAC packet counts, MAC current PPS, MAC 60-second PPS
- country ranking, local/private IP classification, optional ASN/org data from `location.csv`
- alerts for new IPs, new MACs, and high PPS

Print the full catalog:

```bash
nettop features
```

## Linux Install


Ubuntu install:
```bash
sudo add-apt-repository ppa:najuaircrack/nettop
sudo apt update
sudo apt install nettop
```

Other install:
```bash
curl -fsSL https://nettop.cybroxa.com/nettop.gpg \
| sudo gpg --dearmor -o /usr/share/keyrings/nettop.gpg

echo "deb [signed-by=/usr/share/keyrings/nettop.gpg] https://nettop.cybroxa.com stable main" \
| sudo tee /etc/apt/sources.list.d/nettop.list

sudo apt update
sudo apt install nettop
```

Developer install:

```bash
git clone https://github.com/najuaircrack/Nettop.git
cd Nettop
python3 -m pip install .[full]
```

System service files are in `packaging/systemd`. Debian metadata is in `packaging/debian`; use it as the starting point for building a `.deb` and publishing it through your own APT repository.

## APT Publishing Outline

On a Debian/Ubuntu build host:

```bash
sudo apt install build-essential debhelper dh-python python3-all python3-setuptools python3-rich python3-scapy pybuild-plugin-pyproject
cp -r packaging/debian ./debian
dpkg-buildpackage -us -uc
```

Then publish the generated `.deb` in an APT repository using your normal repo tooling, such as `reprepro` or `aptly`.

## Useful Commands

```bash
nettop doctor
nettop demo --top 30 --interval 0.5
sudo nettop run --dst 10.0.0.5 --port 22,80,443 --jsonl /var/log/nettop/events.jsonl
sudo nettop run --pcap capture.pcap --no-geo
```

## Design

The code is modular:

- `nettop.capture`: Scapy capture, raw socket fallback, demo traffic, PCAP replay
- `nettop.store`: thread-safe counters and PPS windows
- `nettop.geo`: offline resolver backed by Nettop's CSV module
- `nettop.puregeo`: dependency-free CSV/range resolver
- `nettop.control`: Unix socket runtime controller
- `nettop.tui`: responsive Rich dashboard
- `nettop.exporters`: JSON/CSV/JSONL export
- `nettop.alerts`: lightweight alert engine
