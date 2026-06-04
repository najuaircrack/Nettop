# Contributing

Thanks for helping improve Nettop.

## Development Setup

```bash
python -m venv .venv
.venv/bin/python -m pip install -e .[full]
.venv/bin/python -m pytest
```

On Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .[full]
.\.venv\Scripts\python.exe -m pytest
```

## Quality Bar

- Keep runtime packet paths allocation-light.
- Do not add online geolocation APIs.
- Keep packet capture, store, geo, control, TUI, and exporters modular.
- Add focused tests for parsing, lookup, and control behavior.
- Keep docs accurate for Linux deployment.

