# Jaz Recon

> Automated reconnaissance framework for **authorized** penetration testing and security assessments.

Jaz Recon takes a target (domain or IP), runs a full recon pipeline using well-known tools, and
streams every result to `txt`/`json` files **in real time** inside a timestamped folder.

<p align="left">
  <img alt="Python" src="https://img.shields.io/badge/python-3.9%2B-blue.svg">
  <img alt="Platform" src="https://img.shields.io/badge/platform-linux%20%7C%20ubuntu-lightgrey.svg">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green.svg">
  <img alt="Status" src="https://img.shields.io/badge/status-active-brightgreen.svg">
</p>

---

## Features

- **8-stage recon pipeline** — subdomains, DNS, CDN/WAF detection, ports, HTTP, crawling,
  vulnerability scanning, and fingerprinting.
- **Real-time streaming output** — results are appended to files the moment they are discovered,
  so you can monitor a long scan without waiting for it to finish.
- **Graceful degradation** — every stage is independent; a missing tool or a failing stage is
  logged and the pipeline continues.
- **Automatic tool installation** — missing ProjectDiscovery tools are installed via `go install`
  and system tools via the OS package manager (disable with `--no-install`).
- **CDN-aware port scanning** — synthetic CDN edge IPs are skipped by default (`--force-ports`
  to override).
- **Colored terminal UI** with live progress and a final summary table.
- **Per-run artifacts** — a timestamped folder with raw outputs, structured JSON, a full
  `summary.json`, and a detailed `recon.log`.

---

## Requirements

- **Python 3.9+**
- **Go** (to install ProjectDiscovery tools — if missing, the installer skips them)
- **nmap** *(optional)* — used when `--scanner nmap` is selected; auto-installed if possible
- Linux or Ubuntu (Windows via WSL)

---

## Installation

```bash
git clone https://github.com/Arash-Ghayurian/jaz-recon.git
cd jaz-recon

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

External tools are installed automatically on first run. To install them manually:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
```

> **Tip:** make sure `$(go env GOPATH)/bin` (usually `~/go/bin`) is on your `PATH`.
> `whatweb` and `nmap` are system packages and are installed with apt/dnf/pacman/brew if missing.

---

## Usage

### Full pipeline on a domain

```bash
python recon.py --target example.com
```

### Public test target

```bash
python recon.py --target scanme.nmap.org
```

### Run only selected stages

```bash
python recon.py --target example.com --modules subdomains,http,nuclei
```

### Use nmap for more accurate port scanning

```bash
python recon.py --target example.com --scanner nmap
```

### Scan all nuclei severities

```bash
python recon.py --target example.com --severity all
```

### Tune concurrency / timeout

```bash
python recon.py --target example.com --threads 20 --timeout 600
```

### Custom output directory

```bash
python recon.py --target example.com --output-dir /tmp/out
```

### Scan IPs behind a CDN

```bash
python recon.py --target example.com --force-ports
```

---

## CLI Options

| Flag | Description | Default |
| ------ | ------------- | --------- |
| `-t, --target` | Target domain or IP address | **required** |
| `-o, --output-dir` | Base output directory | `./results` |
| `-m, --modules` | Comma-separated stages to run | all |
| `--scanner` | Port scanner: `naabu` (fast) or `nmap` (accurate) | `naabu` |
| `--severity` | Nuclei severity filter (`medium,critical`, `high`, `all`, ...) | `medium,critical` |
| `--threads` | Max concurrency for parallel stages | `10` |
| `--timeout` | Per-tool timeout in seconds | `300` |
| `--force-ports` | Also port-scan IPs behind a CDN/WAF | off |
| `--no-install` | Do not auto-install missing tools | off |
| `--version` | Print version and exit | – |

Valid module names: `subdomains`, `dns`, `cdn`, `ports`, `http`, `crawl`, `nuclei`, `whatweb`.

---

## Pipeline

| # | Stage | Tool | Fallback | Output |
| --- | ------- | ------ | ---------- | -------- |
| 1 | Subdomain Enumeration | `subfinder` | `crt.sh` (CT logs) | `subdomains.txt` |
| 2 | DNS Resolution | `dnsx` | – | `subdomains_ips.json` |
| 3 | CDN / WAF Detection | `cdncheck` | HTTP headers | `cdn_status.json` |
| 4 | Port Scanning | `naabu` / `nmap` | – | `ports/`, `all_ports.json` |
| 5 | HTTP Probing | `httpx` | – | `http_probe.json` |
| 6 | Crawling | `katana` | – | `urls/`, `all_urls.json` |
| 7 | Vulnerability Scanning | `nuclei` | – | `nuclei_results.json` |
| 8 | Fingerprinting | `whatweb` | – | `whatweb.json` |

Stages run in dependency order and are skipped if their input is unavailable.

---

## Output Structure

```
results/example.com_2026-09-07_14-30-00/
├── subdomains.txt          # all discovered subdomains (one per line)
├── subdomains_ips.json     # {host: [ip, ...]}
├── cdn_status.json         # {host: {is_cdn, cdn_name}}
├── ports/
│   ├── ports_<ip>.txt      # open ports per IP
│   └── (raw per-IP results)
├── all_ports.json          # {ip: [port, ...]}
├── http_probe.json         # httpx results (status, title, tech, ...)
├── urls/
│   ├── urls_<host>.txt     # crawled URLs per host
│   └── (raw per-host results)
├── all_urls.json           # {host: [url, ...]}
├── nuclei_results.json     # vulnerability findings
├── whatweb.json            # technology fingerprints
├── summary.json            # aggregate metrics for the run
└── recon.log               # full debug log
```

### `summary.json` example

```json
{
  "target": "example.com",
  "started": "2026-09-07 14:30:00",
  "finished": "2026-09-07 14:42:11",
  "total_subdomains": 37,
  "resolved_hosts": 31,
  "cdn_hosts": 6,
  "open_ports": 18,
  "http_live": 24,
  "total_urls_found": 512,
  "nuclei_findings": 3,
  "nuclei_by_severity": { "medium": 2, "low": 1 },
  "output_dir": "results/example.com_2026-09-07_14-30-00"
}
```

---

## Project Structure

```
jaz-recon/
├── recon.py                  # CLI entry point / argument parsing
├── requirements.txt
├── README.md
└── recon/
    ├── __init__.py
    ├── orchestrator.py       # pipeline coordinator + summary
    ├── utils/
    │   ├── __init__.py
    │   ├── logger.py         # colored logging (rich) + banner
    │   ├── helpers.py        # JSON / file / target helpers
    │   ├── runner.py         # streaming subprocess execution
    │   └── tools.py          # tool detection & auto-install
    └── modules/
        ├── __init__.py
        ├── subdomains.py     # 1. subfinder + crt.sh fallback
        ├── dnsx_module.py    # 2. DNS resolution
        ├── cdncheck_module.py# 3. CDN / WAF detection
        ├── ports.py          # 4. naabu / nmap port scan
        ├── httpx_module.py   # 5. HTTP probing
        ├── katana_module.py  # 6. crawling
        ├── nuclei_module.py  # 7. vulnerability scanning
        └── whatweb_module.py # 8. fingerprinting
```

---

## How Streaming Works

Every external tool is launched through `recon/utils/runner.py`, which reads the process
`stdout` line by line and invokes a callback per line. Each module's callback appends the parsed
result to the relevant file immediately (thread-safe, atomic JSON writes). This means a scan that
takes hours still produces usable, incrementally updated results.

---

## Troubleshooting

| Problem | Fix |
| --------- | ----- |
| `tool not found on PATH: subfinder` | Add `$(go env GOPATH)/bin` to `PATH`, or run without `--no-install`. |
| Port scan skipped: *"No real (non-CDN) IPs"* | The target is behind a CDN. Use `--force-ports` if you really want to scan edge IPs. |
| `go install` fails / times out | Check network access, `GOPROXY`, and Go version. Install the tool manually. |
| System tool install fails | Re-run with `sudo`, or install `nmap` / `whatweb` with your package manager. |
| `nuclei` finds nothing | Try `--severity all` and make sure templates are updated (`nuclei -update-templates`). |
| Want more detail | Inspect `recon.log` inside the run folder — it contains full debug output. |

---

## Acknowledgements

Built on top of excellent open-source projects by
[ProjectDiscovery](https://github.com/projectdiscovery) (subfinder, httpx, naabu, nuclei, katana,
dnsx, cdncheck), [Nmap](https://nmap.org/), [WhatWeb](https://github.com/urbanadventurer/WhatWeb),
and [crt.sh](https://crt.sh/).
