# Jaz Recon

An automated Recon tool for pentest/security (only for **authorized testing**). It takes a target (domain or IP), runs the recon pipeline with well-known tools, and saves results **in real time (streaming)** to `txt` and `json` files inside a timestamped folder.

---

## Installation

Prerequisites:

- **Python 3.9+**
- **Go** (to install the ProjectDiscovery tools - if not installed, the installer skips them)
- **nmap** (optional; if missing, the tool tries to install it via the system package manager)

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Install external tools

The tool checks during execution and, if a tool is missing, installs it automatically (the `--no-install` flag disables this behavior):

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
```

`whatweb` is a system tool and, if missing, the tool installs it with the system package manager (apt/dnf/pacman/brew).

If `GOBIN` is not in PATH, add `$(go env GOPATH)/bin` to PATH.

---

## Usage

### Simplest case (all steps)

```bash
python recon.py --target example.com
```

### Example with a public test target

```bash
python recon.py --target scanme.nmap.org
```

### Only a subset of steps

```bash
python recon.py --target example.com --modules subdomains,http,nuclei
```

### Choosing a port scanner (nmap more accurate / naabu faster)

```bash
python recon.py --target example.com --scanner nmap
```

### Scan all nuclei severities

```bash
python recon.py --target example.com --severity all
```

### Controlling concurrency and timeout

```bash
python recon.py --target example.com --threads 20 --timeout 600
```

### Specifying an output folder

```bash
python recon.py --target example.com --output-dir /tmp/out
```

---

## Options (CLI)

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target (domain or IP) | Required |
| `-o, --output-dir` | Base output folder | `./results` |
| `-m, --modules` | Selected steps (comma-separated) | All |
| `--scanner` | `nmap` or `naabu` | `naabu` |
| `--severity` | Nuclei severity filter | `medium,critical` |
| `--threads` | Max concurrency | `10` |
| `--timeout` | Timeout for each tool (seconds) | `300` |
| `--force-ports` | Also scan IPs behind a CDN | Off |
| `--no-install` | Disable automatic tool installation | Off |
| `--version` | Show version | - |

---

## Pipeline

| # | Step | Tool | Output |
|---|------|------|--------|
| 1 | Subdomain Enumeration | `subfinder` (fallback: crt.sh) | `subdomains.txt` |
| 2 | DNS Resolution | `dnsx` | `subdomains_ips.json` |
| 3 | CDN/WAF Detection | `cdncheck` (fallback: headers) | `cdn_status.json` |
| 4 | Port Scanning | `nmap` or `naabu` | `ports/*` , `all_ports.json` |
| 5 | HTTP Probing | `httpx` | `http_probe.json` |
| 6 | Crawling | `katana` | `urls/*` , `all_urls.json` |
| 7 | Vulnerability Scanning | `nuclei` | `nuclei_results.json` |
| 8 | WhatWeb Fingerprinting | `whatweb` | `whatweb.json` |

### Output structure

```
results/example.com_2026-09-07_14-30-00/
├── subdomains.txt
├── subdomains_ips.json
├── cdn_status.json
├── ports/
│   ├── all_ports.json
│   └── ports_<ip>.txt
├── http_probe.json
├── urls/
│   ├── all_urls.json
│   └── urls_<subdomain>.txt
├── nuclei_results.json
├── whatweb.json
├── summary.json
└── recon.log
```

Results are written **in real time**: as soon as each subdomain/port/result is discovered, it is appended to the corresponding file immediately.

---

## Important notes

- **CDN:** By default only real (non-CDN) IPs are port-scanned, since IPs behind a CDN are synthetic. Use `--force-ports` to scan everything.
- **Fault tolerance:** Each step is independent; if a tool is not installed or a step fails, the next step continues and errors are logged in `recon.log`.
- **`summary.json`** saves a full summary at the end (subdomain count, open ports, vulnerabilities broken down by severity).

---

## Project structure

```
jaz_recon/
├── recon.py                       # Main CLI entry / orchestrator
├── requirements.txt
├── README.md
└── recon/
    ├── __init__.py
    ├── orchestrator.py            # Pipeline coordinator
    ├── utils/
    │   ├── __init__.py
    │   ├── logger.py              # Logging and colored output (rich)
    │   ├── helpers.py             # JSON/file helper functions
    │   ├── runner.py              # Streaming execution via subprocess.Popen
    │   └── tools.py               # Tool checks and auto-install
    └── modules/
        ├── __init__.py
        ├── subdomains.py          # Step 1
        ├── dnsx_module.py         # Step 2
        ├── cdncheck_module.py     # Step 3
        ├── ports.py               # Step 4
        ├── httpx_module.py        # Step 5
        ├── katana_module.py       # Step 6
        ├── nuclei_module.py       # Step 7
        └── whatweb_module.py      # Step 8
```

---

## Real example

```bash
pip install -r requirements.txt
python recon.py --target scanme.nmap.org --scanner nmap
```

The final output is saved in `results/scanme.nmap.org_<timestamp>/` and a colored summary is printed in the terminal.
