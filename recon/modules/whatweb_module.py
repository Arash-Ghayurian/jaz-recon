"""Module 8 - WhatWeb web technology fingerprinting.

Runs ``whatweb`` against every discovered subdomain (both http:// and
https://), capturing the HTTP status and detected plugins (web server,
CMS, framework, ...) per host. The raw whatweb JSON array is produced in
real time by whatweb itself; we then normalise it into a clean per-host
map written to ``whatweb.json``.
"""
from __future__ import annotations

import json

from recon.utils import helpers
from recon.utils.logger import console, log
from recon.utils.runner import run_stream, which

REQUIRED_TOOL = "whatweb"
OUT_JSON = "whatweb.json"


def run(in_file, out_file, timeout: int = 300, threads: int = 10) -> list[dict]:
    subs = [s for s in helpers.read_lines(in_file) if s]
    binary = which(REQUIRED_TOOL)
    if not binary:
        log.warning("%s not available; skipping WhatWeb fingerprinting.", REQUIRED_TOOL)
        return []
    if not subs:
        log.warning("no subdomains to fingerprint with %s.", REQUIRED_TOOL)
        return []

    log.info("WhatWeb fingerprinting %s hosts ...", len(subs))
    # Test both schemes so whatweb fingerprints whichever is actually served.
    targets = []
    for s in subs:
        host = s.strip()
        if "://" not in host:
            targets.append(f"http://{host}/")
            targets.append(f"https://{host}/")
        else:
            targets.append(host)

    # whatweb (this version) needs an input file (-i); it ignores piped stdin.
    targets_file = out_file.with_name("whatweb_targets.txt")
    targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
    # whatweb appends to --log-json, so make sure we start from a clean file.
    out_file.unlink(missing_ok=True)

    cmd = [
        binary,
        "-q",
        "-i", str(targets_file),
        "--log-json", str(out_file),
        "--max-threads", str(max(1, threads)),
        "--open-timeout", str(min(timeout, 15)),
        "--read-timeout", str(min(timeout, 30)),
    ]
    code, _ = run_stream(cmd, timeout=timeout)
    if code not in (0, 124):
        log.warning("whatweb exited with code %s", code)
    targets_file.unlink(missing_ok=True)

    records = _normalise(out_file)
    _clean_write(out_file, records)
    console.print(
        f"[green][+] WhatWeb done: fingerprinted {len(records)} host(s)[/green]"
    )
    return records


def _normalise(out_file) -> list[dict]:
    """Load the raw whatweb JSON array (created by whatweb itself)."""
    if not out_file.exists():
        return []
    try:
        data = json.loads(out_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(data, list):
        return []
    return [e for e in data if isinstance(e, dict)]


def _clean_write(out_file, records: list[dict]) -> None:
    """Store a tidy per-host map (raw entries keyed by url, deduped)."""
    clean: dict[str, dict] = {}
    for rec in records:
        url = str(rec.get("target", "")).rstrip("/")
        if not url:
            continue
        clean[url] = {
            "url": url,
            "http_status": rec.get("http_status"),
            "response_time": rec.get("response_time"),
            "plugins": rec.get("plugins") or {},
        }
    helpers.atomic_json_write(out_file, clean)
