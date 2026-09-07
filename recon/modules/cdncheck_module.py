"""Module 3 - CDN / WAF detection.

Uses ``cdncheck`` if available. Otherwise we fall back to a lightweight HTTP
header heuristics pass built into this module (no extra binary needed).
"""
from __future__ import annotations

import json

from recon.utils import helpers
from recon.utils.logger import console, log
from recon.utils.runner import run_stream, which

REQUIRED_TOOL = "cdncheck"
OUT_JSON = "cdn_status.json"

# Known markers: provider name -> list of substrings seen in headers/cname.
_KNOWN = [
    ("Cloudflare", ["cloudflare"]),
    ("Akamai", ["akamai"]),
    ("Fastly", ["fastly"]),
    ("Amazon CloudFront", ["cloudfront", "amazon"]),
    ("Google Cloud CDN", ["google"]),
    ("Azure Front Door", ["microsoft", "azure", "frontdoor"]),
    ("Imperva", ["imperva", "incapsula"]),
    ("Sucuri", ["sucuri"]),
    ("StackPath", ["stackpath"]),
    ("CDN77", ["cdn77"]),
    ("KeyCDN", ["keycdn"]),
    ("Limelight", ["limelight"]),
    ("Alibaba", ["aliyun"]),
]


def _fallback(host: str, ip: str | None) -> tuple[bool, str]:
    """Header-based CDN guess when cdncheck is unavailable."""
    import urllib.request

    detect = ""
    try:
        req = urllib.request.Request(
            f"https://{host}", method="GET", headers={"User-Agent": "JazRecon/1.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            detect = " ".join(resp.headers.values()).lower()
            for name, markers in _KNOWN:
                if any(m in detect for m in markers):
                    return True, name
    except Exception:
        return False, ""
    return False, ""


def _load(out_file) -> dict:
    if out_file.exists():
        try:
            return json.loads(out_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def _save(out_file, data: dict) -> None:
    helpers.atomic_json_write(out_file, data)


def run(ips_json_file, host_map: dict, out_file, timeout: int = 300) -> dict:
    """Check each host for CDN/WAF; write live to JSON.

    ``host_map`` maps host -> [ip,...] from the dnsx module.
    """
    log.info("Running CDN detection ...")
    result: dict = _load(out_file)

    entries = list(host_map.items())
    if not entries:
        log.warning("No host/IP data to check for CDN.")

    for idx, (host, ips) in enumerate(entries, 1):
        ip = ips[0] if ips else None
        is_cdn, cdn_name = _check_host(host, ip, timeout)
        result[host] = {"is_cdn": is_cdn, "cdn_name": cdn_name}
        _save(out_file, result)  # streaming write after each host
        status = f"[yellow]{cdn_name}[/yellow]" if is_cdn else "[dim]origin[/dim]"
        console.print(f"  [{idx}/{len(entries)}] {host} -> {status}")

    n_cdn = sum(1 for v in result.values() if v["is_cdn"])
    console.print(f"[green][+] CDN check done: {n_cdn}/{len(result)} behind CDN[/green]")
    return result


def _check_host(host: str, ip: str | None, timeout: int) -> tuple[bool, str]:
    if which(REQUIRED_TOOL):
        # cdncheck can take cidr/ip/host; try host with resolve of raw ip too.
        cmd = [which(REQUIRED_TOOL), "-resp-only", "-nc", "-silent", host]
        out: list[str] = []

        def on_line(line: str) -> None:
            out.append(line.strip())

        code, _ = run_stream(cmd, timeout=timeout, on_line=on_line)
        if code == 0:
            for name, markers in _KNOWN:
                blob = " ".join(out).lower()
                if any(m in blob for m in markers):
                    return True, name
            if out and any(w in " ".join(out).lower() for w in ("cdn", "waf", "cloud", "proxy", "non-cdn", "not-cdn")):
                return True, out[0]
    return _fallback(host, ip)
