"""Module 2 - DNS resolution with dnsx.

Maps each subdomain to its IPv4/IPv6 addresses and streams the mapping to a
JSON file as results arrive.
"""
from __future__ import annotations

import json

from recon.utils import helpers
from recon.utils.logger import console, log
from recon.utils.runner import run_stream, which

REQUIRED_TOOL = "dnsx"
OUT_JSON = "subdomains_ips.json"


def _handle_record(out_file) -> None:
    def on_line(line: str) -> None:
        # dnsx -json line: {"host":"x.com","a":["1.2.3.4"],...}
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return
        host = str(obj.get("host", "")).lower().rstrip(".")
        ips = []
        for key in ("a", "aaaa"):
            ips.extend([str(x) for x in obj.get(key, [])])
        if not host or not ips:
            return
        _merge(out_file, host, ips)

    return on_line


def _merge(out_file, host: str, new_ips: list[str]) -> None:
    existing = {}
    if out_file.exists():
        try:
            existing = json.loads(out_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = {}
    cur = set(existing.get(host, []))
    cur.update(new_ips)
    existing[host] = sorted(cur)
    helpers.atomic_json_write(out_file, existing)


def run(in_file, out_file, timeout: int = 300) -> dict:
    """Resolve every subdomain in ``in_file`` and store IP mapping in JSON."""
    subs = helpers.read_lines(in_file)
    log.info("Resolving %s subdomains with dnsx ...", len(subs))
    mapping: dict = {}
    for host in subs:
        # Resolve each host by feeding it on stdin (dnsx -d requires a
        # wordlist; per-host stdin keeps streaming granular and avoids one
        # huge run).
        cmd = [which(REQUIRED_TOOL), "-silent", "-json", "-a", "-aaaa", "-resp"]
        handler = _handle_record(out_file)

        def wrapper(line: str) -> None:
            handler(line)
            # also accumulate in-memory copy
            try:
                obj = json.loads(line)
                h = str(obj.get("host", "")).lower().rstrip(".")
                ip = obj.get("a") or obj.get("aaaa") or []
                mapping.setdefault(h, []).extend(ip)
            except json.JSONDecodeError:
                pass

        run_stream(cmd, timeout=timeout, stdin_text=host + "\n", on_line=wrapper)

    if out_file.exists():
        try:
            mapping = json.loads(out_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass

    total_ips = sum(len(v) for v in mapping.values())
    console.print(f"[green][+] Resolved {len(mapping)} hosts -> {total_ips} IPs[/green]")
    return mapping
