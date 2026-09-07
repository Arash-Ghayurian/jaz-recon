"""Module 5 - HTTP probing with httpx.

Probes each subdomain, capturing status code, title, tech stack and server
header. Results stream into ``http_probe.json``.
"""
from __future__ import annotations

import json

from recon.utils import helpers
from recon.utils.logger import console, log
from recon.utils.runner import run_stream, which

REQUIRED_TOOL = "httpx"
OUT_JSON = "http_probe.json"

_loaded = False


def _banner_seen() -> bool:
    global _loaded
    if not _loaded:
        return False
    return True


def run(in_file, out_file, cdn_hosts: set[str], timeout: int = 300) -> list[dict]:
    subs = [s for s in helpers.read_lines(in_file) if s]
    binary = which(REQUIRED_TOOL)
    if not binary:
        log.warning("%s not available; skipping HTTP probing.", REQUIRED_TOOL)
        return []
    log.info("HTTP probing %s hosts ...", len(subs))
    results: list[dict] = []

    # httpx accepts a list of URLs/subdomains on stdin.
    inp = "\n".join(subs) + "\n"
    base_out = {}

    def on_line(line: str) -> None:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return
        host = str(obj.get("input", "") or obj.get("url", "")).rstrip("/")
        record = {
            "url": obj.get("url", ""),
            "input": obj.get("input", ""),
            "status": obj.get("status_code"),
            "title": obj.get("title"),
            "tech": obj.get("tech") or [],
            "server": obj.get("webserver") or (obj.get("server", "") if isinstance(obj.get("server"), str) else ""),
            "content_length": obj.get("content_length"),
            "cdn": obj.get("cdn", None),
            "final_url": obj.get("final_url", ""),
        }
        results.append(record)
        base_out[host] = record
        helpers.atomic_json_write(out_file, base_out)

    cmd = [
        binary, "-silent", "-json",
        "-status-code", "-title", "-tech-detect", "-web-server",
        "-timeout", str(min(timeout, 30)),
        "-threads", "30",
    ]
    code, _ = run_stream(cmd, timeout=timeout, stdin_text=inp, on_line=on_line)
    if code not in (0, 124):
        log.warning("httpx exited with code %s", code)

    # merge results into cdn aware set and print summary
    live = sum(1 for r in results if r.get("status") and 200 <= int(r["status"]) < 400)
    console.print(f"[green][+] HTTP probing done: {len(results)} responded ({live} 2xx/3xx)[/green]")
    return results
