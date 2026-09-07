"""Module 6 - Crawling with katana.

Discovers URLs for each live subdomain. Outputs per-host ``urls_<sub>.txt``
and a combined ``all_urls.json``.
"""
from __future__ import annotations

import json
from pathlib import Path

from recon.utils import helpers
from recon.utils.logger import console, log
from recon.utils.runner import run_stream, which

REQUIRED_TOOL = "katana"
URLS_DIR = "urls"


def _sanitize_host(host: str) -> str:
    return host.replace("/", "_").replace(":", "_")


def run(in_file, urls_dir: Path, all_urls_json, live_hosts: list[str], timeout: int = 300) -> dict:
    targets = live_hosts or [h for h in helpers.read_lines(in_file) if h]
    if not which(REQUIRED_TOOL):
        log.warning("%s not available; skipping crawling.", REQUIRED_TOOL)
        return {}
    log.info("Crawling %s host(s) with katana ...", len(targets))
    results: dict = {}

    # katana crawls one seed URL at a time for clean per-host files.
    for i, host in enumerate(targets, 1):
        scheme = "https" if host.endswith((":443", "")) else host
        seed = host if host.startswith("http") else f"https://{host}"
        urls: list[str] = []
        per_host_file = urls_dir / f"urls_{_sanitize_host(host)}.txt"

        def on_line(line: str) -> None:
            u = line.strip()
            if not u:
                return
            urls.append(u)
            helpers.append_line(per_host_file, u)
            results.setdefault(host, []).append(u)
            helpers.atomic_json_write(all_urls_json, results)

        cmd = [
            which(REQUIRED_TOOL), "-u", seed,
            "-silent",
            "-js-crawl",
            "-depth", "3",
            "-c", "10",
            "-timeout", str(min(timeout, 60)),
        ]
        code, _ = run_stream(cmd, timeout=timeout, on_line=on_line)
        if code not in (0, 124):
            log.warning("katana exited %s on %s", code, host)
        console.print(f"  [{i}/{len(targets)}] {host}: {len(urls)} URLs")

    total = sum(len(v) for v in results.values())
    console.print(f"[green][+] Crawling done: {total} URLs from {len(results)} hosts[/green]")
    return results
