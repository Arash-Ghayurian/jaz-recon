"""Module 7 - Vulnerability scanning with nuclei.

Targets live HTTP hosts. Default severity is medium..critical; pass
``severity='all'`` to include everything.
"""
from __future__ import annotations

import json

from recon.utils import helpers
from recon.utils.logger import console, log
from recon.utils.runner import run_stream, which

REQUIRED_TOOL = "nuclei"
OUT_JSON = "nuclei_results.json"

SEVERITIES = ["critical", "high", "medium", "low", "info"]


def run(targets_file, out_file, live_hosts: list[str], severity: str = "medium,critical",
        timeout: int = 600, rate_limit: int = 150) -> list[dict]:
    targets = live_hosts or helpers.read_lines(targets_file)
    if not which(REQUIRED_TOOL):
        log.warning("%s not available; skipping vulnerability scan.", REQUIRED_TOOL)
        return []

    if severity and severity.lower() != "all":
        allowed = [s for s in SEVERITIES if s in severity.lower()]
    else:
        allowed = SEVERITIES

    log.info("Running nuclei (severity: %s) on %s target(s) ...",
             ",".join(allowed) if allowed else "all", len(targets))

    results: list[dict] = []
    base = {"findings": []}

    def on_line(line: str) -> None:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return
        rec = {
            "template": obj.get("template-id", ""),
            "name": obj.get("info", {}).get("name", ""),
            "severity": obj.get("info", {}).get("severity", ""),
            "matched_at": obj.get("matched-at", ""),
            "url": obj.get("host", ""),
            "type": obj.get("type", ""),
            "description": obj.get("info", {}).get("description", ""),
        }
        # Only keep findings that match our severity whitelist.
        sev = rec["severity"].lower()
        if allowed and sev not in allowed:
            return
        results.append(rec)
        base["findings"] = results
        helpers.atomic_json_write(out_file, base)

    # Feed each live host line-by-line so every finding streams immediately.
    for host in targets:
        inp = host + "\n" if not host.startswith("http") else host + "\n"
        cmd = [which(REQUIRED_TOOL), "-silent", "-jsonl", "-timeout", str(min(timeout, 60))]
        if allowed:
            cmd += ["-severity"] + allowed
        cmd += ["-rl", str(rate_limit)]
        run_stream(cmd, timeout=timeout, stdin_text=inp, on_line=on_line)

    # Ensure an output file exists even when nothing was found.
    if not out_file.exists():
        helpers.atomic_json_write(out_file, {"findings": []})

    by_sev: dict[str, int] = {}
    for r in results:
        s = r["severity"].lower()
        by_sev[s] = by_sev.get(s, 0) + 1
    console.print(f"[green][+] Nuclei done: {len(results)} findings {by_sev}[/green]")
    return results
