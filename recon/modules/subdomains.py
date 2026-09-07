"""Module 1 - Subdomain enumeration.

Primary source: ``subfinder``. If unavailable we fall back to crt.sh
(Certificate Transparency) which requires no local binary.
"""
from __future__ import annotations

from recon.utils import helpers
from recon.utils.logger import console, log
from recon.utils.runner import run_stream, which

MODULE_NAME = "subdomains"
REQUIRED_TOOL = "subfinder"


def _subfinder(domain: str, out_file, timeout: int) -> None:
    def on_line(line: str) -> None:
        sd = line.strip().lower().rstrip(".")
        if sd and sd.endswith(domain):
            helpers.append_line(out_file, sd)

    cmd = [which(REQUIRED_TOOL), "-d", domain, "-silent", "-all"]
    log.info("Running subfinder on %s ...", domain)
    code, _ = run_stream(cmd, timeout=timeout, on_line=on_line)
    if code not in (0, 124):
        log.warning("subfinder exited with code %s for %s", code, domain)


def _crt_sh(domain: str, out_file, timeout: int) -> None:
    """Fallback via Certificate Transparency logs (no binary required)."""
    import json
    import urllib.request

    log.info("Falling back to crt.sh for %s ...", domain)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:
        log.warning("crt.sh lookup failed for %s: %s", domain, exc)
        return
    seen = set()
    for entry in data:
        name = entry.get("name_value", "")
        for cand in name.splitlines():
            cand = cand.strip().lower().rstrip(".")
            if cand.endswith(domain) and "*" not in cand and cand not in seen:
                seen.add(cand)
                helpers.append_line(out_file, cand)
    log.info("crt.sh returned %s names for %s", len(seen), domain)


def run(domain: str, out_file, timeout: int = 300) -> int:
    """Enumerate subdomains, appending each to ``out_file`` live."""
    if not which(REQUIRED_TOOL):
        log.warning("%s not found; using crt.sh fallback", REQUIRED_TOOL)
        _crt_sh(domain, out_file, timeout)
    else:
        _subfinder(domain, out_file, timeout)
        # Merge any crt.sh names not caught by subfinder (best-effort).
        _crt_sh(domain, out_file, min(timeout, 60))

    subs = helpers.read_lines(out_file)
    console.print(f"[green][+] {len(subs)} subdomains collected for {domain}[/green]")
    return len(subs)
