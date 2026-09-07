"""Pipeline orchestrator.

Runs the requested recon stages in dependency order, creating the per-run
output folder and streaming results into files as each module discovers them.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from recon.modules import (
    cdncheck_module,
    dnsx_module,
    httpx_module,
    katana_module,
    nuclei_module,
    ports,
    subdomains,
    whatweb_module,
)
from recon.utils import helpers
from recon.utils.logger import console, log

ALL_MODULES = [
    "subdomains",
    "dns",
    "cdn",
    "ports",
    "http",
    "crawl",
    "nuclei",
    "whatweb",
]

# ordered list of stage names
STAGES = ["subdomains", "dns", "cdn", "ports", "http", "crawl", "nuclei", "whatweb"]

# human friendly names
STAGE_TITLES = {
    "subdomains": "Subdomain Enumeration",
    "dns": "DNS Resolution",
    "cdn": "CDN / WAF Detection",
    "ports": "Port Scanning",
    "http": "HTTP Probing",
    "crawl": "Crawling",
    "nuclei": "Vulnerability Scanning",
    "whatweb": "WhatWeb Fingerprinting",
}


class ReconPipeline:
    def __init__(
        self,
        target: str,
        output_dir: Path,
        timeout: int = 300,
        threads: int = 10,
        scanner: str = "naabu",
        severity: str = "medium,critical",
        force_ports: bool = False,
        auto_install: bool = True,
    ) -> None:
        self.target = target
        self.output_dir = output_dir
        self.timeout = timeout
        self.threads = threads
        self.scanner = scanner
        self.severity = severity
        self.force_ports = force_ports
        self.auto_install = auto_install

        self.port_dir = output_dir / "ports"
        self.urls_dir = output_dir / "urls"

        # data holders shared between stages
        self.host_map: dict = {}          # host -> [ips]
        self.cdn_map: dict = {}           # host -> {is_cdn, cdn_name}
        self.port_map: dict = {}          # ip -> [ports]
        self.http_results: list[dict] = []
        self.all_urls: dict = {}
        self.nuclei_results: list[dict] = []

        self.summary: dict = {}
        self._started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ------------------------------------------------------------------
    def make_dirs(self) -> None:
        for d in (self.output_dir, self.port_dir, self.urls_dir):
            d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    def stage_subdomains(self) -> None:
        out_file = self.output_dir / "subdomains.txt"
        console.rule(f"[bold magenta]1. {STAGE_TITLES['subdomains']}[/bold magenta]")
        subdomains.run(self.target, out_file, timeout=self.timeout)
        # If nothing was found, fall back to the root target so downstream
        # stages (dns/ports/http/nuclei) still have a host to work on.
        if not helpers.read_lines(out_file):
            log.warning("no subdomains found; using root target %s", self.target)
            helpers.append_line(out_file, self.target)

    def stage_dns(self) -> None:
        in_file = self.output_dir / "subdomains.txt"
        if not in_file.exists():
            log.warning("no subdomains.txt; skipping DNS resolution")
            return
        out_file = self.output_dir / dnsx_module.OUT_JSON
        console.rule(f"[bold magenta]2. {STAGE_TITLES['dns']}[/bold magenta]")
        self.host_map = dnsx_module.run(in_file, out_file, timeout=self.timeout)

    def stage_cdn(self) -> None:
        out_file = self.output_dir / cdncheck_module.OUT_JSON
        console.rule(f"[bold magenta]3. {STAGE_TITLES['cdn']}[/bold magenta]")
        if not self.host_map:
            log.warning("no resolved hosts; skipping CDN detection")
            return
        self.cdn_map = cdncheck_module.run(None, self.host_map, out_file, timeout=self.timeout)

    def stage_ports(self) -> None:
        all_ports_json = self.output_dir / "all_ports.json"
        console.rule(f"[bold magenta]4. {STAGE_TITLES['ports']}[/bold magenta]")
        cdn_status_file = self.output_dir / cdncheck_module.OUT_JSON
        # If DNS wasn't run, try to load the mapping from a previous file.
        if not self.host_map:
            f = self.output_dir / dnsx_module.OUT_JSON
            if f.exists():
                try:
                    self.host_map = json.loads(f.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    self.host_map = {}
        self.port_map = ports.run(
            ips=[],
            host_map=self.host_map,
            cdn_status_file=cdn_status_file,
            port_dir=self.port_dir,
            all_ports_json=all_ports_json,
            scanner=self.scanner,
            force=self.force_ports,
            threads=self.threads,
            timeout=max(self.timeout, 600),
        )

    def stage_http(self) -> None:
        in_file = self.output_dir / "subdomains.txt"
        out_file = self.output_dir / httpx_module.OUT_JSON
        console.rule(f"[bold magenta]5. {STAGE_TITLES['http']}[/bold magenta]")
        cdn_hosts = {h for h, v in self.cdn_map.items() if v.get("is_cdn")}
        self.http_results = httpx_module.run(in_file, out_file, cdn_hosts, timeout=self.timeout)

    def stage_crawl(self) -> None:
        in_file = self.output_dir / "subdomains.txt"
        all_urls_json = self.output_dir / "all_urls.json"
        console.rule(f"[bold magenta]6. {STAGE_TITLES['crawl']}[/bold magenta]")
        # crawl live hosts from http probing
        live = [r.get("input") or r.get("url") for r in self.http_results]
        live = [h for h in live if h]
        self.all_urls = katana_module.run(
            in_file, self.urls_dir, all_urls_json, live_hosts=live, timeout=self.timeout
        )

    def stage_nuclei(self) -> None:
        in_file = self.output_dir / "subdomains.txt"
        out_file = self.output_dir / nuclei_module.OUT_JSON
        console.rule(f"[bold magenta]7. {STAGE_TITLES['nuclei']}[/bold magenta]")
        live = [r.get("url") or r.get("input") for r in self.http_results]
        live = [h for h in live if h]
        self.nuclei_results = nuclei_module.run(
            in_file, out_file, live_hosts=live, severity=self.severity, timeout=max(self.timeout, 600)
        )

    def stage_whatweb(self) -> None:
        in_file = self.output_dir / "subdomains.txt"
        out_file = self.output_dir / whatweb_module.OUT_JSON
        console.rule(f"[bold magenta]8. {STAGE_TITLES['whatweb']}[/bold magenta]")
        if not in_file.exists():
            log.warning("no subdomains.txt; skipping WhatWeb fingerprinting")
            return
        whatweb_module.run(
            in_file, out_file, timeout=self.timeout, threads=self.threads
        )

    # ------------------------------------------------------------------
    def run_stages(self, requested: list[str]) -> None:
        """Execute stages in dependency order, skipping unrequested ones."""
        for stage in STAGES:
            if stage not in requested:
                continue
            try:
                getattr(self, f"stage_{stage}")()
            except Exception:
                log.exception("stage %s crashed (continuing)", stage)
        self.finalize()

    # ------------------------------------------------------------------
    def finalize(self) -> None:
        self._build_summary()
        self._write_summary()
        self._print_summary()

    def _build_summary(self) -> None:
        sub_count = len(helpers.read_lines(self.output_dir / "subdomains.txt")) if (self.output_dir / "subdomains.txt").exists() else 0
        self.summary = {
            "target": self.target,
            "started": self._started,
            "finished": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "stage_counts": {},
            "total_subdomains": sub_count,
            "resolved_hosts": len(self.host_map),
            "cdn_hosts": sum(1 for v in self.cdn_map.values() if v.get("is_cdn")),
            "open_ports": sum(len(v) for v in self.port_map.values()),
            "http_live": len(self.http_results),
            "total_urls_found": sum(len(v) for v in self.all_urls.values()),
            "nuclei_findings": len(self.nuclei_results),
            "nuclei_by_severity": {},
            "output_dir": str(self.output_dir),
        }
        by_sev: dict[str, int] = {}
        for f in self.nuclei_results:
            s = f.get("severity", "unknown").lower()
            by_sev[s] = by_sev.get(s, 0) + 1
        self.summary["nuclei_by_severity"] = by_sev

    def _write_summary(self) -> None:
        p = self.output_dir / "summary.json"
        helpers.atomic_json_write(p, self.summary)

    def _print_summary(self) -> None:
        console.rule("[bold green]Summary[/bold green]")
        s = self.summary
        from rich.table import Table

        table = Table(title=f"Recon summary for {self.target}", show_header=False)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        def row(label, val):
            table.add_row(label, str(val))

        row("Subdomains found", s["total_subdomains"])
        row("Hosts resolved", s["resolved_hosts"])
        row("CDN / WAF protected", s["cdn_hosts"])
        row("Open ports (non-CDN)", s["open_ports"])
        row("Live HTTP hosts", s["http_live"])
        row("Discovered URLs", s["total_urls_found"])
        row("Nuclei findings", s["nuclei_findings"])
        if s["nuclei_by_severity"]:
            for sev, cnt in sorted(s["nuclei_by_severity"].items()):
                color = {"critical": "red", "high": "red", "medium": "yellow",
                         "low": "blue", "info": "dim"}.get(sev, "white")
                row(f"  - {sev}", f"[{color}]{cnt}[/{color}]")
        row("Results in", s["output_dir"])
        console.print(table)
