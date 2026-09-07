#!/usr/bin/env python3
"""Jaz Recon - main CLI entry point.

Example:
    python recon.py --target scanme.nmap.org
    python recon.py --target example.com --modules subdomains,http,nuclei
    python recon.py --target 1.2.3.4 --scanner nmap --severity all
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from recon.orchestrator import ALL_MODULES, ReconPipeline
from recon.utils import helpers
from recon.utils.logger import banner, console, log, setup_logger


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="Jaz Recon",
        description="Automated reconnaissance framework for authorized security testing.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--target", "-t", required=True, help="Target domain or IP address.")
    p.add_argument("--output-dir", "-o", default=None,
                   help="Base output directory (default: ./results/<target>_<timestamp>).")
    p.add_argument("--modules", "-m", default=None,
                   help=f"Comma-separated stages to run. Options: {','.join(ALL_MODULES)}. "
                        f"Default: all.")
    p.add_argument("--scanner", choices=["nmap", "naabu"], default="naabu",
                   help="Port scanner to use (naabu=fast, nmap=accurate).")
    p.add_argument("--severity", default="medium,critical",
                   help="Nuclei severity filter, e.g. medium,critical,high or 'all'.")
    p.add_argument("--threads", type=int, default=10,
                   help="Max concurrency for parallel stages.")
    p.add_argument("--timeout", type=int, default=300,
                   help="Per-tool timeout in seconds.")
    p.add_argument("--force-ports", action="store_true",
                   help="Port-scan CDN/WAF IPs too (they are normally skipped).")
    p.add_argument("--no-install", action="store_true",
                   help="Do not auto-install missing tools.")
    p.add_argument("--version", action="version", version="Jaz Recon 1.0.0")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    target = helpers.normalize_target(args.target)

    # output directory
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base = Path(args.output_dir) if args.output_dir else (Path.cwd() / "results")
    output_dir = base / f"{target}_{stamp}"

    # logging (recon.log inside the output dir)
    setup_logger(output_dir / "recon.log")
    banner()
    log.info("target=%s output=%s", target, output_dir)

    # requested modules
    if args.modules:
        requested = [m.strip().lower() for m in args.modules.split(",") if m.strip()]
        unknown = [m for m in requested if m not in ALL_MODULES]
        if unknown:
            console.print(f"[bold red]Unknown module(s): {', '.join(unknown)}[/bold red]")
            console.print(f"Valid: {', '.join(ALL_MODULES)}")
            return 2
    else:
        requested = list(ALL_MODULES)

    # Tool availability check (best effort auto install unless disabled).
    from recon.utils.tools import ToolManager

    manager = ToolManager(auto_install=not args.no_install)
    needed = _needed_tools(requested)
    console.print("[bold]Checking required tools ...[/bold]")
    missing = []
    for tool in needed:
        rep = manager.check(tool)
        mark = "[green]ok[/green]" if rep.found else "[red]missing[/red]"
        console.print(f"  {tool:<12} {mark}" + (f"  {rep.message}" if not rep.found else ""))
        if not rep.found:
            missing.append(tool)
    if missing:
        console.print(f"[yellow]Warning: some tools are missing: {', '.join(missing)}. "
                      f"Related stages will be skipped.[/yellow]")

    # Build + run pipeline
    pipe = ReconPipeline(
        target=target,
        output_dir=output_dir,
        timeout=args.timeout,
        threads=args.threads,
        scanner=args.scanner,
        severity=args.severity,
        force_ports=args.force_ports,
        auto_install=not args.no_install,
    )
    pipe.make_dirs()
    pipe.run_stages(requested)

    console.print(f"\n[bold green]Done. Results saved under: {output_dir}[/bold green]")
    return 0


def _needed_tools(requested: list[str]) -> list[str]:
    """Map requested stages to the binaries they depend on."""
    tools = []
    mapping = {
        "subdomains": ["subfinder"],
        "dns": ["dnsx"],
        "cdn": ["cdncheck"],
        "ports": ["nmap", "naabu"],  # we prefer the chosen one but check both
        "http": ["httpx"],
        "crawl": ["katana"],
        "nuclei": ["nuclei"],
        "whatweb": ["whatweb"],
    }
    for stage in requested:
        tools.extend(mapping.get(stage, []))
    # drop exact duplicates, keep order
    seen = set()
    uniq = []
    for t in tools:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


if __name__ == "__main__":
    raise SystemExit(main())
