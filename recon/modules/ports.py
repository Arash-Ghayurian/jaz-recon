"""Module 4 - Port scanning with nmap (accurate) or naabu (fast).

By default only real / non-CDN IPs are scanned (CDN IPs are synthetic edge
nodes). Use ``force=True`` to scan everything.
"""
from __future__ import annotations

import json
import re

from recon.utils import helpers
from recon.utils.logger import console, log
from recon.utils.runner import run_stream, which

SCAN_NMAP = "nmap"
SCAN_NAABU = "naabu"

PORT_RE = re.compile(r"^\d+/(tcp|udp)")


def _unique_ips(cdn_status_file, host_map, force: bool) -> list[str]:
    """Collect the distinct IPs that should be port-scanned."""
    cdn: dict = {}
    if cdn_status_file and cdn_status_file.exists():
        try:
            cdn = json.loads(cdn_status_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            cdn = {}

    pool: set[str] = set()
    for host, ips in host_map.items():
        for ip in ips:
            behind = cdn.get(host, {}).get("is_cdn", False)
            if force or not behind:
                pool.add(ip)
            elif force is False and behind:
                log.debug("skipping CDN ip %s for %s", ip, host)
    return sorted(pool)


def _nm_ports_txt(port_dir, ip: str):
    return port_dir / f"ports_{ip}.txt"


def _nmap_scan(ip: str, port_dir, timeout: int, extra: str = "") -> list[int]:
    ports: set[int] = set()
    out_file = _nm_ports_txt(port_dir, ip)

    def on_line(line: str) -> None:
        m = PORT_RE.match(line.strip())
        if m:
            port = int(line.split("/")[0])
            if "open" in line or "open|filtered" in line:
                ports.add(port)
                helpers.append_line(out_file, f"{port}/tcp open")
        if "open" in line and m:
            pass

    args = [which(SCAN_NMAP), "-sT", "-Pn", "--open", "-T4"]
    if extra:
        args += extra.split()
    args += ["-oG", "-", ip]
    code, _ = run_stream(args, timeout=timeout, on_line=on_line)
    if code not in (0, 1, 124):
        log.warning("nmap exited %s on %s", code, ip)
    return sorted(ports)


def _naabu_scan(ip: str, port_dir, timeout: int) -> list[int]:
    ports: set[int] = set()
    out_file = _nm_ports_txt(port_dir, ip)

    def on_line(line: str) -> None:
        # naabu format: "1.2.3.4:80" or "[1.2.3.4]:80"
        text = line.strip()
        if ":" in text:
            maybe = text.rsplit(":", 1)[1].split("]")[0]
            if maybe.isdigit():
                p = int(maybe)
                ports.add(p)
                helpers.append_line(out_file, f"{p}/tcp open")

    cmd = [which(SCAN_NAABU), "-host", ip, "-silent", "-top-ports", "1000"]
    code, _ = run_stream(cmd, timeout=timeout, on_line=on_line)
    if code not in (0, 124):
        log.warning("naabu exited %s on %s", code, ip)
    return sorted(ports)


def run(
    *,
    ips: list[str],
    host_map: dict,
    cdn_status_file,
    port_dir,
    all_ports_json,
    scanner: str = SCAN_NAABU,
    force: bool = False,
    threads: int = 8,
    timeout: int = 600,
) -> dict:
    """Scan each non-CDN IP; returns {ip: [ports]}."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    targets = _unique_ips(cdn_status_file, host_map, force) if not ips else list(set(ips))
    if not targets:
        log.warning("No real (non-CDN) IPs to scan. Use --force-ports to scan all.")
        return {}

    console.print(f"[cyan][*] Port scanning {len(targets)} IP(s) with {scanner}[/cyan]")
    results: dict = {}
    all_file_lock = _SingleWriter(all_ports_json)

    def worker(ip: str):
        if scanner == SCAN_NMAP and which(SCAN_NMAP):
            ports = _nmap_scan(ip, port_dir, timeout)
        elif scanner == SCAN_NAABU and which(SCAN_NAABU):
            ports = _naabu_scan(ip, port_dir, timeout)
        elif which(SCAN_NMAP):
            ports = _nmap_scan(ip, port_dir, timeout)
        elif which(SCAN_NAABU):
            ports = _naabu_scan(ip, port_dir, timeout)
        else:
            log.error("Neither nmap nor naabu is available for port scan.")
            return ip, []
        all_file_lock.update(ip, ports)
        console.print(f"[green][+] {ip}: {len(ports)} open ports -> {ports}[/green]")
        return ip, ports

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(worker, ip): ip for ip in targets}
        for fut in as_completed(futs):
            ip, ports = fut.result()
            results[ip] = ports

    all_file_lock.flush()
    total_open = sum(len(v) for v in results.values())
    console.print(f"[green][+] Port scan done: {total_open} open ports across {len(results)} IPs[/green]")
    return results


class _SingleWriter:
    """Thread-safe streaming accumulator that appends to all_ports.json."""

    def __init__(self, json_path) -> None:
        self.json_path = json_path
        self.lock = _import_lock()
        self.data: dict = {}
        if json_path.exists():
            try:
                self.data = json.loads(json_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                self.data = {}

    def update(self, ip: str, ports: list[int]) -> None:
        with self.lock:
            cur = set(self.data.get(ip, []))
            cur.update(ports)
            self.data[ip] = sorted(cur)
            helpers.atomic_json_write(self.json_path, self.data)

    def flush(self) -> None:
        pass


def _import_lock():
    import threading

    return threading.Lock()
