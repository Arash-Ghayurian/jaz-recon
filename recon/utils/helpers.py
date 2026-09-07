"""Small helpers shared across the recon pipeline."""
from __future__ import annotations

import json
import os
import socket
import threading
from pathlib import Path

import validators

_reentrant = threading.Lock()


def atomic_json_write(path: Path, data) -> None:
    """Write JSON atomically to avoid a reader seeing a half-written file."""
    with _reentrant:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False, sort_keys=True)
        os.replace(tmp, path)


def append_line(path: Path, line: str) -> None:
    """Append a single line to a text file immediately (streaming output)."""
    with _reentrant:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line.rstrip("\n") + "\n")


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def is_ip(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        return False


def normalize_target(raw: str) -> str:
    """Return a cleaned target string or raise ValueError."""
    t = raw.strip().strip("/")
    if not t:
        raise ValueError("empty target")
    if "://" in t:
        t = t.split("://", 1)[1]
    # drop path, keep host[:port]
    t = t.split("/", 1)[0]
    if ":" in t and not is_ip(t.split(":")[0]) and t.count(":") == 1:
        t = t.split(":", 1)[0]
    if not validators.domain(t) and not validators.ip_address.ipv4(t) and not validators.ip_address.ipv6(t):
        # fall back: allow hostnames the validators reject
        if not is_ip(t) and (" " in t or t == ""):
            raise ValueError(f"invalid target: {raw!r}")
    return t.rstrip(".")


def unique(seq):
    seen = set()
    out = []
    for item in seq:
        item = str(item).strip().rstrip(".")
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out
