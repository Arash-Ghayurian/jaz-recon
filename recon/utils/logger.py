"""Logging and terminal output helpers.

Provides a single colored terminal printer and a file logger that writes
into the per-run ``recon.log``.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.markup import escape

console = Console()

_LEVEL_COLORS = {
    "DEBUG": "dim",
    "INFO": "cyan",
    "WARNING": "yellow",
    "ERROR": "red",
    "CRITICAL": "bold red",
}


class ConsoleHandler(logging.Handler):
    """Compact, colored console handler rendered through rich."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            ts = time.strftime("%H:%M:%S", time.localtime(record.created))
            color = _LEVEL_COLORS.get(record.levelname, "white")
            level = f"{record.levelname:<8}"
            msg = escape(record.getMessage())
            console.print(f"[dim]{ts}[/dim] | [{color}]{level}[/{color}] | {msg}")
        except Exception:  # pragma: no cover - defensive
            self.handleError(record)


# Root logger named after the package.
log = logging.getLogger("recon")
log.setLevel(logging.DEBUG)
log.propagate = False


def setup_logger(log_file: Path | None) -> None:
    """Attach a rich stream handler (stderr) and an optional file handler."""
    # Avoid duplicating handlers if setup is called more than once.
    for h in list(log.handlers):
        log.removeHandler(h)

    stream = ConsoleHandler()
    stream.setLevel(logging.INFO)
    log.addHandler(stream)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s")
        )
        log.addHandler(fh)


def banner() -> None:
    """Print a colored ASCII banner + legal disclaimer."""
    from rich.panel import Panel

    art = r"""
     ██╗ █████╗ ███████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
     ██║██╔══██╗╚══███╔╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
     ██║███████║  ███╔╝     ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██   ██║██╔══██║ ███╔╝      ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚█████╔╝██║  ██║███████╗    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                       """
    console.print(Panel.fit(art, style="bold cyan", border_style="cyan"))
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    console.print(f"Started at {ts}\n", style="dim")
