"""Detect, check and auto-install the external tools used by the pipeline.

Go-based tools (subfinder, dnsx, httpx, naabu, katana, nuclei, cdncheck)
are installed via ``go install``. System tools (nmap) use the OS package
manager. Every install attempt is best-effort: failures are logged and the
pipeline degrades gracefully rather than crashing.
"""
from __future__ import annotations

import os
import platform
import subprocess
import sys
from dataclasses import dataclass, field

from recon.utils.logger import console, log

GO_TOOLS = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "cdncheck": "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
}


@dataclass
class InstallReport:
    tool: str
    found: bool
    installed: bool = False
    message: str = ""


class ToolManager:
    """Validates/installs binaries used across the pipeline."""

    def __init__(self, auto_install: bool = True) -> None:
        self.auto_install = auto_install
        self.gopath = self._detect_gopath()
        self.reports: dict[str, InstallReport] = {}

    # -- detection -----------------------------------------------------
    @staticmethod
    def _detect_gopath() -> str | None:
        gopath = os.environ.get("GOPATH")
        if gopath:
            return gopath
        try:
            out = subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True).stdout.strip()
            return out or None
        except Exception:
            return None

    @staticmethod
    def _tool_available(tool: str) -> bool:
        from shutil import which

        return which(tool) is not None

    # -- public API ----------------------------------------------------
    def check(self, tool: str) -> InstallReport:
        if self._tool_available(tool):
            report = InstallReport(tool=tool, found=True)
        elif self.auto_install:
            report = self.install(tool)
        else:
            report = InstallReport(
                tool=tool, found=False, installed=False,
                message=f"{tool} is missing and auto-install is disabled.",
            )
        self.reports[tool] = report
        return report

    def install(self, tool: str) -> InstallReport:
        if tool in GO_TOOLS:
            return self._install_go(tool)
        if tool in ("nmap", "whatweb"):
            return self._install_system(tool)
        return InstallReport(tool, found=False, message=f"no installer for {tool}")

    # -- installers ----------------------------------------------------
    def _install_go(self, tool: str) -> InstallReport:
        if not _go_present():
            log.error(
                "Go is not installed. Install it from https://go.dev/dl/ then "
                "re-run, or install %s manually.", tool,
            )
            return InstallReport(tool, found=False, message="go missing")
        module = GO_TOOLS[tool]
        log.info("Installing %s via go install ...", tool)
        console.print(f"[cyan]go install {module}[/cyan]")
        try:
            env = dict(os.environ)
            env["GOBIN"] = env.get("GOBIN", "")
            proc = subprocess.run(
                ["go", "install", module], capture_output=True, text=True,
                env=env, timeout=900,
            )
        except subprocess.TimeoutExpired:
            log.error("%s install timed out", tool)
            return InstallReport(tool, found=False, message="go install timed out")
        if proc.returncode != 0:
            log.error("%s install failed:\n%s", tool, proc.stderr.strip())
            return InstallReport(tool, found=False, message="go install failed")

        # The freshly installed binary may not be on PATH yet.
        if not self._tool_available(tool):
            hint = ""
            if self.gopath:
                bindir = os.path.join(self.gopath, "bin")
                hint = f" Add {bindir} to your PATH."
            log.warning("%s installed but not on PATH.%s", tool, hint)
        log.info("%s installed successfully.", tool)
        return InstallReport(tool, found=True, installed=True, message="go install ok")

    def _install_system(self, tool: str) -> InstallReport:
        system = platform.system().lower()
        pkg = None
        install_cmd = None
        if system == "linux":
            distro = _linux_distro()
            if distro in ("debian", "ubuntu"):
                pkg, install_cmd = tool, ["apt-get", "install", "-y", tool]
            elif distro in ("fedora", "centos", "rhel"):
                pkg, install_cmd = tool, ["dnf", "install", "-y", tool]
            elif distro in ("arch", "manjaro"):
                pkg, install_cmd = tool, ["pacman", "-Sy", "--noconfirm", tool]
            else:
                pkg, install_cmd = tool, ["apt-get", "install", "-y", tool]
        elif system == "darwin":
            pkg, install_cmd = tool, ["brew", "install", tool]
        else:
            log.error("Unsupported OS for automatic %s install: %s", tool, system)
            return InstallReport(tool, found=False, message="unsupported OS")

        log.info("Installing %s via %s ...", pkg, install_cmd[0])
        console.print(f"[cyan]{' '.join(install_cmd)}[/cyan]")
        try:
            proc = subprocess.run(install_cmd, capture_output=True, text=True, timeout=1200)
        except FileNotFoundError:
            log.error("Package manager %s not found; install %s manually.", install_cmd[0], tool)
            return InstallReport(tool, found=False, message="no package manager")
        except subprocess.TimeoutExpired:
            log.error("%s install timed out", tool)
            return InstallReport(tool, found=False, message="install timed out")

        if proc.returncode != 0 or not self._tool_available(tool):
            if os.geteuid() != 0:
                log.warning(
                    "Install failed, possibly missing root privileges. Try: sudo %s",
                    " ".join(install_cmd),
                )
            return InstallReport(tool, found=False, message=proc.stderr.strip()[:300])
        log.info("%s installed successfully.", tool)
        return InstallReport(tool, found=True, installed=True, message="ok")


def _go_present() -> bool:
    from shutil import which

    return which("go") is not None


def _linux_distro() -> str:
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            data = fh.read()
        for line in data.splitlines():
            if line.startswith("ID="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "unknown"
