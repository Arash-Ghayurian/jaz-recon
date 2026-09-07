"""Streaming subprocess helpers.

All tool execution goes through :func:`run_stream` which consumes the tool's
stdout line-by-line (``subprocess.Popen``) and invokes a callback for every
line so results can be written/appended to files *in real time*.
"""
from __future__ import annotations

import shlex
import subprocess
from collections.abc import Callable
from typing import Any

from recon.utils.logger import log

LineHandler = Callable[[str], None]


def _cmd_name(cmd: str | list[str]) -> str:
    if isinstance(cmd, list):
        return (cmd[0] if cmd else "?").rsplit("/", 1)[-1]
    return cmd.split()[0].rsplit("/", 1)[-1]


def run_stream(
    cmd: str | list[str],
    *,
    timeout: int = 300,
    stdin_text: str | None = None,
    on_line: LineHandler | None = None,
    on_stderr: LineHandler | None = None,
    env: dict[str, str] | None = None,
) -> tuple[int, list[str]]:
    """Run a command, yielding every stdout line to ``on_line`` as it appears.

    Returns ``(returncode, lines_seen)``. Never raises on a non-zero exit.
    """
    if isinstance(cmd, (list, tuple)):
        argv: list[str] = list(cmd)
    else:
        argv = shlex.split(cmd)

    name = _cmd_name(argv)
    log.debug("exec: %s", shlex.join(argv))

    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if stdin_text is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            bufsize=1,
        )
    except FileNotFoundError:
        log.error("tool not found on PATH: %s", argv[0])
        return 127, []
    except Exception as exc:  # pragma: no cover - defensive
        log.error("failed to start %s: %s", name, exc)
        return -1, []

    collected: list[str] = []

    def _reader(stream, handler: LineHandler | None, target: list[str]) -> None:
        assert stream is not None
        for raw in stream:
            line = raw.rstrip("\n")
            if handler is not None and line:
                try:
                    handler(line)
                except Exception:
                    log.exception("on_line handler crashed for %s", name)
            target.append(line)
        stream.close()

    # Close stdin immediately if we are not feeding data.
    if stdin_text is not None:
        try:
            assert proc.stdin is not None
            proc.stdin.write(stdin_text)
            proc.stdin.flush()
            proc.stdin.close()
        except Exception as exc:
            log.warning("could not write stdin to %s: %s", name, exc)
    else:
        if proc.stdin is not None:
            try:
                proc.stdin.close()
            except Exception:
                pass

    from threading import Thread

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    tout = Thread(target=_reader, args=(proc.stdout, on_line, stdout_lines), daemon=True)
    terr = Thread(target=_reader, args=(proc.stderr, on_stderr, stderr_lines), daemon=True)
    tout.start()
    terr.start()

    try:
        code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        log.warning("%s timed out after %ss; killing", name, timeout)
        proc.kill()
        proc.wait()
        code = 124
    finally:
        tout.join(timeout=5)
        terr.join(timeout=5)

    collected = stdout_lines
    if code != 0 and code != 124:
        tail = "\n".join(stderr_lines[-3:])
        if tail:
            log.debug("%s exited %s; stderr tail:\n%s", name, code, tail)
    log.debug("%s finished rc=%s lines=%s", name, code, len(collected))
    return code, collected


def run_once(cmd: str | list[str], *, timeout: int = 60) -> str:
    """Run a command and return the trimmed combined output (no streaming)."""
    _, lines = run_stream(cmd, timeout=timeout)
    return "\n".join(lines)


def which(tool: str) -> str | None:
    import os
    import shutil

    # ProjectDiscovery binaries usually land in GOPATH/bin; prefer them over
    # any similarly-named tool earlier in PATH (e.g. a python 'httpx' script).
    gopath = os.environ.get("GOPATH")
    for base in [gopath, _go_env_gopath()]:
        if not base:
            continue
        cand = os.path.join(base, "bin", tool)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return shutil.which(tool)


def _go_env_gopath() -> str | None:
    import subprocess

    try:
        out = subprocess.run(["go", "env", "GOPATH"], capture_output=True, text=True)
        return out.stdout.strip() or None
    except Exception:
        return None
