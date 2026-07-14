"""penguin - resilient command runner.

Wraps subprocess execution with exponential backoff retries, timeouts and
structured logging. This is the engineering answer to the guide's call for
"resilient wrappers with retries" (Resile / go-resiliency equivalents).
"""
from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger("penguin.runner")


@dataclass
class RunResult:
    cmd: list
    returncode: int
    stdout: str
    stderr: str
    attempts: int
    duration: float
    ok: bool


class CommandMissing(Exception):
    pass


def _which(binary: str) -> Optional[str]:
    from shutil import which

    return which(binary)


# Substrings that mean "this exact command will never succeed, no matter how
# many times we retry it" -- CLI-flag drift, missing Python deps, or a
# protocol-level "no" (e.g. gRPC server refusing reflection). Retrying these
# just burns wall-clock time waiting through the same backoff for a result
# that was already final on attempt 1.
_PERMANENT_ERR_SUBSTRINGS = (
    "flag provided but not defined",
    "unknown shorthand flag",
    "unrecognized arguments",
    "executable file not found in $PATH",
    "modulenotfounderror",
    "traceback (most recent call last)",
    "does not support the reflection api",
)


def is_permanent(binary: str, returncode: int, err: str) -> bool:
    if binary == "curl" and returncode == 6:
        # CURLE_COULDNT_RESOLVE_HOST -- DNS doesn't resolve, never will on retry.
        return True
    low = err.lower()
    return any(s in low for s in _PERMANENT_ERR_SUBSTRINGS)


def run(
    cmd: list,
    *,
    retries: int = 3,
    backoff: float = 2.0,
    timeout: Optional[float] = None,
    cwd: Optional[str | Path] = None,
    env: Optional[dict] = None,
    check_binary: bool = True,
    fatal: bool = False,
    log_stdout: bool = False,
    input: Optional[str] = None,
) -> RunResult:
    """Run ``cmd`` (list of args) with retries / exponential backoff.

    Missing binaries are skipped non-fatally (so partially installed
    environments still run). Set ``fatal=True`` to raise on failure.
    Commands whose failure is classified as permanent (bad flags, missing
    modules, etc.) stop retrying immediately instead of repeating the same
    guaranteed failure ``retries`` times.
    """
    binary = cmd[0]
    resolved = _which(binary)
    if resolved is None:
        msg = f"[skip] binary not found: {binary}"
        logger.warning(msg)
        if fatal:
            raise CommandMissing(msg)
        return RunResult(cmd, -1, "", msg, 0, 0.0, False)

    attempts = 0
    last_err = ""
    start = time.time()
    while attempts < max(1, retries):
        attempts += 1
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(cwd) if cwd else None,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input,
                check=False,
            )
            if proc.returncode == 0:
                if log_stdout:
                    logger.debug("stdout[%s]: %s", binary, proc.stdout[:500])
                return RunResult(cmd, proc.returncode, proc.stdout, proc.stderr, attempts, time.time() - start, True)
            last_err = proc.stderr.strip() or f"exit={proc.returncode}"
            logger.warning("[retry %d/%d] %s -> %s", attempts, retries, binary, last_err[:200])
            if is_permanent(binary, proc.returncode, last_err):
                logger.warning("[fail-fast] %s -> permanent failure, not retrying", binary)
                break
        except subprocess.TimeoutExpired as exc:
            last_err = f"timeout after {timeout}s"
            logger.warning("[retry %d/%d] %s -> %s", attempts, retries, binary, last_err)
        except FileNotFoundError as exc:
            last_err = str(exc)
            logger.warning("[skip] %s", last_err)
            break
        if attempts < retries:
            time.sleep(backoff * (2 ** (attempts - 1)))
    res = RunResult(cmd, -1, "", last_err, attempts, time.time() - start, False)
    if fatal:
        raise RuntimeError(f"command failed after {attempts} attempts: {' '.join(cmd)}")
    return res


def pipe(commands: list[list], *, timeout: Optional[float] = None, fatal: bool = False) -> RunResult:
    """Chain commands via shell pipes. Returns the final command's result."""
    procs = []
    prev = None
    try:
        for i, cmd in enumerate(commands):
            if _which(cmd[0]) is None:
                logger.warning("[skip] binary not found in pipe: %s", cmd[0])
                if fatal:
                    raise CommandMissing(cmd[0])
                return RunResult(cmd, -1, "", "missing binary", 0, 0.0, False)
            inp = prev.stdout if prev else None
            prev = subprocess.Popen(cmd, stdin=inp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            procs.append(prev)
        out, err = prev.communicate(timeout=timeout)
        rc = prev.returncode
        return RunResult(commands[-1], rc, out, err, 1, 0.0, rc == 0)
    except Exception as exc:  # noqa
        if fatal:
            raise
        return RunResult(commands[-1] if commands else [], -1, "", str(exc), 1, 0.0, False)
    finally:
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass
