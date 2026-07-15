"""penguin - resilient command runner.

Wraps subprocess execution with exponential backoff retries, timeouts and
structured logging. This is the engineering answer to the guide's call for
"resilient wrappers with retries" (Resile / go-resiliency equivalents).
"""
from __future__ import annotations

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger("penguin.runner")

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _clean_err(text: str) -> str:
    """Strip ANSI color codes. Tools like nuclei/kr print a multi-line ASCII
    banner to stderr before the real error, so logging the *first* N chars
    (the old behavior) only ever showed banner noise -- callers should slice
    from the end instead, where the actual message lives."""
    return _ANSI_RE.sub("", text).strip()


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


def _which(binary: str, path: Optional[str] = None) -> Optional[str]:
    from shutil import which

    return which(binary, path=path)


# Substrings that mean "this exact command will never succeed, no matter how
# many times we retry it" -- CLI-flag drift, missing Python deps, or a
# protocol-level "no" (e.g. gRPC server refusing reflection). Retrying these
# just burns wall-clock time waiting through the same backoff for a result
# that was already final on attempt 1.
_PERMANENT_ERR_SUBSTRINGS = (
    "flag provided but not defined",
    "unknown shorthand flag",
    "unrecognized arguments",
    "executable file not found in $path",
    "modulenotfounderror",
    "traceback (most recent call last)",
    "does not support the reflection api",
    # a missing input file/wordlist never materializes on retry -- e.g.
    # puredns "open .../subdomains-large.txt: no such file or directory",
    # retried 3x through the full backoff for a result final on attempt 1.
    "no such file or directory",
    # Windows equivalents for missing file/binary errors
    "cannot find file",
    "system cannot find",
    "cannot find the file",
    "cannot find the path",
    "is not recognized as an internal or external command",
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
    log_attempt: Optional[tuple[int, int]] = None,
) -> RunResult:
    """Run ``cmd`` (list of args) with retries / exponential backoff.

    Missing binaries are skipped non-fatally (so partially installed
    environments still run). Set ``fatal=True`` to raise on failure.
    Commands whose failure is classified as permanent (bad flags, missing
    modules, etc.) stop retrying immediately instead of repeating the same
    guaranteed failure ``retries`` times.

    ``log_attempt``, if given, overrides the (attempt, total) pair used in
    "[retry x/y]" log lines. Callers like ``ToolContext.execute`` that wrap
    ``run`` in their own outer retry loop (one ``run(..., retries=1)`` per
    outer attempt, to re-pick a proxy each time) would otherwise always log
    "1/1" here regardless of which real outer-loop attempt is executing.
    """
    binary = cmd[0]
    env_path = env.get('PATH') if env else None
    resolved = _which(binary, path=env_path)
    if resolved is None:
        msg = f"[skip] binary not found: {binary}"
        logger.warning(msg)
        if fatal:
            raise CommandMissing(msg)
        return RunResult(cmd, -1, "", msg, 0, 0.0, False)

    attempts = 0
    last_err = ""
    start = time.time()
    total_attempts = max(1, retries)
    while attempts < total_attempts:
        attempts += 1
        log_a, log_n = log_attempt if log_attempt else (attempts, retries)
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
            last_err = _clean_err(proc.stderr) or f"exit={proc.returncode}"
            logger.warning("[retry %d/%d] %s -> %s", log_a, log_n, binary, last_err[-200:])
            if is_permanent(binary, proc.returncode, last_err):
                logger.warning("[fail-fast] %s -> permanent failure, not retrying", binary)
                break
        except subprocess.TimeoutExpired as exc:
            last_err = f"timeout after {timeout}s"
            logger.warning("[retry %d/%d] %s -> %s", log_a, log_n, binary, last_err)
        except FileNotFoundError as exc:
            last_err = str(exc)
            logger.warning("[skip] %s", last_err)
            break
            if attempts < total_attempts:
                time.sleep(min(backoff * (2 ** (attempts - 1)), 8))
    res = RunResult(cmd, -1, "", last_err, attempts, time.time() - start, False)
    if fatal:
        raise RuntimeError(f"command failed after {attempts} attempts: {' '.join(cmd)}")
    return res


def pipe(commands: list[list], *, timeout: Optional[float] = None, fatal: bool = False) -> RunResult:
    """Chain commands via shell pipes. Returns the final command's result.

    Intermediate stages' stderr is drained on background threads so a chatty
    upstream tool can't fill its OS pipe buffer and deadlock the chain; every
    stage's returncode is checked so a crashed early stage (feeding an empty
    stream to a downstream tool that then exits 0) is still reported as a
    failure, not silently swallowed.
    """
    procs: list[subprocess.Popen] = []
    # (proc, single-item list used as a mutable box for its drained stderr)
    stderr_boxes: list[tuple[subprocess.Popen, list]] = []
    threads: list[threading.Thread] = []
    prev = None
    try:
        for i, cmd in enumerate(commands):
            # Note: pipe() does not take a custom env param, so we use system PATH here
            if _which(cmd[0]) is None:
                logger.warning("[skip] binary not found in pipe: %s", cmd[0])
                if fatal:
                    raise CommandMissing(cmd[0])
                return RunResult(cmd, -1, "", "missing binary", 0, 0.0, False)
            inp = prev.stdout if prev else None
            proc = subprocess.Popen(cmd, stdin=inp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if prev is not None:
                # drop our copy so the upstream stage sees SIGPIPE/EPIPE if a
                # downstream stage exits early, instead of blocking forever
                prev.stdout.close()
            procs.append(proc)
            is_last = i == len(commands) - 1
            if not is_last:
                # nothing else will ever read this stage's stderr; drain it on
                # a thread so it can't fill the OS pipe buffer and deadlock
                box: list = []
                t = threading.Thread(target=lambda p=proc, b=box: b.append(p.stderr.read()))
                t.daemon = True
                t.start()
                stderr_boxes.append((proc, box))
                threads.append(t)
            prev = proc
        out = ""
        try:
            out, last_err = prev.communicate(timeout=timeout)
            # Bound the *total* remaining cleanup time by `timeout`, not
            # `timeout` per thread/proc -- reusing the full original timeout on
            # every join/wait below would let wall-clock balloon to roughly
            # (1 + num_threads + num_procs) * timeout instead of ~timeout.
            deadline = time.monotonic() + timeout if timeout is not None else None
            for t in threads:
                remaining = max(0, deadline - time.monotonic()) if deadline is not None else None
                t.join(timeout=remaining)
            for p in procs:
                if p.returncode is None:
                    remaining = max(0, deadline - time.monotonic()) if deadline is not None else None
                    p.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            # Single attribution-aware handler for BOTH places a timeout can
            # originate: prev.communicate() on the LAST stage (raised here if
            # an EARLIER stage is actually hung -- e.g. stage1 sleeps forever
            # and never closes stdout, so stage2 blocks forever reading it --
            # in which case communicate() times out before the cleanup loop
            # below ever runs), and the cleanup loop's own p.wait() timing
            # out. Either way, never assume *which* proc raised the
            # exception -- scan procs in pipeline order and attribute to the
            # first one still running. That's the earliest stage still
            # alive, which is the one actually blocking everything
            # downstream of it, not necessarily commands[-1].
            #
            # Popen.returncode is only ever populated by poll()/wait()/
            # communicate() -- it is NOT updated automatically when the OS
            # process exits on its own. If prev.communicate() on the LAST
            # stage is what raised TimeoutExpired, none of the earlier
            # stages have been polled yet, so they'd all still show
            # returncode is None even if they finished long ago. Do a cheap,
            # non-blocking poll() pass over every proc first so the scan
            # below reflects live process state instead of "never checked".
            for p in procs:
                p.poll()
            stuck = next((p for p in procs if p.returncode is None), None)
            if stuck is not None:
                stuck_idx = procs.index(stuck)
                stuck_cmd = commands[stuck_idx]
                stuck_err = next((box[0] for pp, box in stderr_boxes if pp is stuck and box), "")
            else:
                # Every proc already finished by the time we got here (race
                # between the timeout firing and the last stage exiting) --
                # nothing to attribute to a specific stage.
                stuck_cmd = commands[-1] if commands else []
                stuck_err = ""
            for p in procs:
                if p.returncode is None:
                    try:
                        p.kill()
                    except Exception:
                        pass
            return RunResult(stuck_cmd, -1, out, stuck_err or "timeout", len(procs), 0.0, False)
        failed = [p for p in procs if p.returncode != 0]
        if failed:
            bad = failed[0]
            bad_idx = procs.index(bad)
            bad_cmd = commands[bad_idx]
            if bad is prev:
                bad_err = last_err
            else:
                bad_err = next((box[0] for p, box in stderr_boxes if p is bad and box), "")
            return RunResult(bad_cmd, bad.returncode, out, bad_err or last_err, len(procs), 0.0, False)
        return RunResult(commands[-1], prev.returncode, out, last_err, 1, 0.0, True)
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
        for t in threads:
            t.join(timeout=1)
