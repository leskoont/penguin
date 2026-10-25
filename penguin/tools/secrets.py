"""Secret / JS analysis and git-secret scanners (Block 2.3, Block 4.2)."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from ._base import ToolContext, ok_path

logger = logging.getLogger("penguin.tools.secrets")


def linkfinder(ctx: ToolContext, js_file: Path) -> Optional[str]:
    # install.sh installs linkfinder as a standalone wrapper binary on PATH
    # (a shim that execs its own venv python against the script's absolute
    # path) -- invoking "python3 linkfinder.py" as a relative filename only
    # ever worked if the CWD happened to contain a checkout of the repo,
    # which it doesn't, hence "No such file or directory" every run.
    # Returns found text instead of writing it: this is called in a loop over
    # every discovered JS file, fanning into one shared endpoints file -- the
    # caller owns that accumulation (and the single write), not this wrapper.
    cmd = ["linkfinder", "-i", str(js_file), "-o", "cli"]
    r = ctx.execute("linkfinder", cmd, timeout=120)
    return r.stdout if r.ok and r.stdout else None


def secretfinder(ctx: ToolContext, js_file: Path) -> Optional[str]:
    cmd = ["SecretFinder", "-i", str(js_file), "-o", "cli"]
    r = ctx.execute("secretfinder", cmd, timeout=120)
    return r.stdout if r.ok and r.stdout else None


def jsluice(ctx: ToolContext, js_files: "list[Path]", out: Path, *, chunk: int = 100) -> Optional[Path]:
    """Run jsluice over downloaded JS files, writing combined URL output.

    Takes a list of paths (the old signature took a space-joined string fed to
    glob(), which could never match and made jsluice a silent no-op). Files are
    passed in chunks so the argv stays well under the Windows command-line
    length limit on JS-heavy targets; stdout chunks are concatenated."""
    files = [str(f) for f in (js_files or []) if Path(f).exists()]
    if not files:
        return None
    parts: list[str] = []
    for i in range(0, len(files), max(1, chunk)):
        cmd = ["jsluice", "urls"] + files[i:i + max(1, chunk)]
        r = ctx.execute("jsluice", cmd, timeout=180)
        if r.ok and r.stdout:
            parts.append(r.stdout)
    if not parts:
        return None
    out.write_text("".join(parts), encoding="utf-8")
    return out


def trufflehog_git(ctx: ToolContext, target: str, out: Path) -> Optional[Path]:
    cmd = ["trufflehog", "git", target, "--only-verified", "--json"]
    r = ctx.execute("trufflehog", cmd, timeout=900)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def gitleaks_hits(report: Path) -> int:
    """Number of leaks in a gitleaks JSON report (0 for a clean/empty/missing
    report). gitleaks always writes the report file -- an empty ``[]`` when it
    finds nothing -- so the file merely *existing* must never be read as a hit."""
    if not report or not report.exists():
        return 0
    try:
        data = json.loads(report.read_text(encoding="utf-8", errors="ignore") or "[]")
    except (ValueError, TypeError):
        return 0
    return len(data) if isinstance(data, list) else 0


def trufflehog_hits(report: Path) -> int:
    """Number of verified secrets in a trufflehog ``--json`` report (JSONL, one
    finding per line). Empty/clean output is an empty file, which is 0 hits."""
    if not report or not report.exists():
        return 0
    n = 0
    for line in report.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            continue
        # trufflehog emits one JSON object per detected secret; ignore any
        # non-object bookkeeping lines some versions interleave.
        if isinstance(row, dict) and row:
            n += 1
    return n


def gitleaks(ctx: ToolContext, source: Path, out: Path) -> Optional[Path]:
    # --exit-code 0: gitleaks defaults to exit 1 when it *finds* leaks (its
    # signal for "leaks present", not "scan failed"), which would make an
    # r.ok check punish the tool for succeeding at its job. Pin it to 0 so
    # the exit code reflects whether the scan actually ran.
    cmd = ["gitleaks", "detect", "--source", str(source), "--report-format", "json",
           "--report-path", str(out), "--exit-code", "0"]
    r = ctx.execute("gitleaks", cmd, timeout=900)
    return ok_path(r, out)


def github_subdomains(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    # github-subdomains requires a GitHub token (-t or GITHUB_TOKEN env) --
    # without one it just dumps its usage banner and exits nonzero every
    # time. -o itself is a real flag; the token was the actual missing piece.
    if not ctx.cfg.paid_enabled("github"):
        return None
    cmd = ["github-subdomains", "-d", domain, "-o", str(out)]
    r = ctx.execute("github-subdomains", cmd, timeout=300,
                     extra_env={"GITHUB_TOKEN": ctx.cfg.paid_key("github")})
    return ok_path(r, out)


def gitdumper(ctx: ToolContext, url: str, out_dir: Path) -> Optional[Path]:
    # gitdumper is GitTools' gitdumper.sh (bash, not Python), installed as a
    # standalone wrapper binary on PATH -- not a script to invoke via python3.
    cmd = ["gitdumper", url, str(out_dir)]
    r = ctx.execute("gitdumper", cmd, timeout=300)
    return ok_path(r, out_dir)
