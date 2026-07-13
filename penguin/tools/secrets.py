"""Secret / JS analysis and git-secret scanners (Block 2.3, Block 4.2)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext


def linkfinder(ctx: ToolContext, js_file: Path, out: Path) -> Optional[Path]:
    cmd = ["python3", "linkfinder.py", "-i", str(js_file), "-o", "cli"]
    r = ctx.execute("linkfinder", cmd, timeout=120)
    if r.ok:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(r.stdout)
        return out
    return None


def secretfinder(ctx: ToolContext, js_file: Path, out: Path) -> Optional[Path]:
    cmd = ["python3", "SecretFinder.py", "-i", str(js_file), "-o", "cli"]
    r = ctx.execute("secretfinder", cmd, timeout=120)
    if r.ok:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(r.stdout)
        return out
    return None


def jsluice(ctx: ToolContext, js_glob: str, out: Path) -> Optional[Path]:
    cmd = ["jsluice", "urls"] + js_glob.split()
    r = ctx.execute("jsluice", cmd, timeout=180)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def trufflehog_git(ctx: ToolContext, target: str, out: Path) -> Optional[Path]:
    cmd = ["trufflehog", "git", target, "--only-verified", "--json"]
    r = ctx.execute("trufflehog", cmd, timeout=900)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def gitleaks(ctx: ToolContext, source: Path, out: Path) -> Optional[Path]:
    cmd = ["gitleaks", "detect", "--source", str(source), "--report-format", "json",
           "--report-path", str(out)]
    r = ctx.execute("gitleaks", cmd, timeout=900)
    return out if out.exists() else None


def github_subdomains(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    cmd = ["github-subdomains", "-d", domain, "-o", str(out)]
    r = ctx.execute("github-subdomains", cmd, timeout=300)
    return out if out.exists() else None


def gitdumper(ctx: ToolContext, url: str, out_dir: Path) -> Optional[Path]:
    cmd = ["python3", "gitdumper.py", url, str(out_dir)]
    r = ctx.execute("gitdumper", cmd, timeout=300)
    return out_dir if out_dir.exists() else None
