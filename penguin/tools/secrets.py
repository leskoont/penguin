"""Secret / JS analysis and git-secret scanners (Block 2.3, Block 4.2)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext, ok_path


def linkfinder(ctx: ToolContext, js_file: Path, out: Path) -> Optional[Path]:
    # install.sh installs linkfinder as a standalone wrapper binary on PATH
    # (a shim that execs its own venv python against the script's absolute
    # path) -- invoking "python3 linkfinder.py" as a relative filename only
    # ever worked if the CWD happened to contain a checkout of the repo,
    # which it doesn't, hence "No such file or directory" every run.
    cmd = ["linkfinder", "-i", str(js_file), "-o", "cli"]
    r = ctx.execute("linkfinder", cmd, timeout=120)
    if r.ok:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(r.stdout)
        return out
    return None


def secretfinder(ctx: ToolContext, js_file: Path, out: Path) -> Optional[Path]:
    cmd = ["SecretFinder", "-i", str(js_file), "-o", "cli"]
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
