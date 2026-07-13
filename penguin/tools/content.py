"""Content discovery wrappers (Block 2.3-2.4): crawling, JS collection,
directory/param fuzzing.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext


def katana(ctx: ToolContext, in_file: Path, out: Path) -> Optional[Path]:
    cmd = ["katana", "-list", str(in_file), "-js", "-jc", "-d", "5", "-aff", "-silent", "-o", str(out)]
    r = ctx.execute("katana", cmd, timeout=900)
    return out if out.exists() else None


def gau(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    cmd = ["gau", domain]
    r = ctx.execute("gau", cmd, timeout=600)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def waybackurls(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    cmd = ["waybackurls", domain]
    r = ctx.execute("waybackurls", cmd, timeout=600)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def subjs(ctx: ToolContext, in_file: Path, out: Path) -> Optional[Path]:
    cmd = ["subjs", "-i", str(in_file), "-o", str(out)]
    r = ctx.execute("subjs", cmd, timeout=600)
    return out if out.exists() else None


def hakrawler(ctx: ToolContext, in_file: Path, out: Path) -> Optional[Path]:
    if not in_file.exists():
        return None
    hosts = in_file.read_text(encoding="utf-8").splitlines()
    if not hosts:
        return None
    # hakrawler takes a single URL; run once over the first host
    cmd = ["hakrawler", "-subs", "-plain", hosts[0]]
    r = ctx.execute("hakrawler", cmd, timeout=600)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def ffuf_dirs(ctx: ToolContext, url: str, wordlist: Path, out: Path,
              exts: Optional[str] = None) -> Optional[Path]:
    cmd = ["ffuf", "-u", f"{url}/FUZZ", "-w", str(wordlist), "-t", "100",
           "-mc", "200,204,301,302,307,401,403,405", "-rate", "300", "-o", str(out)]
    if exts:
        cmd += ["-e", exts]
    r = ctx.execute("ffuf", cmd, timeout=1800)
    return out if out.exists() else None


def feroxbuster(ctx: ToolContext, url: str, wordlist: Path, out: Path) -> Optional[Path]:
    cmd = ["feroxbuster", "-u", url, "-w", str(wordlist), "-r", "-t", "30", "-o", str(out)]
    r = ctx.execute("feroxbuster", cmd, timeout=1800)
    return out if out.exists() else None


def arjun(ctx: ToolContext, url: str, out: Path, method: str = "GET") -> Optional[Path]:
    cmd = ["arjun", "-u", url, "-m", method, "--stable", "-o", str(out)]
    r = ctx.execute("arjun", cmd, timeout=600)
    return out if out.exists() else None


def paramspider(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    cmd = ["paramspider", "-d", domain, "-o", str(out)]
    r = ctx.execute("paramspider", cmd, timeout=600)
    return out if out.exists() else None


def x8(ctx: ToolContext, url: str, wordlist: Path, out: Path) -> Optional[Path]:
    cmd = ["x8", "-u", url, "-w", str(wordlist), "-o", str(out)]
    r = ctx.execute("x8", cmd, timeout=600)
    return out if out.exists() else None
