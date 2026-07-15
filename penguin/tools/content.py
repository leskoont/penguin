"""Content discovery wrappers (Block 2.3-2.4): crawling, JS collection,
directory/param fuzzing.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext, ok_path


def katana(ctx: ToolContext, in_file: Path, out: Path) -> Optional[Path]:
    # -js is not a real katana flag (only -jc/-js-crawl exists); passing it
    # trips cobra's unknown-flag parsing and katana exits 2 before doing anything.
    cmd = ["katana", "-list", str(in_file), "-jc", "-d", "5", "-aff", "-silent", "-o", str(out)]
    r = ctx.execute("katana", cmd, timeout=900)
    return ok_path(r, out)


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
    # subjs has no -o flag -- it only writes to stdout.
    cmd = ["subjs", "-i", str(in_file)]
    r = ctx.execute("subjs", cmd, timeout=600)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def hakrawler(ctx: ToolContext, in_file: Path, out: Path) -> Optional[Path]:
    if not in_file.exists():
        return None
    hosts = in_file.read_text(encoding="utf-8").splitlines()
    if not hosts:
        return None
    # hakrawler dropped -plain and takes URLs via stdin only, not a
    # positional/CLI arg -- feed entire host list, not just the first one.
    cmd = ["hakrawler", "-subs"]
    r = ctx.execute("hakrawler", cmd, timeout=600, input="\n".join(hosts) + "\n")
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
    return ok_path(r, out)


def feroxbuster(ctx: ToolContext, url: str, wordlist: Path, out: Path) -> Optional[Path]:
    cmd = ["feroxbuster", "-u", url, "-w", str(wordlist), "-r", "-t", "30", "-o", str(out)]
    r = ctx.execute("feroxbuster", cmd, timeout=1800)
    return ok_path(r, out)


def arjun(ctx: ToolContext, url: str, out: Path, method: str = "GET") -> Optional[Path]:
    # --stable forces threads=1 plus a random 6-12s delay between every
    # request -- against a large param wordlist that alone burns the whole
    # 600s timeout x3 retries. Drop it and use arjun's real threads/timeout
    # flags (-t default 5, -T per-request timeout default 15s) instead.
    cmd = ["arjun", "-u", url, "-m", method, "-t", "10", "-T", "10", "-o", str(out)]
    r = ctx.execute("arjun", cmd, timeout=300)
    return ok_path(r, out)


def paramspider(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    # paramspider has no -o/--output flag -- it always writes to a hardcoded
    # ./results/<domain>.txt relative to the CWD it's invoked from. Run it,
    # then relocate that file to the caller-requested `out` path.
    import shutil

    cmd = ["paramspider", "-d", domain]
    r = ctx.execute("paramspider", cmd, timeout=600)
    produced = Path("results") / f"{domain}.txt"
    if r.ok and produced.exists():
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(produced), str(out))
    return ok_path(r, out)


def x8(ctx: ToolContext, url: str, wordlist: Path, out: Path) -> Optional[Path]:
    cmd = ["x8", "-u", url, "-w", str(wordlist), "-o", str(out)]
    r = ctx.execute("x8", cmd, timeout=600)
    return ok_path(r, out)
