"""Content discovery wrappers (Block 2.3-2.4): crawling, JS collection,
directory/param fuzzing.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from ._base import ToolContext, ok_path

logger = logging.getLogger("penguin.tools.content")


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
              exts: Optional[str] = None, *, threads: int = 40, rate: int = 150) -> Optional[Path]:
    # -t/-rate bound ffuf's concurrent sockets and request rate. Left at the old
    # -t 100 -rate 300 and then multiplied by block2's per-host run_parallel
    # fan-out (up to max_parallel_tools ffuf processes at once), the aggregate
    # was ~800 live sockets plus thousands of short-lived TIME_WAIT entries per
    # second -- which exhausts a home/SOHO router's NAT/conntrack table and
    # drops the whole WAN link mid-run (the HTTP analogue of block1's DNS
    # flood). Callers pass a per-host share of the global budget so the
    # aggregate stays under the router's ceiling.
    cmd = ["ffuf", "-u", f"{url}/FUZZ", "-w", str(wordlist), "-t", str(threads),
           "-mc", "200,204,301,302,307,401,403,405", "-rate", str(rate), "-o", str(out)]
    if exts:
        cmd += ["-e", exts]
    r = ctx.execute("ffuf", cmd, timeout=1800)
    return ok_path(r, out)


def feroxbuster(ctx: ToolContext, url: str, wordlist: Path, out: Path,
                *, threads: int = 20, rate: int = 150) -> Optional[Path]:
    # -t/--rate-limit bound concurrency + request rate for the same conntrack
    # reason as ffuf_dirs (feroxbuster runs in the same per-host fan-out).
    cmd = ["feroxbuster", "-u", url, "-w", str(wordlist), "-r", "-t", str(threads),
           "--rate-limit", str(rate), "-o", str(out)]
    r = ctx.execute("feroxbuster", cmd, timeout=1800)
    return ok_path(r, out)


def arjun(ctx: ToolContext, url: str, out: Path, method: str = "GET",
          *, threads: int = 10) -> Optional[Path]:
    # --stable forces threads=1 plus a random 6-12s delay between every
    # request -- against a large param wordlist that alone burns the whole
    # 600s timeout x3 retries. Drop it and use arjun's real threads/timeout
    # flags (-t default 5, -T per-request timeout default 15s) instead. -t is a
    # caller-supplied share of the global budget so the per-host fan-out doesn't
    # add up to a conntrack-exhausting connection flood (see ffuf_dirs).
    cmd = ["arjun", "-u", url, "-m", method, "-t", str(threads), "-T", "10", "-o", str(out)]
    r = ctx.execute("arjun", cmd, timeout=300)
    return ok_path(r, out)


def paramspider(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    # paramspider has no -o/--output flag -- it always writes to a hardcoded
    # ./results/<domain>.txt relative to the CWD it's invoked from. Run it
    # inside a throwaway directory (execute's cwd isolation) so it can neither
    # scatter files into whatever directory penguin was launched from nor pick
    # up a stale/planted file of the same name, then relocate the output.
    import shutil
    import tempfile

    with tempfile.TemporaryDirectory(prefix="penguin-paramspider-") as tmp:
        cmd = ["paramspider", "-d", domain]
        r = ctx.execute("paramspider", cmd, timeout=600, cwd=tmp)
        produced = Path(tmp) / "results" / f"{domain}.txt"
        if r.ok and produced.is_file():
            out.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.move(str(produced), str(out))
            except OSError:
                logger.warning("[paramspider] could not relocate output for %s", domain)
                return None
    return ok_path(r, out)


def x8(ctx: ToolContext, url: str, wordlist: Path, out: Path) -> Optional[Path]:
    cmd = ["x8", "-u", url, "-w", str(wordlist), "-o", str(out)]
    r = ctx.execute("x8", cmd, timeout=600)
    return ok_path(r, out)
