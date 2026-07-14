"""DNS resolution, brute-force and permutation wrappers (Block 1, stage 2-3)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext


def dnsvalidator(ctx: ToolContext, resolvers_out: Path) -> Optional[Path]:
    cmd = ["dnsvalidator", "-tL", "https://public-dns.info/nameservers.txt",
           "-o", str(resolvers_out), "-threads", "100"]
    r = ctx.execute("dnsvalidator", cmd, timeout=300)
    return resolvers_out if resolvers_out.exists() else None


def puredns_bruteforce(ctx: ToolContext, domain: str, wordlist: Path, resolvers: Path, out: Path) -> Optional[Path]:
    cmd = ["puredns", "bruteforce", str(wordlist), domain, "-r", str(resolvers), "-w", str(out)]
    # retries=1: puredns doesn't use the proxy pool, and a 1200s timeout that
    # already ran to the wall means the same wordlist+resolvers will run just as
    # long the next time -- replaying it 3x is 60 min of dead wall-clock for a
    # result that was already final on attempt 1.
    r = ctx.execute("puredns", cmd, timeout=1200, retries=1)
    return out if out.exists() else None


def puredns_resolve(ctx: ToolContext, in_file: Path, resolvers: Path, out: Path) -> Optional[Path]:
    cmd = ["puredns", "resolve", "-r", str(resolvers), "-w", str(out), str(in_file)]
    r = ctx.execute("puredns", cmd, timeout=1200, retries=1)  # same as puredns_bruteforce
    return out if out.exists() else None


def dnsx_ips(ctx: ToolContext, in_file: Path, resolvers: Path, out: Path) -> Optional[Path]:
    """Resolve hostnames to plain A-record IPs (one per line, no host/type labels)."""
    cmd = ["dnsx", "-l", str(in_file), "-r", str(resolvers), "-a", "-resp-only", "-o", str(out)]
    r = ctx.execute("dnsx", cmd, timeout=600)
    return out if out.exists() else None


def dnsx(ctx: ToolContext, in_file: Path, resolvers: Path, out: Path, *, ipv6: bool = False) -> Optional[Path]:
    cmd = ["dnsx", "-l", str(in_file), "-r", str(resolvers), "-a", "-resp", "-cname", "-mx", "-ns", "-txt"]
    if ipv6:
        cmd += ["-aaaa"]
    cmd += ["-o", str(out)]
    r = ctx.execute("dnsx", cmd, timeout=600)
    return out if out.exists() else None


def dnsgen(ctx: ToolContext, in_file: Path, out: Path) -> Optional[Path]:
    cmd = ["dnsgen", str(in_file)]
    r = ctx.execute("dnsgen", cmd, timeout=300)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def altdns(ctx: ToolContext, in_file: Path, words: Path, out: Path, resolved: Path) -> Optional[Path]:
    cmd = ["altdns", "-i", str(in_file), "-o", str(out), "-w", str(words), "-r", "-s", str(resolved)]
    r = ctx.execute("altdns", cmd, timeout=300)
    return resolved if resolved.exists() else None


def gotator(ctx: ToolContext, in_file: Path, out: Path, words: Path) -> Optional[Path]:
    # gotator has no -o/output flag at all -- it only ever writes to stdout.
    cmd = ["gotator", "-sub", str(in_file), "-perm", str(words), "-depth", "2"]
    r = ctx.execute("gotator", cmd, timeout=300)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


