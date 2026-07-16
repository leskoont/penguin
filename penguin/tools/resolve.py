"""DNS resolution, brute-force and permutation wrappers (Block 1, stage 2-3)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext, ok_path


def dnsvalidator(ctx: ToolContext, resolvers_out: Path) -> Optional[Path]:
    cmd = ["dnsvalidator", "-tL", "https://public-dns.info/nameservers.txt",
           "-o", str(resolvers_out), "-threads", "100"]
    r = ctx.execute("dnsvalidator", cmd, timeout=300)
    return ok_path(r, resolvers_out)


def puredns_bruteforce(ctx: ToolContext, domain: str, wordlist: Path, resolvers: Path, out: Path) -> Optional[Path]:
    # --rate-limit / --rate-limit-trusted are REQUIRED here: puredns defaults to
    # 0 (unlimited), so massdns underneath keeps thousands of concurrent UDP:53
    # flows open at once. From behind a consumer/SOHO router that exhausts the
    # NAT/conntrack table and drops the whole WAN link mid-run. Bound both to
    # the configured qps so query volume stays under the router's flow ceiling.
    rate = ctx.cfg.general.rate_limit
    cmd = ["puredns", "bruteforce", str(wordlist), domain, "-r", str(resolvers),
           "--rate-limit", str(rate), "--rate-limit-trusted", str(rate), "-w", str(out)]
    # retries=1: puredns doesn't use the proxy pool, and a 1200s timeout that
    # already ran to the wall means the same wordlist+resolvers will run just as
    # long the next time -- replaying it 3x is 60 min of dead wall-clock for a
    # result that was already final on attempt 1.
    r = ctx.execute("puredns", cmd, timeout=1200, retries=1)
    return ok_path(r, out)


def puredns_resolve(ctx: ToolContext, in_file: Path, resolvers: Path, out: Path) -> Optional[Path]:
    # Rate-limit for the same reason as puredns_bruteforce (unlimited default
    # floods the link). See that function's comment.
    rate = ctx.cfg.general.rate_limit
    cmd = ["puredns", "resolve", "-r", str(resolvers),
           "--rate-limit", str(rate), "--rate-limit-trusted", str(rate),
           "-w", str(out), str(in_file)]
    r = ctx.execute("puredns", cmd, timeout=1200, retries=1)  # same as puredns_bruteforce
    return ok_path(r, out)


def dnsx_ips(ctx: ToolContext, in_file: Path, resolvers: Path, out: Path) -> Optional[Path]:
    """Resolve hostnames to plain A-record IPs (one per line, no host/type labels)."""
    # -rl/-t: dnsx defaults to unlimited rate + 100 threads; bound both so the
    # direct DNS query volume stays under the router's conntrack/NAT ceiling
    # (see dnsx()/puredns_bruteforce comments -- this is what dropped the link).
    rate = ctx.cfg.general.rate_limit
    threads = ctx.cfg.general.threads
    cmd = ["dnsx", "-l", str(in_file), "-r", str(resolvers), "-a", "-resp-only",
           "-rl", str(rate), "-t", str(threads), "-o", str(out)]
    r = ctx.execute("dnsx", cmd, timeout=600)
    return ok_path(r, out)


def dnsx(ctx: ToolContext, in_file: Path, resolvers: Path, out: Path, *, ipv6: bool = False) -> Optional[Path]:
    # -rl/-t bound dnsx's direct query volume: it defaults to unlimited rate and
    # ~100 threads, and here each name triggers 5-6 record-type lookups
    # (A/AAAA/CNAME/MX/NS/TXT) -- unbounded, that packet flood exhausts a home
    # router's conntrack/NAT table and drops the WAN link. Tie both to config.
    rate = ctx.cfg.general.rate_limit
    threads = ctx.cfg.general.threads
    cmd = ["dnsx", "-l", str(in_file), "-r", str(resolvers), "-a", "-resp", "-cname", "-mx", "-ns", "-txt",
           "-rl", str(rate), "-t", str(threads)]
    if ipv6:
        cmd += ["-aaaa"]
    cmd += ["-o", str(out)]
    r = ctx.execute("dnsx", cmd, timeout=600)
    return ok_path(r, out)


def dnsgen(ctx: ToolContext, in_file: Path, out: Path) -> Optional[Path]:
    cmd = ["dnsgen", str(in_file)]
    # retries=1: dnsgen doesn't use the proxy pool (not in _base's proxy_flag
    # map), so the default 3x "re-pick a proxy" budget applies no proxy and just
    # replays a full 300s timeout up to three times -- 15 min of dead wall-clock
    # for a permutation set that would be identical on every attempt.
    r = ctx.execute("dnsgen", cmd, timeout=300, retries=1)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


# altdns removed: broken upstream against modern tldextract (import of the
# deleted ``LOG`` symbol), so it fail-fasted every run, and gotator + dnsgen
# already cover the same DNS-permutation space and actually work.


def gotator(ctx: ToolContext, in_file: Path, out: Path, words: Path) -> Optional[Path]:
    # gotator has no -o/output flag at all -- it only ever writes to stdout.
    cmd = ["gotator", "-sub", str(in_file), "-perm", str(words), "-depth", "2"]
    # retries=1: same as dnsgen/puredns -- gotator isn't proxied, so replaying a
    # hit 300s timeout 3x buys nothing but wall-clock. This is the retry storm
    # observed adding ~15 min to a run ("[retry 1/3] gotator -> timeout after
    # 300s") before the block would even finish.
    r = ctx.execute("gotator", cmd, timeout=300, retries=1)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


