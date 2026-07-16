"""DNS resolution, brute-force and permutation wrappers (Block 1, stage 2-3)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext, ok_path


def _dns_timeout(work_file: Path, rate: int, ceiling: int, *,
                 per_name: int = 1, floor: int = 1200) -> int:
    """Wall-clock a rate-limited puredns/dnsx needs to process ``work_file`` in full.

    A *fixed* timeout silently truncates coverage: at a conntrack-safe DNS rate a
    large wordlist/hostlist can't finish inside a flat 1200s, so the tool is
    killed mid-list and every name it hadn't reached yet is lost -- the single
    biggest silent cause of low subdomain counts. Scale the wall to the actual
    work (``lines * per_name`` queries / qps, +50% headroom for retries and slow
    resolvers) so the whole list resolves. ``floor`` covers tiny lists (spin-up
    dominates); ``ceiling`` (cfg.general.dns_max_timeout) stops a pathological
    multi-million-line list from wedging a run forever.
    """
    try:
        with work_file.open("r", encoding="utf-8", errors="ignore") as fh:
            lines = sum(1 for _ in fh)
    except OSError:
        return floor
    needed = int(lines * max(1, per_name) / max(1, rate) * 1.5)
    return max(floor, min(ceiling, needed))


def dnsvalidator(ctx: ToolContext, resolvers_out: Path) -> Optional[Path]:
    cmd = ["dnsvalidator", "-tL", "https://public-dns.info/nameservers.txt",
           "-o", str(resolvers_out), "-threads", "100"]
    r = ctx.execute("dnsvalidator", cmd, timeout=300)
    return ok_path(r, resolvers_out)


def puredns_bruteforce(ctx: ToolContext, domain: str, wordlist: Path, resolvers: Path, out: Path) -> Optional[Path]:
    # --rate-limit / --rate-limit-trusted are REQUIRED here: puredns defaults to
    # 0 (unlimited), so massdns underneath keeps thousands of concurrent UDP:53
    # flows open at once. From behind a consumer/SOHO router that exhausts the
    # NAT/conntrack table and drops the whole WAN link mid-run. Bound both to the
    # DNS qps so query volume stays under the router's flow ceiling; at a fixed
    # rate concurrency stays ~= rate*RTT (tens of flows), so this can run fast
    # without the flood that killed the link.
    rate = ctx.cfg.general.dns_rate_limit
    cmd = ["puredns", "bruteforce", str(wordlist), domain, "-r", str(resolvers),
           "--rate-limit", str(rate), "--rate-limit-trusted", str(rate), "-w", str(out)]
    # Timeout scales with the wordlist so the *whole* list resolves instead of
    # being cut off at a flat 1200s (which dropped every unreached name). retries=1:
    # puredns isn't proxied, and a run that hit its (already size-matched) wall
    # will take just as long next time -- replaying it is dead wall-clock.
    timeout = _dns_timeout(wordlist, rate, ctx.cfg.general.dns_max_timeout)
    r = ctx.execute("puredns", cmd, timeout=timeout, retries=1)
    return ok_path(r, out)


def puredns_resolve(ctx: ToolContext, in_file: Path, resolvers: Path, out: Path) -> Optional[Path]:
    # Rate-limit for the same reason as puredns_bruteforce (unlimited default
    # floods the link). See that function's comment.
    rate = ctx.cfg.general.dns_rate_limit
    cmd = ["puredns", "resolve", "-r", str(resolvers),
           "--rate-limit", str(rate), "--rate-limit-trusted", str(rate),
           "-w", str(out), str(in_file)]
    # Scale the wall to the input size so a big permutation/name list resolves in
    # full instead of truncating at a flat 1200s. Same retries=1 rationale.
    timeout = _dns_timeout(in_file, rate, ctx.cfg.general.dns_max_timeout)
    r = ctx.execute("puredns", cmd, timeout=timeout, retries=1)
    return ok_path(r, out)


def dnsx_ips(ctx: ToolContext, in_file: Path, resolvers: Path, out: Path) -> Optional[Path]:
    """Resolve hostnames to plain A-record IPs (one per line, no host/type labels)."""
    # -rl/-t: dnsx defaults to unlimited rate + 100 threads; bound both so the
    # direct DNS query volume stays under the router's conntrack/NAT ceiling
    # (see dnsx()/puredns_bruteforce comments -- this is what dropped the link).
    rate = ctx.cfg.general.dns_rate_limit
    threads = ctx.cfg.general.threads
    cmd = ["dnsx", "-l", str(in_file), "-r", str(resolvers), "-a", "-resp-only",
           "-rl", str(rate), "-t", str(threads), "-o", str(out)]
    # One A-lookup per name; scale the wall so a big hostlist finishes in full.
    timeout = _dns_timeout(in_file, rate, ctx.cfg.general.dns_max_timeout, floor=600)
    r = ctx.execute("dnsx", cmd, timeout=timeout)
    return ok_path(r, out)


def dnsx(ctx: ToolContext, in_file: Path, resolvers: Path, out: Path, *, ipv6: bool = False) -> Optional[Path]:
    # -rl/-t bound dnsx's direct query volume: it defaults to unlimited rate and
    # ~100 threads, and here each name triggers 5-6 record-type lookups
    # (A/AAAA/CNAME/MX/NS/TXT) -- unbounded, that packet flood exhausts a home
    # router's conntrack/NAT table and drops the WAN link. Tie both to config.
    rate = ctx.cfg.general.dns_rate_limit
    threads = ctx.cfg.general.threads
    cmd = ["dnsx", "-l", str(in_file), "-r", str(resolvers), "-a", "-resp", "-cname", "-mx", "-ns", "-txt",
           "-rl", str(rate), "-t", str(threads)]
    if ipv6:
        cmd += ["-aaaa"]
    cmd += ["-o", str(out)]
    # 6-7 record-type lookups per name (A/AAAA/CNAME/MX/NS/TXT), so the query
    # volume is ~per_name x the hostlist; scale the wall to match and finish full.
    timeout = _dns_timeout(in_file, rate, ctx.cfg.general.dns_max_timeout,
                           per_name=7 if ipv6 else 6, floor=600)
    r = ctx.execute("dnsx", cmd, timeout=timeout)
    return ok_path(r, out)


# altdns and dnsgen both removed: altdns is broken upstream against modern
# tldextract (import of the deleted ``LOG`` symbol) so it fail-fasted every
# run, and dnsgen's permutation output is redundant with gotator's -- it only
# added wall-clock and duplicate names. gotator alone covers the permutation
# space.


def gotator(ctx: ToolContext, in_file: Path, out: Path, words: Path) -> Optional[Path]:
    # gotator has no -o/output flag at all -- it only ever writes to stdout.
    cmd = ["gotator", "-sub", str(in_file), "-perm", str(words), "-depth", "2"]
    # retries=1: same as puredns -- gotator isn't proxied, so replaying a
    # hit 300s timeout 3x buys nothing but wall-clock. This is the retry storm
    # observed adding ~15 min to a run ("[retry 1/3] gotator -> timeout after
    # 300s") before the block would even finish.
    r = ctx.execute("gotator", cmd, timeout=300, retries=1)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


