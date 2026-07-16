"""Block 1 - Infrastructure recon.

ASN/BGP discovery -> 3-stage subdomain enumeration -> resolve + HTTP probe ->
IPv6 sweep -> continuous diff. Mirrors guide Block 1.
"""
from __future__ import annotations

import logging
import re
from functools import partial
from pathlib import Path

from ..config import Config
from ..parallel import run_parallel
from ..state import ARTIFACTS, RunState
from ..tools import subdomain as sd
from ..tools import resolve as rs
from ..tools import probe as pb
from ..tools._base import ToolContext

logger = logging.getLogger("penguin.block1")


def _domain_targets(cfg: Config, target: dict) -> list[str]:
    if target["type"] in ("domain", "url"):
        return [target["value"].replace("https://", "").replace("http://", "").split("/")[0]]
    return [target["value"]]


def _scope_regex(domains: list[str]) -> "re.Pattern[str]":
    """Regex matching the target apex or any subdomain of it, and nothing else."""
    alts = "|".join(re.escape(d) for d in sorted(set(domains), key=len, reverse=True))
    return re.compile(rf"(?<![\w.-])((?:[a-z0-9_-]+\.)*(?:{alts}))(?![\w.-])", re.IGNORECASE)


def _extract_scoped(text: str, rx: "re.Pattern[str]") -> set[str]:
    """Pull only in-scope hostnames out of a tool's output file.

    amass v4's ``enum -o`` writes an association *graph*, not a plain host list::

        relay.hantik.ru (FQDN) --> a_record --> 109.120.155.254 (IPAddress)
        13238 (ASN) --> announces --> 77.88.0.0/18 (Netblock)

    A naive line-by-line merge therefore dumped ASNs, netblocks and bare IPs
    into the subdomain set -- inflating the reported count with junk, poisoning
    the httpx/resolve inputs, and seeding ~150k bogus permutations from
    non-host seeds. Extracting only in-scope FQDN tokens recovers the real
    names embedded in the graph (``relay.hantik.ru``) and is a no-op for tools
    that already emit clean, one-host-per-line lists.
    """
    return {m.group(1).lower().rstrip(".") for m in rx.finditer(text)}


def run_block1(cfg: Config, state: RunState, target: dict) -> dict:
    ctx = ToolContext(cfg)
    results: dict = {"subdomains": [], "resolved": [], "live": []}
    if not cfg.stage_enabled("infra"):
        logger.info("[block1] disabled by config")
        return results

    domains = _domain_targets(cfg, target)
    sub_dir = state.sub("subdomains")

    # ---- Stage 1: passive ----
    # Each source writes its own distinct output file and none of them touch
    # the target host (they query subfinder/amass/crt.sh/chaos aggregators),
    # so the whole fan-out is safe to overlap: wall-clock collapses from the
    # *sum* of every source's timeout to roughly the slowest single source
    # (amass). ToolContext.execute picks proxies under a lock, so concurrent
    # calls are thread-safe. See penguin/parallel for the safety contract.
    passive_tasks: list = []
    for domain in domains:
        logger.info("[block1] passive enum: %s", domain)
        passive_tasks += [
            partial(sd.subfinder, ctx, domain, sub_dir / f"subfinder_{domain}.txt"),
            partial(sd.amass_passive, ctx, domain, sub_dir / f"amass_{domain}.txt"),
            partial(sd.assetfinder, ctx, domain, sub_dir / f"assetfinder_{domain}.txt"),
            partial(sd.findomain, ctx, domain, sub_dir / f"findomain_{domain}.txt"),
            partial(sd.chaos, ctx, domain, sub_dir / f"chaos_{domain}.txt"),
            partial(sd.crtsh, ctx, domain, sub_dir / f"crtsh_{domain}.txt"),
            partial(sd.amass_intel, ctx, domain.split(".")[0], sub_dir / f"amass_intel_{domain}.txt"),
        ]
    run_parallel(passive_tasks, max_workers=cfg.general.max_parallel_tools,
                 label="block1 passive enum")

    # ---- merge raw (stage 1: passive) ----
    all_raw = state.path("all_subdomains_raw.txt")
    scope_rx = _scope_regex(domains)
    raw_lines: set[str] = set()
    for f in sub_dir.glob("*.txt"):
        if f.exists():
            raw_lines |= _extract_scoped(f.read_text(encoding="utf-8", errors="ignore"), scope_rx)

    # ---- Stage 2: brute + Stage 3: permutations ----
    resolvers = cfg.path(cfg.general.resolvers_file)
    if not resolvers.exists():
        logger.info("[block1] no resolvers file; bootstrapping via dnsvalidator")
        rs.dnsvalidator(ctx, resolvers)
    if resolvers.exists():
        from ..tools import resolve as rs2

        brute_wl = cfg.path("wordlists/subdomains-large.txt")
        if brute_wl.exists():
            for dom in domains:
                rs2.puredns_bruteforce(ctx, dom, brute_wl, resolvers,
                                       sub_dir / f"puredns_brute_{dom}.txt")
        else:
            # Without this guard puredns is invoked anyway and fails 3x with
            # "open .../subdomains-large.txt: no such file or directory" -- a
            # guaranteed-permanent error. Skip loudly instead: a missing brute
            # wordlist is the single biggest cause of subdomain-count
            # degradation, so make it visible rather than a buried retry storm.
            logger.warning("[block1] brute wordlist missing (%s); skipping puredns "
                           "bruteforce -- run scripts/install.sh to fetch wordlists", brute_wl)
        perms_in = sub_dir / "all_for_perms.txt"
        perms_in.write_text("\n".join(sorted(raw_lines)), encoding="utf-8")

        # Permutation *generation* writes a distinct file, so it could fan out,
        # but gotator is now the only generator. Its puredns *resolution* stays
        # strictly sequential below: two puredns runs against the same resolver
        # set would rate-limit each other and silently drop valid names.
        # altdns was dropped (broken upstream against modern tldextract) and
        # dnsgen was removed too: its output is redundant with gotator's
        # permutation space, so it only added wall-clock and duplicate names.
        words = cfg.path("wordlists/permutation-words.txt")
        gen_tasks = []
        if words.exists():
            gen_tasks.append(partial(rs2.gotator, ctx, perms_in,
                                     sub_dir / "gotator_perms.txt", words))
        if gen_tasks:
            run_parallel(gen_tasks, max_workers=cfg.general.max_parallel_tools,
                         label="block1 permutation gen")

        if (sub_dir / "gotator_perms.txt").exists():
            rs2.puredns_resolve(ctx, sub_dir / "gotator_perms.txt", resolvers,
                                sub_dir / "gotator_resolved.txt")

        # feed brute-force + permutation discoveries back into the pipeline
        # (guide's self-learning principle: every found artifact returns to
        # the pipeline instead of being a dead end)
        # Brute-force writes one file *per domain* (puredns_brute_<dom>.txt at
        # line ~105), so glob them all -- a hardcoded "puredns_brute.txt" never
        # exists and would silently drop every brute-forced subdomain.
        extras = list(sub_dir.glob("puredns_brute_*.txt"))
        extras += [sub_dir / "gotator_resolved.txt"]
        for extra in extras:
            if extra.exists():
                raw_lines |= _extract_scoped(extra.read_text(encoding="utf-8", errors="ignore"), scope_rx)

    all_raw.write_text("\n".join(sorted(raw_lines)) + "\n", encoding="utf-8")
    results["subdomains"] = sorted(raw_lines)

    # ---- resolve + probe ----
    resolved_file = state.path(ARTIFACTS.RESOLVED)
    if resolvers.exists():
        rs.puredns_resolve(ctx, all_raw, resolvers, resolved_file)
        # dnsx v4 and v6 resolve sequentially: both hit the same resolver set
        # directly (dnsx's -proxy only covers DoH/HTTP, not the plain queries
        # to -r), so overlapping them doubles the direct DNS query volume and
        # can saturate/drop the connection -- same rate-limit caution that
        # keeps puredns sequential (issue: block1 killed the network link).
        rs.dnsx(ctx, all_raw, resolvers, state.path("resolved_dnsx.txt"))
        rs.dnsx(ctx, all_raw, resolvers, state.path("resolved_ipv6.txt"), ipv6=True)
    else:
        logger.warning("[block1] no resolvers file; skipping active resolution")

    live_csv = state.path(ARTIFACTS.LIVE_HTTPX_CSV)
    # -screenshot makes httpx shell out to go-rod, which needs a real Chrome
    # binary and will try (and, offline/sandboxed, fail) to auto-download
    # one -- only pay that cost when screenshots are actually wanted.
    shots_dir = state.path("screenshots", run=True) if ctx.cfg.general.screenshots else None
    pb.httpx(ctx, resolved_file if resolved_file.exists() else all_raw, live_csv,
             screenshots_dir=shots_dir)
    results["resolved"] = state.read_lines(ARTIFACTS.RESOLVED)
    if live_csv.exists():
        results["live"] = state.read_lines(ARTIFACTS.LIVE_HTTPX_CSV)
    return results
