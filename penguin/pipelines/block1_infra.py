"""Block 1 - Infrastructure recon.

ASN/BGP discovery -> 3-stage subdomain enumeration -> resolve + HTTP probe ->
IPv6 sweep -> continuous diff. Mirrors guide Block 1.
"""
from __future__ import annotations

import logging
from pathlib import Path

from ..config import Config
from ..state import RunState
from ..tools import subdomain as sd
from ..tools import resolve as rs
from ..tools import probe as pb
from ..tools._base import ToolContext

logger = logging.getLogger("penguin.block1")


def _domain_targets(cfg: Config, target: dict) -> list[str]:
    if target["type"] in ("domain", "url"):
        return [target["value"].replace("https://", "").replace("http://", "").split("/")[0]]
    return [target["value"]]


def run_block1(cfg: Config, state: RunState, target: dict) -> dict:
    ctx = ToolContext(cfg)
    results: dict = {"subdomains": [], "resolved": [], "live": []}
    if not cfg.stage_enabled("infra"):
        logger.info("[block1] disabled by config")
        return results

    domains = _domain_targets(cfg, target)
    sub_dir = state.sub("subdomains")

    # ---- Stage 1: passive ----
    for domain in domains:
        logger.info("[block1] passive enum: %s", domain)
        sd.subfinder(ctx, domain, sub_dir / f"subfinder_{domain}.txt")
        sd.amass_passive(ctx, domain, sub_dir / f"amass_{domain}.txt")
        sd.assetfinder(ctx, domain, sub_dir / f"assetfinder_{domain}.txt")
        sd.findomain(ctx, domain, sub_dir / f"findomain_{domain}.txt")
        sd.chaos(ctx, domain, sub_dir / f"chaos_{domain}.txt")
        sd.crtsh(ctx, domain, sub_dir / f"crtsh_{domain}.txt")
        sd.amass_intel(ctx, domain.split(".")[0], sub_dir / f"amass_intel_{domain}.txt")

    # ---- merge raw (stage 1: passive) ----
    all_raw = state.path("all_subdomains_raw.txt")
    raw_lines: set[str] = set()
    for f in sub_dir.glob("*.txt"):
        if f.exists():
            raw_lines |= {l.strip() for l in f.read_text(encoding="utf-8").splitlines() if l.strip()}

    # ---- Stage 2: brute + Stage 3: permutations ----
    resolvers = cfg.path(cfg.general.resolvers_file)
    if not resolvers.exists():
        logger.info("[block1] no resolvers file; bootstrapping via dnsvalidator")
        rs.dnsvalidator(ctx, resolvers)
    if resolvers.exists():
        from ..tools import resolve as rs2

        brute_wl = cfg.path("wordlists/subdomains-large.txt")
        if brute_wl.exists():
            rs2.puredns_bruteforce(ctx, domains[0], brute_wl, resolvers,
                                   sub_dir / "puredns_brute.txt")
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
        rs2.dnsgen(ctx, perms_in, sub_dir / "dnsgen_perms.txt")
        rs2.puredns_resolve(ctx, sub_dir / "dnsgen_perms.txt", resolvers, sub_dir / "perms_resolved.txt")

        words = cfg.path("wordlists/permutation-words.txt")
        if words.exists():
            rs2.altdns(ctx, perms_in, words, sub_dir / "altdns_perms.txt", sub_dir / "altdns_resolved.txt")
            rs2.gotator(ctx, perms_in, sub_dir / "gotator_perms.txt", words)
            rs2.puredns_resolve(ctx, sub_dir / "gotator_perms.txt", resolvers, sub_dir / "gotator_resolved.txt")

        # feed brute-force + permutation discoveries back into the pipeline
        # (guide's self-learning principle: every found artifact returns to
        # the pipeline instead of being a dead end)
        for extra in (sub_dir / "puredns_brute.txt", sub_dir / "perms_resolved.txt",
                      sub_dir / "altdns_resolved.txt", sub_dir / "gotator_resolved.txt"):
            if extra.exists():
                raw_lines |= {l.strip() for l in extra.read_text(encoding="utf-8").splitlines() if l.strip()}

    all_raw.write_text("\n".join(sorted(raw_lines)) + "\n", encoding="utf-8")
    results["subdomains"] = sorted(raw_lines)

    # ---- resolve + probe ----
    resolved_file = state.path("resolved.txt")
    if resolvers.exists():
        rs.puredns_resolve(ctx, all_raw, resolvers, resolved_file)
        rs.dnsx(ctx, all_raw, resolvers, state.path("resolved_dnsx.txt"))
        rs.dnsx(ctx, all_raw, resolvers, state.path("resolved_ipv6.txt"), ipv6=True)
    else:
        logger.warning("[block1] no resolvers file; skipping active resolution")

    live_csv = state.path("live", run=True) / "httpx.csv"
    live_csv.parent.mkdir(parents=True, exist_ok=True)
    # -screenshot makes httpx shell out to go-rod, which needs a real Chrome
    # binary and will try (and, offline/sandboxed, fail) to auto-download
    # one -- only pay that cost when screenshots are actually wanted.
    shots_dir = state.path("screenshots", run=True) if ctx.cfg.general.screenshots else None
    pb.httpx(ctx, resolved_file if resolved_file.exists() else all_raw, live_csv,
             screenshots_dir=shots_dir)
    results["resolved"] = state.read_lines("resolved.txt")
    if live_csv.exists():
        results["live"] = state.read_lines("live/httpx.csv")
    return results
