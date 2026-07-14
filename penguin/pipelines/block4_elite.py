"""Block 4 - Elite recon: origin IP / Cloudflare bypass, CI/CD+Git, WAF, custom Nuclei."""
from __future__ import annotations

import logging
import re
from functools import partial
from pathlib import Path

from ..config import Config
from ..parallel import run_parallel
from ..state import ARTIFACTS, RunState
from ..tools import origin as og
from ..tools import gitcicd as gc
from ..tools import secrets as sc
from ..tools import nuclei_custom as nu
from ..tools._base import ToolContext

logger = logging.getLogger("penguin.block4")


def run_block4(cfg: Config, state: RunState, target: dict) -> dict:
    ctx = ToolContext(cfg)
    results: dict = {"origin_ips": [], "exposed_git": [], "secrets": []}
    if not cfg.stage_enabled("elite"):
        logger.info("[block4] disabled by config")
        return results

    domain = re.sub(r"^https?://", "", target["value"]).split("/")[0]

    # ---- origin IP discovery ----
    # Seven independent OSINT lookups, each hitting a *different* external
    # service (Cloudflare DNS, viewdns, SecurityTrails, Censys, ...) and
    # writing its own distinct file -- no shared state, no target hammering --
    # so fan them out instead of summing their latencies serially.
    origin_dir = state.sub("origin")
    origin_tasks = [
        partial(og.dig_resolve, ctx, f"www.{domain}", "1.1.1.1", origin_dir / "dig_www.txt"),
        partial(og.dig_resolve, ctx, domain, "1.1.1.1", origin_dir / "dig_apex.txt"),
        partial(og.cloudflare_trace, ctx, f"https://www.{domain}", origin_dir / "cf_trace.txt"),
        partial(og.viewdns_history, ctx, domain, origin_dir / "viewdns.txt"),
        partial(og.historical_dns_securitytrails, ctx, domain, origin_dir / "securitytrails.json"),
        partial(og.censys_certs, ctx, domain, origin_dir / "censys_certs.json"),
        partial(og.cloudflair, ctx, domain, origin_dir / "cloudflair.txt"),
    ]
    run_parallel(origin_tasks, max_workers=cfg.general.max_parallel_tools,
                 label="block4 origin discovery")

    # ---- verify origin IP candidates found above (bypasses CDN if real) ----
    ip_re = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    candidate_ips: set[str] = set()
    for f in origin_dir.glob("*.txt"):
        candidate_ips |= set(ip_re.findall(f.read_text(encoding="utf-8")))
    for f in origin_dir.glob("*.json"):
        candidate_ips |= set(ip_re.findall(f.read_text(encoding="utf-8")))
    # Each candidate is a *distinct* IP probed into its own verify_*.txt, so the
    # probes overlap safely; the returncode check is read back sequentially
    # afterwards to preserve the original sorted-order result list.
    ordered_ips = sorted(candidate_ips)
    verify_tasks = [
        partial(og.verify_origin, ctx, domain, ip,
                origin_dir / f"verify_{ip.replace('.', '_')}.txt")
        for ip in ordered_ips
    ]
    run_parallel(verify_tasks, max_workers=cfg.general.max_parallel_tools,
                 label="block4 origin verify")
    verified_ips = []
    for ip in ordered_ips:
        vout = origin_dir / f"verify_{ip.replace('.', '_')}.txt"
        if vout.exists() and "returncode=0" in vout.read_text(encoding="utf-8"):
            verified_ips.append(ip)
    results["origin_ips"] = verified_ips

    # ---- CI/CD + Git ----
    # github code search is a passive subdomain source too, but it's grouped
    # here (not block1) per its git-secret-scanner module (Block 4.2)
    sc.github_subdomains(ctx, domain, state.path("gitcicd/github_subdomains.txt"))

    subs_file = state.path(ARTIFACTS.RESOLVED)
    if subs_file.exists():
        exposed = gc.exposed_git_probe(ctx, subs_file, state.path("gitcicd/exposed_git.txt"))
        if exposed:
            results["exposed_git"] = exposed.read_text(encoding="utf-8").splitlines()
            # dump + scan exposed .git repos for leaked secrets
            dumps_dir = state.sub("gitcicd/dumps")
            for sub in results["exposed_git"][:10]:
                dump_dir = dumps_dir / sub.replace("/", "_")
                gc_out = gc.gitdumper(ctx, f"https://{sub}/.git/", dump_dir)
                if gc_out and gc_out.exists():
                    th = sc.trufflehog_git(ctx, str(dump_dir), state.path("gitcicd") / f"trufflehog_{sub.replace('/', '_')}.json")
                    gl = sc.gitleaks(ctx, dump_dir, state.path("gitcicd") / f"gitleaks_{sub.replace('/', '_')}.json")
                    for r in (th, gl):
                        if r and r.exists():
                            results["secrets"].append(str(r))

    # ---- exposed docker registries (best-effort hostname guesses) ----
    registry_dir = state.sub("gitcicd/registries")
    for registry in (f"registry.{domain}", f"{domain}:5000"):
        catalog_out = registry_dir / f"catalog_{registry.replace(':', '_').replace('/', '_')}.json"
        cat = gc.docker_registry_catalog(ctx, registry, catalog_out)
        if cat and cat.exists():
            import json as _json

            try:
                repos = _json.loads(cat.read_text(encoding="utf-8")).get("repositories", [])
            except Exception:
                repos = []
            for repo in repos[:10]:
                gc.trivy_image(ctx, f"{registry}/{repo}:latest",
                               registry_dir / f"trivy_{repo.replace('/', '_')}.json")

    # ---- custom nuclei templates on live hosts ----
    live_hosts = state.path(ARTIFACTS.LIVE_HOSTS)
    if live_hosts.exists():
        nu.nuclei_scan(ctx, live_hosts, state.path("vulns/nuclei_custom.json"),
                       custom_only=True, rate_limit=cfg.general.rate_limit, concurrency=40)
    return results
