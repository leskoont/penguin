"""Block 4 - Elite recon: origin IP / Cloudflare bypass, CI/CD+Git, WAF, custom Nuclei."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..config import Config
from ..state import RunState
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
    origin_dir = state.sub("origin")
    og.dig_resolve(ctx, f"www.{domain}", "1.1.1.1", origin_dir / "dig_www.txt")
    og.dig_resolve(ctx, domain, "1.1.1.1", origin_dir / "dig_apex.txt")
    og.cloudflare_trace(ctx, f"https://www.{domain}", origin_dir / "cf_trace.txt")
    og.viewdns_history(ctx, domain, origin_dir / "viewdns.txt")
    og.historical_dns_securitytrails(ctx, domain, origin_dir / "securitytrails.json")
    og.censys_certs(ctx, domain, origin_dir / "censys_certs.json")
    og.cloudflair(ctx, domain, origin_dir / "cloudflair.txt")

    # ---- CI/CD + Git ----
    subs_file = state.path("resolved.txt")
    if subs_file.exists():
        exposed = gc.exposed_git_probe(ctx, subs_file, state.path("gitcicd/exposed_git.txt"))
        if exposed:
            results["exposed_git"] = exposed.read_text(encoding="utf-8").splitlines()
    # git history secrets on dumped repos (if any)
    nu.nuclei_update(ctx)  # ensure templates present (best-effort)

    # ---- custom nuclei templates on live hosts ----
    live_hosts = state.path("live_hosts.txt")
    if live_hosts.exists():
        nu.nuclei_scan(ctx, live_hosts, state.path("vulns/nuclei_custom.json"),
                       custom_only=True, rate_limit=cfg.general.rate_limit, concurrency=40)
    return results
