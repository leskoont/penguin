"""Block 5 - Feedback pass: re-runs driven by what blocks 1-4 discovered.

The pipeline's blocks each discover assets whose *follow-up* work only becomes
possible once the whole run has been seen. This block closes those loops:

  1. Straggler subdomains -- names found late (TLS SANs, permutations, brute)
     that block1 never resolved/probed because they surfaced after its
     resolve stage. Re-resolve + HTTP-probe them here.
  2. Service-credential vectors -- open DB/service ports found by block3 are
     mapped to knowledge-bank products (redis/mongodb/elasticsearch/tomcat) so
     known default-credential sets surface the same way fingerprinted tech
     does in block2.
  3. Targeted CVE scan -- when block2's knowledge-bank match flagged a
     detected technology as vulnerable (incl. actively-exploited KEV), run
     nuclei's official CVE templates against the live hosts. This is the
     "re-run based on discovered data" step: no KB hit -> no scan.
  4. Web-misconfig re-check -- the straggler hosts that turned out live get
     the same CORS/header checks block2 ran on its own host set.

All inputs are read from the per-block checkpoint files block1-4 wrote, so
this block degrades gracefully (empty results) whenever an earlier block
crashed or was skipped.
"""
from __future__ import annotations

import json
import logging
from functools import partial

from ..config import Config
from ..knowledge import KnowledgeBank
from ..parallel import run_parallel
from ..state import ARTIFACTS, RunState
from ..tools import nuclei_custom as nu
from ..tools import probe as pb
from ..tools import resolve as rs
from ..tools import webchecks as wc
from ..tools._base import ToolContext

logger = logging.getLogger("penguin.block5")


def _read_block_result(state: RunState, block_num: int) -> dict:
    """Load an earlier block's checkpoint (empty dict when absent/corrupt)."""
    p = state.run_dir / f"_block{block_num}_result.json"
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (ValueError, OSError):
        return {}


def compute_stragglers(subdomains: list[str], resolved: list[str]) -> list[str]:
    """Subdomains that were discovered but never resolved by block1.

    Pure + deterministic so it is unit-testable."""
    return sorted(set(subdomains) - set(resolved))


def run_block5(cfg: Config, state: RunState, target: dict) -> dict:
    ctx = ToolContext(cfg, run_dir=state.run_dir)
    results: dict = {"stragglers": [], "new_live": [], "service_vectors": [],
                     "cve_hits": [], "web_issues": []}
    if not cfg.stage_enabled("feedback"):
        logger.info("[block5] disabled by config")
        return results

    cap = cfg.general.feedback_max_hosts or 50
    fb_dir = state.sub("feedback")

    # ---- 1. straggler subdomains: resolve + probe what block1 missed ----
    b1 = _read_block_result(state, 1)
    stragglers = compute_stragglers(b1.get("subdomains", []),
                                    b1.get("resolved", []))[:cap]
    if stragglers:
        logger.info("[block5] %d straggler subdomains never resolved by block1 -- "
                    "re-resolving + probing", len(stragglers))
        stragglers_in = fb_dir / "straggler_subdomains.txt"
        stragglers_in.write_text("\n".join(stragglers) + "\n", encoding="utf-8")
        resolved_out = fb_dir / "straggler_resolved.txt"
        resolvers = cfg.path(cfg.general.resolvers_file)
        if resolvers.exists():
            rs.puredns_resolve(ctx, stragglers_in, resolvers, resolved_out)
        results["stragglers"] = (state.read_lines("feedback/straggler_resolved.txt")
                                 if resolved_out.exists() else [])
        if results["stragglers"]:
            probe_in = fb_dir / "straggler_probe_in.txt"
            probe_in.write_text("\n".join(results["stragglers"]) + "\n", encoding="utf-8")
            live_out = fb_dir / "straggler_live.txt"
            pb.httpx_simple(ctx, probe_in, live_out)
            new_live = state.read_lines("feedback/straggler_live.txt")
            results["new_live"] = new_live
            if new_live:
                # fold the newly-live hosts into this run's live_hosts artifact
                # (block4 already ran, so this benefits the report + accumulators
                # + the next run, which is exactly the feedback-loop intent)
                existing = state.read_lines(ARTIFACTS.LIVE_HOSTS)
                state.path(ARTIFACTS.LIVE_HOSTS).write_text(
                    "\n".join(sorted(set(existing) | set(new_live))) + "\n",
                    encoding="utf-8")
    else:
        logger.info("[block5] no straggler subdomains to re-probe")

    # ---- 2. open service ports -> knowledge-bank credential vectors ----
    b3 = _read_block_result(state, 3)
    open_db = b3.get("open_db", []) or []
    if open_db:
        extra_dirs = [cfg.path(cfg.general.knowledge_dir)] if cfg.general.knowledge_dir else []
        kb = KnowledgeBank.load(extra_dirs)
        results["service_vectors"] = kb.service_vectors(open_db)
        if results["service_vectors"]:
            logger.warning("[block5] %d open service(s) match knowledge-bank "
                           "default-credential sets", len(results["service_vectors"]))

    # ---- 3. KB-flagged vulnerable tech -> targeted nuclei CVE scan ----
    b2 = _read_block_result(state, 2)
    kb_findings = b2.get("kb_findings", []) or []
    cve_flagged = [v for v in kb_findings
                   if isinstance(v, dict) and v.get("kind") in ("known_cve", "kev_exploited")]
    live_hosts = state.path(ARTIFACTS.LIVE_HOSTS)
    if cve_flagged and live_hosts.exists():
        n_kev = sum(1 for v in cve_flagged if v.get("kind") == "kev_exploited")
        logger.warning("[block5] knowledge bank flagged %d CVE(s) (%d actively "
                       "exploited) -- running targeted nuclei CVE scan", len(cve_flagged), n_kev)
        cve_out = fb_dir / "nuclei_cves.jsonl"
        if nu.nuclei_cves(ctx, live_hosts, cve_out,
                          rate_limit=cfg.general.rate_limit, concurrency=40):
            hits = [h for h in nu.parse_nuclei_jsonl(cve_out) if h.get("matcher_status")]
            # dedup on (cve|template_id, host), preserving order
            seen: set[tuple] = set()
            for h in hits:
                key = (h.get("cve") or h.get("template_id"), h.get("host"))
                if key not in seen:
                    seen.add(key)
                    results["cve_hits"].append(h)
            if results["cve_hits"]:
                logger.warning("[block5] nuclei CVE templates confirmed %d finding(s)",
                               len(results["cve_hits"]))
    elif cve_flagged:
        logger.info("[block5] KB flagged CVEs but no live_hosts artifact; skipping CVE scan")

    # ---- 4. web-misconfig re-check on newly-live stragglers ----
    if results["new_live"]:
        for issue in run_parallel([partial(wc.check_host, ctx, h) for h in results["new_live"]],
                                  max_workers=cfg.general.clamp_workers(cfg.general.max_parallel_tools),
                                  label="block5 web-misconfig recheck"):
            if issue:
                results["web_issues"].append(issue)
    return results
