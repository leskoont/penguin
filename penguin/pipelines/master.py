"""Master orchestrator: ties Block 0..4 together, accumulates state, learns
wordlists, diffs against previous run and notifies on new assets.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from .. import diagnostics
from ..config import Config
from ..notify import notify
from ..state import ARTIFACTS, RunState
from ..wordlists import WordlistManager
from .block1_infra import run_block1
from .block2_web import run_block2
from .block3_cloud_db import run_block3
from .block4_elite import run_block4

logger = logging.getLogger("penguin.master")

# Core tools whose presence is recorded in the run manifest (a missing binary is
# the dominant silent cause of low result counts).
_MANIFEST_TOOLS = (
    "subfinder", "amass", "assetfinder", "findomain", "crtsh", "puredns", "dnsx",
    "gotator", "httpx", "nuclei", "katana", "gau", "ffuf", "arjun",
    "masscan", "nmap", "trufflehog", "gitleaks",
)


def _penguin_sha() -> Optional[str]:
    """Best-effort short git SHA of the penguin checkout (None off-git)."""
    try:
        root = Path(__file__).resolve().parent.parent.parent
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=5)
        sha = out.stdout.strip()
        return sha or None
    except Exception:  # noqa - manifest metadata must never break a run
        return None


def _write_manifest(cfg: Config, state: RunState, target: dict, summary: dict,
                    started_at: float, proxy_pool_size: int) -> None:
    """Write <run_dir>/_manifest.json: a redacted snapshot of what this run was
    configured to do, plus rolled-up tool-ledger stats. Never raises."""
    g = cfg.general
    manifest = {
        "target": target,
        "run_dir": str(state.run_dir),
        "penguin_sha": _penguin_sha(),
        "started_at": started_at,
        "ended_at": time.time(),
        "duration_s": round(time.time() - started_at, 1),
        "stages": dict(cfg.stages),
        "net": {
            "profile": g.net_profile,
            "threads": g.threads,
            "rate_limit": g.rate_limit,
            "dns_rate_limit": g.dns_rate_limit,
            "max_parallel_tools": g.max_parallel_tools,
            "max_global_concurrency": g.max_global_concurrency,
        },
        "proxies": {"enabled": cfg.proxies.enabled, "pool_size_at_start": proxy_pool_size},
        "tools_present": {t: shutil.which(t) is not None for t in _MANIFEST_TOOLS},
        "summary": summary,
        "ledger": diagnostics.rollup(diagnostics.read_ledger(state.run_dir)),
    }
    try:
        (state.run_dir / diagnostics.MANIFEST_NAME).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:  # noqa
        logger.debug("[manifest] failed to write", exc_info=True)

ProgressCb = Callable[[int, str, str], None]

# Empty-result shapes matching each run_blockN's own fallback (see the
# `results: dict = {...}` at the top of each run_blockN / its disabled-stage
# return) so a block that raises degrades to exactly what "stage disabled"
# already produces -- downstream `b#["key"]` / `b#.get("key")` lookups never
# KeyError on a failed block.
_BLOCK_FALLBACKS: dict[int, dict] = {
    1: {"subdomains": [], "resolved": [], "live": []},
    2: {"endpoints": [], "js_secrets": [], "api": []},
    3: {"open_db": [], "buckets": []},
    4: {"origin_ips": [], "exposed_git": [], "secrets": []},
}

# Ordered block sequence for run_target's cancel-between-blocks loop below.
_BLOCKS: list[tuple[int, str, Callable]] = [
    (1, "infra", run_block1),
    (2, "web", run_block2),
    (3, "cloud_db", run_block3),
    (4, "elite", run_block4),
]


def _critical_findings(b2: dict, b3: dict, b4: dict) -> dict[str, int]:
    """Non-empty high-severity finding categories across blocks 2-4.

    Returns only categories with a positive count, so callers can treat a
    truthy result as "something worth a critical alert". Kept pure + separate
    from run_target so it is unit-testable without running the pipeline.
    """
    categories = {
        "secrets": len(b2.get("js_secrets", [])) + len(b4.get("secrets", [])),
        "open databases": len(b3.get("open_db", [])),
        "exposed .git": len(b4.get("exposed_git", [])),
        "public buckets": len(b3.get("buckets", [])),
    }
    return {k: n for k, n in categories.items() if n}


def _emit(cb: Optional[ProgressCb], block_num: int, name: str, phase: str) -> None:
    if cb is None:
        return
    try:
        cb(block_num, name, phase)
    except Exception:  # noqa - a UI callback must never break a recon run
        logger.debug("progress_cb raised", exc_info=True)


def _run_block(cfg: Config, state: RunState, target: dict, progress_cb: Optional[ProgressCb],
               block_num: int, name: str, run_fn) -> dict:
    """Run one recon block in isolation.

    `run_parallel` already isolates individual *task* failures inside a
    block, but nothing previously protected the substantial top-level block
    code itself (merges, `read_text`, regex passes) -- an unhandled
    exception there used to abort the whole target, skipping every
    remaining block plus diff/notify/archive/report. Catch it here, log it,
    and degrade to that block's own empty-result shape so the rest of
    `run_target` (and the caller) sees a valid, if partial, result.
    """
    _emit(progress_cb, block_num, name, "start")
    try:
        result = run_fn(cfg, state, target)
    except Exception:
        logger.exception("[block%d:%s] %s unhandled exception -- degrading to empty result",
                          block_num, name, target["value"])
        result = {k: list(v) for k, v in _BLOCK_FALLBACKS[block_num].items()}
    _emit(progress_cb, block_num, name, "done")
    return result


def run_target(cfg: Config, target: dict, progress_cb: Optional[ProgressCb] = None,
               cancel_event: Optional[threading.Event] = None) -> dict:
    started_at = time.time()
    state = RunState(cfg, target["value"])
    logger.info("=== penguin run %s -> %s ===", target["value"], state.run_dir)
    try:
        from ..proxies import get_pool
        proxy_pool_size = len(get_pool(cfg)) if cfg.proxies.enabled else 0
    except Exception:  # noqa
        proxy_pool_size = 0

    # Cancellation is checked between blocks (not mid-block -- individual
    # tool subprocesses can't be cleanly interrupted from here). Once the
    # caller signals cancel_event (e.g. the TUI on quit), stop launching any
    # further blocks; blocks that never ran degrade to the same empty-result
    # shape as a block that raised (see _BLOCK_FALLBACKS), so downstream
    # accumulate/diff/notify/archive/report all still see a valid dict.
    results: dict[int, dict] = {}
    for block_num, name, run_fn in _BLOCKS:
        if cancel_event is not None and cancel_event.is_set():
            logger.info("[%s] cancellation requested -- stopping before block%d:%s",
                        target["value"], block_num, name)
            break
        results[block_num] = _run_block(cfg, state, target, progress_cb, block_num, name, run_fn)
    for block_num, _name, _run_fn in _BLOCKS:
        results.setdefault(block_num, {k: list(v) for k, v in _BLOCK_FALLBACKS[block_num].items()})
    b1, b2, b3, b4 = results[1], results[2], results[3], results[4]

    # accumulate into per-target history files (anew dedup). Wrapped so a
    # failure here (e.g. a corrupt live/httpx.csv) can't skip diff/notify/
    # archive/report for a target whose blocks otherwise succeeded.
    try:
        state.add_lines(ARTIFACTS.ALL_SUBDOMAINS, b1["subdomains"])
        state.add_lines(ARTIFACTS.ALL_URLS, b2.get("endpoints", []))
        # live/httpx.csv rows are "url,input,title,..." (httpx -csv output), not
        # bare URLs -- appending them raw would pollute the accumulator with CSV
        # headers and multi-field rows. Extract just the URL column, same as
        # block2_web.py. Use block1's own return value (`b1["live"]`) instead of
        # re-reading+re-parsing live/httpx.csv from disk -- block1 already read
        # it once to build that return value.
        live_urls = []
        for row in b1.get("live", []):
            m = re.match(r'"??(https?://[^",]+)', row)
            if m:
                live_urls.append(m.group(1).strip('"'))
        # Accumulate under a name distinct from ARTIFACTS.LIVE_HOSTS: that name
        # is the per-run artifact block2/block4 write fresh each run; reusing it
        # here for the cross-run accumulator would make one filename mean two
        # different things depending on which directory you're looking in.
        state.add_lines(ARTIFACTS.ALL_LIVE_HOSTS, live_urls)
    except Exception:
        logger.exception("[%s] failed to accumulate run history", target["value"])

    # self-learning wordlist
    try:
        wm = WordlistManager(cfg)
        wm.learn_from_endpoints(b2.get("endpoints", []) + b1["subdomains"])
    except Exception:
        logger.exception("[%s] wordlist learning failed", target["value"])

    # diff against previous run
    try:
        diff = state.write_diff_files(ARTIFACTS.ALL_SUBDOMAINS)
    except Exception:
        logger.exception("[%s] diff engine failed", target["value"])
        diff = {"new": [], "removed": []}
    if diff["new"]:
        try:
            notify(cfg, f"[{target['value']}] {len(diff['new'])} new subdomains", event="new_subdomains")
        except Exception:
            logger.exception("[%s] notify failed", target["value"])
        logger.info("[diff] %d new subdomains", len(diff["new"]))

    # critical findings notification (gap: `critical_findings` was declared in
    # notify_on but nothing ever emitted it). Alert on the high-severity
    # artifacts the pipeline surfaces: leaked secrets, open databases, exposed
    # .git, and public buckets. notify() itself is gated on notify.enabled +
    # the event being in notify_on, so this is a no-op unless configured.
    hits = _critical_findings(b2, b3, b4)
    if hits:
        detail = ", ".join(f"{n} {k}" for k, n in hits.items())
        logger.warning("[%s] CRITICAL findings: %s", target["value"], detail)
        try:
            notify(cfg, f"[{target['value']}] critical findings: {detail}",
                   level="critical", event="critical_findings")
        except Exception:
            logger.exception("[%s] critical notify failed", target["value"])

    try:
        state.archive()
    except Exception:
        logger.exception("[%s] archive failed", target["value"])

    summary = {
        "target": target["value"],
        "run_dir": str(state.run_dir),
        "subdomains": len(b1["subdomains"]),
        "live": len(b1.get("live", [])),
        "endpoints": len(b2.get("endpoints", [])),
        "js_secrets": len(b2.get("js_secrets", [])),
        "open_db": len(b3.get("open_db", [])),
        "buckets": len(b3.get("buckets", [])),
        "new_subdomains": len(diff["new"]),
        "exposed_git": len(b4.get("exposed_git", [])),
        "secrets": len(b2.get("js_secrets", [])) + len(b4.get("secrets", [])),
    }

    # Typed, severity-ranked findings, accumulated per target with a
    # first_seen_run stamp so the report can show what is new this run for every
    # finding type (not only subdomains). Never let this break the run.
    try:
        from ..findings import FindingStore, derive_findings
        store = FindingStore.for_target(cfg.path("reports"), target["value"])
        derived = derive_findings(target, b1, b2, b3, b4, diff)
        current, new_findings = store.record(derived, state.run_dir.name)
        summary["findings"] = [f.to_dict() for f in current]
        summary["new_findings"] = len(new_findings)
    except Exception:  # noqa
        logger.exception("[%s] findings derivation failed", target["value"])
        summary["findings"] = []
        summary["new_findings"] = 0

    # Per-run manifest (config snapshot + tool presence + rolled-up ledger) so
    # `penguin diagnose <run_dir>` can explain the run without log grepping.
    try:
        _write_manifest(cfg, state, target, summary, started_at, proxy_pool_size)
    except Exception:  # noqa
        logger.debug("[%s] manifest write failed", target["value"], exc_info=True)

    logger.info("=== done %s: %s ===", target["value"], summary)
    # A single machine-parseable line so continuous-mode logs are greppable.
    logger.info("RUN_SUMMARY %s", json.dumps(summary, ensure_ascii=False))
    return summary
