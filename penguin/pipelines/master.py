"""Master orchestrator: ties Block 0..4 together, accumulates state, learns
wordlists, diffs against previous run and notifies on new assets.
"""
from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Callable, Optional

from ..config import Config
from ..state import ARTIFACTS, RunState
from ..wordlists import WordlistManager
from ..notify import notify
from .block1_infra import run_block1
from .block2_web import run_block2
from .block3_cloud_db import run_block3
from .block4_elite import run_block4

logger = logging.getLogger("penguin.master")

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
    state = RunState(cfg, target["value"])
    logger.info("=== penguin run %s -> %s ===", target["value"], state.run_dir)

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
    }
    logger.info("=== done %s: %s ===", target["value"], summary)
    return summary
