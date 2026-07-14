"""Master orchestrator: ties Block 0..4 together, accumulates state, learns
wordlists, diffs against previous run and notifies on new assets.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Callable, Optional

from ..config import Config
from ..state import RunState
from ..wordlists import WordlistManager
from ..notify import notify
from .block1_infra import run_block1
from .block2_web import run_block2
from .block3_cloud_db import run_block3
from .block4_elite import run_block4

logger = logging.getLogger("penguin.master")

ProgressCb = Callable[[int, str, str], None]


def _emit(cb: Optional[ProgressCb], block_num: int, name: str, phase: str) -> None:
    if cb is None:
        return
    try:
        cb(block_num, name, phase)
    except Exception:  # noqa - a UI callback must never break a recon run
        logger.debug("progress_cb raised", exc_info=True)


def run_target(cfg: Config, target: dict, progress_cb: Optional[ProgressCb] = None) -> dict:
    state = RunState(cfg, target["value"])
    logger.info("=== penguin run %s -> %s ===", target["value"], state.run_dir)

    _emit(progress_cb, 1, "infra", "start")
    b1 = run_block1(cfg, state, target)
    _emit(progress_cb, 1, "infra", "done")

    _emit(progress_cb, 2, "web", "start")
    b2 = run_block2(cfg, state, target)
    _emit(progress_cb, 2, "web", "done")

    _emit(progress_cb, 3, "cloud_db", "start")
    b3 = run_block3(cfg, state, target)
    _emit(progress_cb, 3, "cloud_db", "done")

    _emit(progress_cb, 4, "elite", "start")
    b4 = run_block4(cfg, state, target)
    _emit(progress_cb, 4, "elite", "done")

    # accumulate into per-target history files (anew dedup)
    state.add_lines("all_subdomains.txt", b1["subdomains"])
    state.add_lines("all_urls.txt", b2.get("endpoints", []))
    # live/httpx.csv rows are "url,input,title,..." (httpx -csv output), not
    # bare URLs -- appending them raw would pollute live_hosts.txt (which
    # block2/block4 treat as a clean URL-per-line list) with CSV headers and
    # multi-field rows. Extract just the URL column, same as block2_web.py.
    live_urls = []
    for row in state.read_lines("live/httpx.csv"):
        m = re.match(r'"??(https?://[^",]+)', row)
        if m:
            live_urls.append(m.group(1).strip('"'))
    state.add_lines("live_hosts.txt", live_urls)

    # self-learning wordlist
    wm = WordlistManager(cfg)
    wm.learn_from_endpoints(b2.get("endpoints", []) + b1["subdomains"])

    # diff against previous run
    diff = state.write_diff_files("all_subdomains.txt")
    if diff["new"]:
        notify(cfg, f"[{target['value']}] {len(diff['new'])} new subdomains", event="new_subdomains")
        logger.info("[diff] %d new subdomains", len(diff["new"]))

    state.archive()
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
