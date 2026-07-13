"""Master orchestrator: ties Block 0..4 together, accumulates state, learns
wordlists, diffs against previous run and notifies on new assets.
"""
from __future__ import annotations

import logging
from pathlib import Path

from ..config import Config
from ..state import RunState
from ..wordlists import WordlistManager
from ..notify import notify
from .block1_infra import run_block1
from .block2_web import run_block2
from .block3_cloud_db import run_block3
from .block4_elite import run_block4

logger = logging.getLogger("penguin.master")


def run_target(cfg: Config, target: dict) -> dict:
    state = RunState(cfg, target["value"])
    logger.info("=== penguin run %s -> %s ===", target["value"], state.run_dir)

    b1 = run_block1(cfg, state, target)
    b2 = run_block2(cfg, state, target)
    b3 = run_block3(cfg, state, target)
    b4 = run_block4(cfg, state, target)

    # accumulate into per-target history files (anew dedup)
    state.add_lines("all_subdomains.txt", b1["subdomains"])
    state.add_lines("all_urls.txt", b2.get("endpoints", []))
    state.add_lines("live_hosts.txt", state.read_lines("live/httpx.csv"))

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
