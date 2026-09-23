"""Subdomain-takeover detection (Block 1).

A dangling DNS record pointing at a de-provisioned third-party service (S3,
GitHub Pages, Heroku, ...) can be claimed by an attacker. We detect it with
nuclei's ``http/takeovers/`` template set -- no extra binary beyond nuclei,
which the pipeline already depends on -- and, if present, the dedicated
``subzy`` scanner as a second opinion.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from ._base import ToolContext, ok_path

logger = logging.getLogger("penguin.tools.takeover")


def nuclei_takeover(ctx: ToolContext, in_file: Path, out: Path) -> Optional[Path]:
    """Run nuclei's takeover templates over a host list, JSONL to ``out``."""
    rate = ctx.cfg.general.rate_limit
    cmd = ["nuclei", "-l", str(in_file), "-t", "http/takeovers/",
           "-rl", str(rate), "-c", "25", "-jsonl", "-o", str(out)]
    r = ctx.execute("nuclei", cmd, timeout=900)
    return ok_path(r, out)


def subzy_takeover(ctx: ToolContext, in_file: Path, out: Path) -> Optional[Path]:
    """Run subzy (if installed) over a host list, writing plain output."""
    cmd = ["subzy", "run", "--targets", str(in_file), "--hide_fails", "--output", str(out)]
    r = ctx.execute("subzy", cmd, timeout=900)
    return ok_path(r, out)


def parse_nuclei_takeovers(out: Path) -> list[str]:
    """Extract the vulnerable hosts from nuclei JSONL takeover output.

    nuclei jsonl rows carry the affected asset under ``host`` (or
    ``matched-at``); return the deduped list of those assets. Malformed lines
    are skipped so a torn file never sinks the whole parse."""
    if not out.exists():
        return []
    hosts: list[str] = []
    seen: set[str] = set()
    for line in out.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            continue
        asset = row.get("host") or row.get("matched-at") or row.get("matched_at")
        if asset and asset not in seen:
            seen.add(asset)
            hosts.append(asset)
    return hosts
