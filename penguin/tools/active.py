"""Opt-in ACTIVE vuln scanning (Block 2, only when config.general.active).

These tools send crafted payloads to the target, so they are gated behind the
explicit --active switch and must only be used in authorized scope. Missing
binaries are skipped non-fatally like every other wrapper.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from ._base import ToolContext, ok_path

logger = logging.getLogger("penguin.tools.active")


def dalfox_file(ctx: ToolContext, urls_file: Path, out: Path) -> Optional[Path]:
    """Run dalfox over a file of parameterized URLs, JSONL results to ``out``."""
    rate = ctx.cfg.general.rate_limit
    cmd = ["dalfox", "file", str(urls_file), "--format", "jsonl",
           "--delay", "0", "--worker", str(max(1, ctx.cfg.general.clamp_workers(rate // 10))),
           "-o", str(out), "--silence", "--no-color"]
    r = ctx.execute("dalfox", cmd, timeout=1800)
    return ok_path(r, out)


def nuclei_fuzz(ctx: ToolContext, hosts_file: Path, out: Path) -> Optional[Path]:
    """Run nuclei DAST/fuzzing templates over live hosts (active)."""
    rate = ctx.cfg.general.rate_limit
    cmd = ["nuclei", "-l", str(hosts_file), "-dast",
           "-rl", str(rate), "-c", "25", "-jsonl", "-o", str(out)]
    r = ctx.execute("nuclei", cmd, timeout=1800)
    return ok_path(r, out)


def parse_dalfox(out: Path) -> list[str]:
    """Extract vulnerable URLs from dalfox JSONL (deduped)."""
    if not out.exists():
        return []
    hits: list[str] = []
    seen: set[str] = set()
    for line in out.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(row, dict):
            continue
        url = row.get("data") or row.get("url") or row.get("evidence")
        if url and url not in seen:
            seen.add(url)
            hits.append(str(url))
    return hits
