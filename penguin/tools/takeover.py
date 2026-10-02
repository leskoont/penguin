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
import re
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
        if not isinstance(row, dict):
            continue  # a valid-JSON but non-object line (list/str/number)
        asset = row.get("host") or row.get("matched-at") or row.get("matched_at")
        if asset and asset not in seen:
            seen.add(asset)
            hosts.append(asset)
    return hosts


def parse_subzy(out: Path) -> list[str]:
    """Extract VULNERABLE subdomains from subzy ``--output``.

    subzy's output format varies by version: recent builds write a JSON array of
    objects (keys like ``subdomain``/``status``, capitalization differs across
    versions), older ones a plain ``[ VULNERABLE ] https://host`` text line. Parse
    both, keep only entries whose status is VULNERABLE (never ``NOT VULNERABLE``),
    and return the deduped assets. Malformed content never raises."""
    if not out.exists():
        return []
    text = out.read_text(encoding="utf-8", errors="ignore")
    hosts: list[str] = []
    seen: set[str] = set()

    def _add(h: str) -> None:
        h = (h or "").strip()
        if h and h not in seen:
            seen.add(h)
            hosts.append(h)

    stripped = text.strip()
    parsed_json = False
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
            parsed_json = True
        except (ValueError, TypeError):
            parsed_json = False
        if parsed_json and isinstance(data, list):
            for row in data:
                if not isinstance(row, dict):
                    continue
                low = {str(k).lower(): v for k, v in row.items()}
                status = str(low.get("status", "")).upper()
                if "VULNERABLE" in status and "NOT" not in status:
                    _add(str(low.get("subdomain") or low.get("host")
                             or low.get("target") or ""))
    if not parsed_json:
        for line in text.splitlines():
            up = line.upper()
            if "VULNERABLE" not in up or "NOT VULNERABLE" in up:
                continue
            m = re.search(r"https?://[^\s\]\)]+", line) or re.search(
                r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+", line)
            if m:
                _add(m.group(0))
    return hosts
