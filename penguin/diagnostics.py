"""penguin - run diagnostics.

Reads the per-run tool ledger (``_tool_ledger.jsonl``) and manifest
(``_manifest.json``) that the pipeline writes, and rolls them up so
"why did this run produce N results?" is answerable from machine-readable
artifacts instead of by grepping the live log. Shared by master.py (which
writes the manifest) and the ``penguin diagnose`` command.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("penguin.diagnostics")

LEDGER_NAME = "_tool_ledger.jsonl"
MANIFEST_NAME = "_manifest.json"

# Outcome labels emitted by tools._base.classify_outcome, in report order.
OUTCOMES = ("ok", "empty", "timeout", "permanent", "missing", "skipped_no_proxy", "error")


def read_ledger(run_dir: Path) -> list[dict]:
    """Return the ledger records for a run dir (empty list if none/malformed)."""
    path = Path(run_dir) / LEDGER_NAME
    if not path.exists():
        return []
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            # A torn last line (crash mid-write) must not sink the whole report.
            logger.debug("[diagnostics] skipping malformed ledger line")
            continue
        if isinstance(rec, dict):  # ignore valid-JSON-but-non-object lines
            records.append(rec)
    return records


def rollup(records: list[dict]) -> dict:
    """Aggregate ledger records per tool and overall.

    Returns::

        {
          "per_tool": {tool: {"calls": n, "ok": n, "timeout": n, ...,
                              "duration": float, "attempts": n}},
          "totals":   {"calls": n, <outcome>: n, ..., "duration": float},
        }
    """
    per_tool: dict[str, dict] = {}
    totals: dict[str, float] = {"calls": 0, "duration": 0.0, "attempts": 0}
    for o in OUTCOMES:
        totals[o] = 0
    for rec in records:
        tool = str(rec.get("tool", "?"))
        outcome = str(rec.get("outcome", "error"))
        if outcome not in OUTCOMES:
            outcome = "error"
        t = per_tool.setdefault(
            tool,
            {"calls": 0, "duration": 0.0, "attempts": 0, **{o: 0 for o in OUTCOMES}},
        )
        t["calls"] += 1
        t[outcome] += 1
        t["duration"] += float(rec.get("duration", 0.0) or 0.0)
        t["attempts"] += int(rec.get("attempts", 0) or 0)
        totals["calls"] += 1
        totals[outcome] += 1
        totals["duration"] += float(rec.get("duration", 0.0) or 0.0)
        totals["attempts"] += int(rec.get("attempts", 0) or 0)
    totals["duration"] = round(totals["duration"], 3)
    for t in per_tool.values():
        t["duration"] = round(t["duration"], 3)
    return {"per_tool": per_tool, "totals": totals}


def read_manifest(run_dir: Path) -> Optional[dict]:
    path = Path(run_dir) / MANIFEST_NAME
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def subdomain_sources(run_dir: Path) -> dict[str, int]:
    """Per-source subdomain line counts from block1's per-tool output files.

    Answers "which source contributed how many names" directly from the files
    on disk (subfinder_*.txt, amass_*.txt, crtsh_*.txt, puredns_brute_*.txt,
    gotator_resolved.txt, ...). This is the crux of the recon-degradation
    investigation, complementing the ledger's per-tool outcome view.
    """
    sub_dir = Path(run_dir) / "subdomains"
    if not sub_dir.is_dir():
        return {}
    counts: dict[str, int] = {}
    for f in sorted(sub_dir.glob("*.txt")):
        # Skip the merged/seed helper files -- they are inputs, not sources.
        if f.name in {"all_for_perms.txt", "brute_wordlist.txt", "perm_words.txt"}:
            continue
        try:
            n = sum(1 for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip())
        except OSError:
            n = 0
        counts[f.name] = n
    return counts
