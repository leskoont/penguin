"""Nuclei vulnerability scanning wrapper (Block 4.4, Block 5 feedback)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from ._base import ToolContext, ok_path

TEMPLATES_DIR = "config/templates"

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def nuclei_scan(ctx: ToolContext, in_file: Path, out: Path, *,
                severity: str = "high,critical", custom_only: bool = False,
                rate_limit: int = 100, concurrency: int = 40) -> Optional[Path]:
    cmd = ["nuclei", "-l", str(in_file), "-severity", severity,
           "-rl", str(rate_limit), "-c", str(concurrency), "-jsonl", "-o", str(out)]
    if custom_only:
        cmd += ["-t", str(ctx.cfg.path(TEMPLATES_DIR))]
    else:
        # nuclei-templates' current layout: everything lives under http/, and
        # it's "misconfiguration" (singular) -- the old "cves/"/"misconfigurations/"
        # paths matched nothing, so a non-custom_only scan silently loaded zero
        # official templates every run.
        cmd += ["-t", "http/cves/", "-t", "http/misconfiguration/", "-t", str(ctx.cfg.path(TEMPLATES_DIR))]
    r = ctx.execute("nuclei", cmd, timeout=3600, log_stdout=False)
    return ok_path(r, out)


def nuclei_update(ctx: ToolContext) -> bool:
    # ctx.execute's first arg is only the proxy/threads lookup key -- the
    # actual argv is the second arg and must include the binary name itself.
    # Without it, runner.run() took "-update-templates" as cmd[0], couldn't
    # find that "binary" on PATH, and skipped -- so the official templates
    # dir (needed by probe.nuclei_tech's -t http/technologies/) was never
    # fetched and its scans always failed with "Could not find template".
    r = ctx.execute("nuclei", ["nuclei", "-update-templates"], timeout=300)
    return r.ok


def nuclei_cves(ctx: ToolContext, in_file: Path, out: Path, *,
                rate_limit: int = 100, concurrency: int = 40) -> Optional[Path]:
    """Official CVE-template scan, run only when the knowledge bank flagged a
    detected technology as vulnerable (block5's data-driven re-run)."""
    cmd = ["nuclei", "-l", str(in_file), "-t", "http/cves/",
           "-severity", "medium,high,critical",
           "-rl", str(rate_limit), "-c", str(concurrency), "-jsonl", "-o", str(out)]
    r = ctx.execute("nuclei", cmd, timeout=3600, log_stdout=False)
    return ok_path(r, out)


def parse_nuclei_jsonl(path: Path) -> list[dict]:
    """Findings from a nuclei ``-jsonl`` output.

    Returns one dict per finding: ``{template_id, cve, host, name, severity,
    matcher_status}``. Torn/malformed lines (crash mid-write) are skipped."""
    if not path or not path.exists():
        return []
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(rec, dict):
            continue
        info = rec.get("info") if isinstance(rec.get("info"), dict) else {}
        cls = info.get("classification")
        cve_field = cls.get("cve-id", "") if isinstance(cls, dict) else ""
        tid = str(rec.get("template-id") or rec.get("templateID") or
                  info.get("name") or "")
        cves = _CVE_ID_RE.findall(tid + " " + str(cve_field))
        out.append({
            "template_id": tid,
            "cve": cves[0].upper() if cves else "",
            "host": str(rec.get("host") or rec.get("matched") or ""),
            "name": str(info.get("name") or ""),
            "severity": str(info.get("severity") or "info").lower(),
            "matcher_status": bool(rec.get("matcher-status", True)),
        })
    return out
