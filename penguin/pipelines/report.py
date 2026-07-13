"""Report generation: per-target Markdown + JSON summary."""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from ..config import Config
from ..state import RunState

logger = logging.getLogger("penguin.report")


def build_report(cfg: Config, target: dict, summary: dict) -> Path:
    reports_dir = cfg.path("reports", str(target["value"]))
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    md = reports_dir / f"{ts}_report.md"
    js = reports_dir / f"{ts}_report.json"

    md_text = [
        f"# penguin recon report - {target['value']}",
        f"_generated: {datetime.now().isoformat()}_",
        "",
        "## Summary",
        f"- Subdomains discovered: **{summary['subdomains']}**",
        f"- Live hosts (httpx): **{summary['live']}**",
        f"- JS endpoints extracted: **{summary['endpoints']}**",
        f"- JS secrets hits: **{summary['js_secrets']}**",
        f"- Open DB services: **{summary['open_db']}**",
        f"- Cloud buckets found: **{summary['buckets']}**",
        f"- New subdomains vs previous run: **{summary['new_subdomains']}**",
        f"- Exposed .git repos: **{summary['exposed_git']}**",
        "",
        f"Artifacts: `{summary['run_dir']}`",
        "",
        "## Next steps",
        "1. Manually verify open DB / bucket findings (honeypots exist).",
        "2. Review JS secrets hits; confirm validity before reporting.",
        "3. Chain: exposed .git -> source -> API endpoints -> hidden params -> IDOR.",
        "",
    ]
    md.write_text("\n".join(md_text), encoding="utf-8")
    js.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    logger.info("[report] wrote %s", md)
    return md
