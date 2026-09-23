"""Report generation: per-target Markdown + JSON + self-contained HTML.

The Markdown/HTML reports group typed findings by severity and list the actual
assets (new subdomains, secret hits, bucket URLs, open-DB artifacts, exposed
.git), plus a recon-coverage section rolled up from the run's tool ledger.
"""
from __future__ import annotations

import html
import json
import logging
import re
from datetime import datetime
from pathlib import Path

from .. import diagnostics
from ..config import Config
from ..findings import SEVERITY_ORDER, Finding

logger = logging.getLogger("penguin.report")

_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _sanitize_slug(s: str) -> str:
    """Replace Windows-illegal filename characters with underscores."""
    return re.sub(r"[^a-z0-9._-]", "_", s.lower())


def _load_findings(summary: dict) -> list[Finding]:
    out: list[Finding] = []
    for d in summary.get("findings", []) or []:
        try:
            out.append(Finding.from_dict(d))
        except (ValueError, TypeError):
            continue
    return out


def _group_by_severity(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.severity, []).append(f)
    return grouped


def _findings_markdown(findings: list[Finding], run_id: str) -> list[str]:
    if not findings:
        return ["## Findings", "", "_No typed findings this run._", ""]
    lines = ["## Findings", ""]
    grouped = _group_by_severity(findings)
    for sev in sorted(grouped, key=lambda s: SEVERITY_ORDER.get(s, 99)):
        items = grouped[sev]
        lines.append(f"### {_SEV_EMOJI.get(sev, '')} {sev.upper()} ({len(items)})")
        lines.append("")
        for f in sorted(items, key=lambda x: (x.type, x.asset)):
            is_new = f.first_seen_run == run_id
            tag = " **[new]**" if is_new else ""
            asset = f.url or f.asset
            detail = f" — {f.evidence}" if f.evidence else ""
            src = f" _(via {f.source_tool})_" if f.source_tool else ""
            lines.append(f"- `{f.type}`{tag}: {asset}{detail}{src}")
        lines.append("")
    return lines


def _coverage_markdown(run_dir: str) -> list[str]:
    rd = Path(run_dir)
    roll = diagnostics.rollup(diagnostics.read_ledger(rd))
    tot = roll.get("totals", {})
    if not tot.get("calls"):
        return []
    lines = ["## Recon coverage", ""]
    lines.append(f"- Tool invocations: **{tot.get('calls', 0)}** "
                 f"(ok {tot.get('ok', 0)}, timeout {tot.get('timeout', 0)}, "
                 f"missing {tot.get('missing', 0)}, "
                 f"hard-fail {tot.get('permanent', 0) + tot.get('error', 0)})")
    problem = [t for t, s in roll.get("per_tool", {}).items()
               if (s.get("timeout") or s.get("missing") or s.get("permanent") or s.get("error"))]
    if problem:
        lines.append(f"- Tools with failures/timeouts: {', '.join(sorted(problem))}")
    sources = diagnostics.subdomain_sources(rd)
    zero = sorted(s for s, n in sources.items() if not n)
    if zero:
        lines.append(f"- Zero-output subdomain sources: {', '.join(zero)}")
    lines.append(f"- Run `penguin diagnose {run_dir}` for the full breakdown.")
    lines.append("")
    return lines


def _html_report(target: str, summary: dict, findings: list[Finding], run_id: str) -> str:
    def esc(s: str) -> str:
        return html.escape(str(s))

    rows = []
    for f in sorted(findings, key=lambda x: (SEVERITY_ORDER.get(x.severity, 99), x.type, x.asset)):
        new = " (new)" if f.first_seen_run == run_id else ""
        rows.append(
            f"<tr class='{esc(f.severity)}'><td>{esc(f.severity)}</td>"
            f"<td>{esc(f.type)}{new}</td><td>{esc(f.url or f.asset)}</td>"
            f"<td>{esc(f.evidence)}</td><td>{esc(f.source_tool)}</td></tr>"
        )
    findings_html = "\n".join(rows) or "<tr><td colspan='5'>No typed findings.</td></tr>"
    metrics = "".join(
        f"<li>{esc(k)}: <b>{esc(summary.get(k, 0))}</b></li>"
        for k in ("subdomains", "live", "endpoints", "js_secrets", "open_db",
                  "buckets", "new_subdomains", "exposed_git", "secrets")
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>penguin report - {esc(target)}</title>
<style>
 body{{font-family:system-ui,Arial,sans-serif;margin:2rem;max-width:1000px}}
 table{{border-collapse:collapse;width:100%}}
 th,td{{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;font-size:.9rem}}
 th{{background:#f4f4f4}}
 tr.critical td:first-child{{color:#b00020;font-weight:bold}}
 tr.high td:first-child{{color:#d35400;font-weight:bold}}
 tr.medium td:first-child{{color:#b7950b}}
 tr.info td:first-child{{color:#555}}
 ul{{columns:2}}
</style></head><body>
<h1>penguin recon report — {esc(target)}</h1>
<p><i>generated {esc(datetime.now().isoformat(timespec='seconds'))}</i></p>
<h2>Summary</h2><ul>{metrics}</ul>
<h2>Findings ({len(findings)})</h2>
<table><thead><tr><th>severity</th><th>type</th><th>asset</th><th>evidence</th><th>source</th></tr></thead>
<tbody>{findings_html}</tbody></table>
<p style="color:#777">Artifacts: {esc(summary.get('run_dir', ''))}</p>
</body></html>
"""


def build_report(cfg: Config, target: dict, summary: dict) -> Path:
    target_safe = _sanitize_slug(str(target["value"]))
    reports_dir = cfg.path("reports", target_safe)
    reports_dir.mkdir(parents=True, exist_ok=True)
    # Use microsecond precision to avoid timestamp collisions at 1-second resolution.
    base_ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    md = reports_dir / f"{base_ts}_report.md"
    js = reports_dir / f"{base_ts}_report.json"
    htmlf = reports_dir / f"{base_ts}_report.html"

    counter = 0
    while md.exists() or js.exists() or htmlf.exists():
        counter += 1
        ts = f"{base_ts}_{counter}"
        md = reports_dir / f"{ts}_report.md"
        js = reports_dir / f"{ts}_report.json"
        htmlf = reports_dir / f"{ts}_report.html"

    findings = _load_findings(summary)
    run_dir = summary.get("run_dir", "")
    run_id = Path(run_dir).name if run_dir else ""

    md_text = [
        f"# penguin recon report - {target['value']}",
        f"_generated: {datetime.now().isoformat()}_",
        "",
        "## Summary",
        f"- Subdomains discovered: **{summary.get('subdomains', 0)}**",
        f"- Live hosts (httpx): **{summary.get('live', 0)}**",
        f"- JS endpoints extracted: **{summary.get('endpoints', 0)}**",
        f"- JS secrets hits: **{summary.get('js_secrets', 0)}**",
        f"- Open DB services: **{summary.get('open_db', 0)}**",
        f"- Cloud buckets found: **{summary.get('buckets', 0)}**",
        f"- New subdomains vs previous run: **{summary.get('new_subdomains', 0)}**",
        f"- Exposed .git repos: **{summary.get('exposed_git', 0)}**",
        f"- Secrets (JS + git/CI): **{summary.get('secrets', 0)}**",
        f"- New findings this run: **{summary.get('new_findings', 0)}**",
        "",
    ]
    md_text += _findings_markdown(findings, run_id)
    md_text += _coverage_markdown(run_dir) if run_dir else []
    md_text += [
        f"Artifacts: `{summary.get('run_dir', '')}`",
        "",
        "## Next steps",
        "1. Manually verify open DB / bucket findings (honeypots exist).",
        "2. Review JS/git secrets hits; confirm validity before reporting.",
        "3. Chain: exposed .git -> source -> API endpoints -> hidden params -> IDOR.",
        "",
    ]
    md.write_text("\n".join(md_text), encoding="utf-8")
    js.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    try:
        htmlf.write_text(_html_report(target["value"], summary, findings, run_id), encoding="utf-8")
    except Exception:  # noqa - HTML is a bonus; never fail the run over it
        logger.debug("[report] HTML render failed", exc_info=True)
    logger.info("[report] wrote %s", md)
    return md
