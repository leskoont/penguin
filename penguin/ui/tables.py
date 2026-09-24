"""Rich table builders for CLI output."""
from __future__ import annotations

from rich.table import Table


def install_check_table(results: list[tuple[str, bool]]) -> Table:
    t = Table(title="penguin install-check")
    t.add_column("tool")
    t.add_column("status")
    for name, present in results:
        t.add_row(name, "[green]present[/]" if present else "[red]MISSING[/]")
    return t


def url_check_table(results: list[tuple[str, bool, str | None]]) -> Table:
    t = Table(title="penguin download-URL liveness check")
    t.add_column("URL")
    t.add_column("status")
    for label, is_alive, error in results:
        if is_alive:
            t.add_row(label, "[green]OK[/]")
        else:
            t.add_row(label, f"[red]DEAD[/] ({error})")
    return t


def summary_table(target: str, summary: dict) -> Table:
    t = Table(title=f"penguin run summary - {target}")
    t.add_column("metric")
    t.add_column("count", justify="right")
    for key in ("subdomains", "live", "endpoints", "js_secrets",
                "open_db", "buckets", "new_subdomains", "exposed_git", "secrets",
                "takeovers", "web_issues"):
        t.add_row(key, str(summary.get(key, 0)))
    return t


def ledger_table(rollup: dict) -> Table:
    """Per-tool outcome table from a diagnostics.rollup() result."""
    t = Table(title="tool outcomes (from _tool_ledger.jsonl)")
    t.add_column("tool")
    t.add_column("calls", justify="right")
    t.add_column("ok", justify="right")
    t.add_column("timeout", justify="right")
    t.add_column("missing", justify="right")
    t.add_column("permanent", justify="right")
    t.add_column("error", justify="right")
    t.add_column("no_proxy", justify="right")
    t.add_column("sec", justify="right")
    per_tool = rollup.get("per_tool", {})
    for tool in sorted(per_tool):
        s = per_tool[tool]

        def _c(n: int, color: str) -> str:
            return f"[{color}]{n}[/]" if n else "0"

        t.add_row(
            tool,
            str(s.get("calls", 0)),
            _c(s.get("ok", 0), "green"),
            _c(s.get("timeout", 0), "yellow"),
            _c(s.get("missing", 0), "red"),
            _c(s.get("permanent", 0), "red"),
            _c(s.get("error", 0), "red"),
            _c(s.get("skipped_no_proxy", 0), "yellow"),
            f"{s.get('duration', 0.0):.0f}",
        )
    tot = rollup.get("totals", {})
    if tot:
        t.add_section()
        t.add_row("TOTAL", str(tot.get("calls", 0)),
                  str(tot.get("ok", 0)), str(tot.get("timeout", 0)),
                  str(tot.get("missing", 0)), str(tot.get("permanent", 0)),
                  str(tot.get("error", 0)), str(tot.get("skipped_no_proxy", 0)),
                  f"{tot.get('duration', 0.0):.0f}")
    return t


def sources_table(counts: dict) -> Table:
    """Per-source subdomain contribution; zero-output sources flagged red."""
    t = Table(title="subdomain contribution by source")
    t.add_column("source file")
    t.add_column("names", justify="right")
    for name in sorted(counts, key=lambda k: (-counts[k], k)):
        n = counts[name]
        t.add_row(name, f"[green]{n}[/]" if n else "[red]0[/]")
    return t
