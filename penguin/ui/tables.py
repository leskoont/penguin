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
                "open_db", "buckets", "new_subdomains", "exposed_git"):
        t.add_row(key, str(summary.get(key, 0)))
    return t
