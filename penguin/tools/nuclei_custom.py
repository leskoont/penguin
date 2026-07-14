"""Nuclei vulnerability scanning wrapper (Block 4.4, master pipeline)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext

TEMPLATES_DIR = "config/templates"


def nuclei_scan(ctx: ToolContext, in_file: Path, out: Path, *,
                severity: str = "high,critical", custom_only: bool = False,
                rate_limit: int = 100, concurrency: int = 40) -> Optional[Path]:
    cmd = ["nuclei", "-l", str(in_file), "-severity", severity,
           "-rl", str(rate_limit), "-c", str(concurrency), "-jsonl", "-o", str(out)]
    if custom_only:
        cmd += ["-t", str(ctx.cfg.path(TEMPLATES_DIR))]
    else:
        cmd += ["-t", "cves/", "-t", "misconfigurations/", "-t", str(ctx.cfg.path(TEMPLATES_DIR))]
    r = ctx.execute("nuclei", cmd, timeout=3600, log_stdout=False)
    return out if out.exists() else None


def nuclei_update(ctx: ToolContext) -> bool:
    # ctx.execute's first arg is only the proxy/threads lookup key -- the
    # actual argv is the second arg and must include the binary name itself.
    # Without it, runner.run() took "-update-templates" as cmd[0], couldn't
    # find that "binary" on PATH, and skipped -- so the official templates
    # dir (needed by probe.nuclei_tech's -t technologies/) was never fetched
    # and its scans always failed with "Could not find template".
    r = ctx.execute("nuclei", ["nuclei", "-update-templates"], timeout=300)
    return r.ok
