"""HTTP probing / fingerprinting wrappers (Block 1.3, Block 2.1)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext


def httpx(ctx: ToolContext, in_file: Path, out_csv: Path, screenshots_dir: Optional[Path] = None) -> Optional[Path]:
    cmd = ["httpx", "-l", str(in_file), "-silent", "-threads", str(ctx.cfg.general.threads),
           "-title", "-sc", "-status-code", "-td", "-tech-detect", "-ip", "-cname",
           "-cdn", "-server", "-asn", "-favicon", "-csv", "-o", str(out_csv)]
    if screenshots_dir:
        cmd += ["-screenshot", "-srd", str(screenshots_dir)]
    r = ctx.execute("httpx", cmd, timeout=900, log_stdout=False)
    return out_csv if out_csv.exists() else None


def httpx_simple(ctx: ToolContext, in_file: Path, out: Path) -> Optional[Path]:
    cmd = ["httpx", "-l", str(in_file), "-silent", "-threads", str(ctx.cfg.general.threads), "-o", str(out)]
    r = ctx.execute("httpx", cmd, timeout=600)
    return out if out.exists() else None


def nuclei_tech(ctx: ToolContext, in_file: Path, out: Path) -> Optional[Path]:
    cmd = ["nuclei", "-l", str(in_file), "-t", "technologies/", "-o", str(out)]
    r = ctx.execute("nuclei", cmd, timeout=600)
    return out if out.exists() else None
