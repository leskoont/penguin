"""HTTP probing / fingerprinting wrappers (Block 1.3, Block 2.1)."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from ._base import ToolContext, ok_path

logger = logging.getLogger("penguin.tools.probe")


def _suspiciously_empty(in_file: Path, out_file: Path, *, has_header: bool = False) -> bool:
    """True if a bulk multi-target probe came back with (near-)nothing despite
    a non-trivial input list. httpx exits 0 no matter how many individual
    targets it actually reached, so a single dead proxy picked for the whole
    invocation (config.tools.httpx.proxy=true passes one -proxy flag for
    every target inside) can silently zero out the hit rate with no failure
    signal for ctx.execute's own retry logic to react to.
    """
    try:
        n_in = sum(1 for l in in_file.read_text(encoding="utf-8").splitlines() if l.strip())
    except OSError:
        return False
    if n_in < 5:
        return False  # too small a batch for a hit-rate heuristic to be meaningful
    try:
        n_out = sum(1 for l in out_file.read_text(encoding="utf-8").splitlines() if l.strip())
    except OSError:
        return True
    return n_out <= (1 if has_header else 0)


def httpx(ctx: ToolContext, in_file: Path, out_csv: Path, screenshots_dir: Optional[Path] = None) -> Optional[Path]:
    cmd = ["httpx", "-l", str(in_file), "-silent", "-threads", str(ctx.cfg.general.threads),
           "-title", "-sc", "-status-code", "-td", "-tech-detect", "-ip", "-cname",
           "-cdn", "-server", "-asn", "-favicon", "-csv", "-o", str(out_csv)]
    if screenshots_dir:
        cmd += ["-screenshot", "-srd", str(screenshots_dir)]
    r = ctx.execute("httpx", cmd, timeout=900, log_stdout=False)
    if r.ok and ctx.proxy_applies("httpx") and _suspiciously_empty(in_file, out_csv, has_header=True):
        logger.warning("[httpx] %s targets in, ~0 results out -- retrying once with a fresh proxy", in_file)
        r = ctx.execute("httpx", cmd, timeout=900, log_stdout=False)
    return ok_path(r, out_csv)


def httpx_simple(ctx: ToolContext, in_file: Path, out: Path) -> Optional[Path]:
    cmd = ["httpx", "-l", str(in_file), "-silent", "-threads", str(ctx.cfg.general.threads), "-o", str(out)]
    r = ctx.execute("httpx", cmd, timeout=600)
    if r.ok and ctx.proxy_applies("httpx") and _suspiciously_empty(in_file, out):
        logger.warning("[httpx] %s targets in, ~0 results out -- retrying once with a fresh proxy", in_file)
        r = ctx.execute("httpx", cmd, timeout=600)
    return ok_path(r, out)


def nuclei_tech(ctx: ToolContext, in_file: Path, out: Path) -> Optional[Path]:
    # nuclei-templates' current layout nests everything under http/ (verified
    # live against the repo) -- a bare "technologies/" matches nothing, so
    # nuclei ran with zero loaded templates every time ("no templates
    # provided for scan") instead of actually fingerprinting anything.
    cmd = ["nuclei", "-l", str(in_file), "-t", "http/technologies/", "-o", str(out)]
    r = ctx.execute("nuclei", cmd, timeout=600)
    return ok_path(r, out)
