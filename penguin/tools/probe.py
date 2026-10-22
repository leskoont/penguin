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


# Common alternate web ports beyond 80/443 (deep tier): dev/admin panels and
# staging apps routinely live here and never show up in the standard probe.
ALT_WEB_PORTS = "81,3000,5000,8000,8008,8081,8080,8443,8888,9000,9090"

# Hard ceiling on alt-port probe targets (hosts x ports). SLIRP-safety: the
# standard httpx pass is bounded by the host count; multiplying by 11 ports
# unbounded would multiply the connection bursts the same way. Pairs beyond
# the cap are dropped (hosts are walked first, so every host gets its first
# ports before any host gets extra depth).
ALT_PORT_MAX_TARGETS = 600


def alt_port_targets(hosts: list[str], ports: str = ALT_WEB_PORTS, *,
                     max_targets: int = ALT_PORT_MAX_TARGETS) -> list[str]:
    """Build the ``host:port`` pair list for the deep alt-port probe.

    Ports any existing URL port is stripped (we probe the hostname fresh), and
    the total is capped at ``max_targets``. Pure, so the pairing/capping is
    unit-testable without touching the network."""
    import re as _re
    plist = [p.strip() for p in (ports or "").split(",") if p.strip().isdigit()]
    seen: set[str] = set()
    out: list[str] = []
    for h in hosts or []:
        host = _re.sub(r"^https?://", "", str(h)).split("/")[0].split(":")[0].strip()
        if not host:
            continue
        for p in plist:
            pair = f"{host}:{p}"
            if pair not in seen:
                seen.add(pair)
                out.append(pair)
                if len(out) >= max_targets:
                    return out
    return out


def httpx_ports(ctx: ToolContext, pairs_file: Path, out_csv: Path, *,
                threads: Optional[int] = None) -> Optional[Path]:
    """Probe pre-built ``host:port`` pairs (deep tier).

    Callers generate the pairs with :func:`alt_port_targets` (capped) rather
    than relying on httpx's ``-ports`` flag, which is version-dependent. The
    thread budget is halved by default: this probe runs *in addition to* the
    main httpx pass over mostly-closed ports (each attempt lingers until
    refused), so the same SLIRP ceiling that bounds the main pass gets its own
    smaller share here, not a second full-size burst."""
    if threads is None:
        threads = max(1, ctx.cfg.general.threads // 2)
    cmd = ["httpx", "-l", str(pairs_file), "-silent", "-threads", str(threads),
           "-csv", "-o", str(out_csv)]
    r = ctx.execute("httpx", cmd, timeout=900, log_stdout=False)
    return ok_path(r, out_csv)


def nuclei_tech(ctx: ToolContext, in_file: Path, out: Path) -> Optional[Path]:
    # nuclei-templates' current layout nests everything under http/ (verified
    # live against the repo) -- a bare "technologies/" matches nothing, so
    # nuclei ran with zero loaded templates every time ("no templates
    # provided for scan") instead of actually fingerprinting anything.
    # -rl/-c bound nuclei's request rate + template concurrency. Unbounded,
    # nuclei's defaults (150 rps) over a large host list add to the same
    # router conntrack pressure that drops the WAN link (see block1 DNS /
    # block2 ffuf comments); tie the rate to the global rate_limit knob.
    rate = ctx.cfg.general.rate_limit
    cmd = ["nuclei", "-l", str(in_file), "-t", "http/technologies/",
           "-rl", str(rate), "-c", "25", "-o", str(out)]
    r = ctx.execute("nuclei", cmd, timeout=600)
    return ok_path(r, out)
