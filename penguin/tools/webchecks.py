"""Lightweight web-misconfig checks (Block 2): CORS + security headers.

One request per live host, reading only the response headers, so it is cheap
and non-intrusive. We use curl (a stable, always-present dependency) rather than
parsing httpx's version-dependent JSON, and reflect an attacker-controlled
Origin to detect the classic reflect-any-origin CORS misconfiguration.
"""
from __future__ import annotations

import logging
from typing import Optional

from ._base import ToolContext

logger = logging.getLogger("penguin.tools.webchecks")

# The high-signal response headers whose ABSENCE is worth reporting.
SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
)

# Origin we send to probe for reflect-any-origin CORS. Deliberately implausible.
CORS_PROBE_ORIGIN = "https://penguin-cors-probe.example"


def fetch_headers(ctx: ToolContext, url: str, timeout: Optional[float] = None) -> Optional[str]:
    """Fetch a URL's response headers via curl, returning the raw header text
    (or None if the request could not be made). Sends the CORS probe Origin."""
    to = timeout or min(ctx.cfg.general.timeout, 20)
    cmd = [
        "curl", "-s", "-o", "/dev/null", "-D", "-",
        "-A", ctx.cfg.general.user_agent,
        "--max-time", str(int(to)),
        "-H", f"Origin: {CORS_PROBE_ORIGIN}",
        url,
    ]
    r = ctx.execute("curl", cmd, timeout=to, log_stdout=True)
    if not r.ok:
        return None
    return r.stdout or ""


def _parse_headers(raw: str) -> tuple[Optional[int], dict]:
    """Parse raw HTTP response headers -> (status_code, {lower-name: value}).

    Handles multiple header blocks (redirect chains / proxy 200-Connected) by
    keeping the LAST status line and merging header names (last value wins)."""
    status: Optional[int] = None
    headers: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.upper().startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
                headers = {}  # reset per response block; keep the last block's
            continue
        if ":" in line:
            name, _, val = line.partition(":")
            headers[name.strip().lower()] = val.strip()
    return status, headers


def analyze_headers(raw: str, probe_origin: str = CORS_PROBE_ORIGIN) -> dict:
    """Pure analysis of raw response headers.

    Returns {status, missing:[...], cors_reflected:bool, cors_wildcard:bool,
    cors_credentials:bool}. ``cors_reflected`` means the server echoed our
    attacker Origin back in Access-Control-Allow-Origin (trusts any origin);
    combined with credentials that is a serious data-exfil misconfig."""
    status, headers = _parse_headers(raw)
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    acao = headers.get("access-control-allow-origin", "").strip()
    acac = headers.get("access-control-allow-credentials", "").strip().lower()
    return {
        "status": status,
        "missing": missing,
        "cors_reflected": acao == probe_origin,
        "cors_wildcard": acao == "*",
        "cors_credentials": acac == "true",
    }


def check_host(ctx: ToolContext, url: str) -> Optional[dict]:
    """Fetch + analyze one host. Returns a web-issue dict (with the url) only
    when there is something worth reporting, else None."""
    raw = fetch_headers(ctx, url)
    if raw is None:
        return None
    res = analyze_headers(raw)
    # A wildcard ACAO without credentials is normal for public APIs; only flag
    # reflect-any-origin, or wildcard *with* credentials (which browsers block
    # but still signals a misconfigured server), plus missing headers.
    cors_bad = res["cors_reflected"] or (res["cors_wildcard"] and res["cors_credentials"])
    if not cors_bad and not res["missing"]:
        return None
    res["url"] = url
    res["cors_bad"] = cors_bad
    return res
