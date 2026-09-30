"""TLS / certificate intelligence (Block 1).

Grabs each host's leaf certificate with openssl (stable, ubiquitous) and derives
security signal from it: expiry, self-signed issuer, and the SAN list -- which
doubles as a subdomain-discovery vector (certs routinely name sibling hosts).
All parsing is pure and unit-tested; the wrappers only shell out.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Optional

from ._base import ToolContext

logger = logging.getLogger("penguin.tools.tlsintel")

_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


def extract_pem(s_client_output: str) -> Optional[str]:
    """First PEM certificate block from `openssl s_client` output."""
    m = _PEM_RE.search(s_client_output or "")
    return m.group(0) if m else None


def _parse_openssl_date(s: str) -> Optional[datetime]:
    # openssl prints e.g. "Nov  3 12:00:00 2025 GMT"
    s = s.strip()
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def parse_x509_text(x509_output: str) -> dict:
    """Parse `openssl x509 -noout -dates -issuer -subject -ext subjectAltName`.

    Returns {not_before, not_after (datetime|None), issuer, subject, sans:[...]}.
    """
    out: dict = {"not_before": None, "not_after": None, "issuer": "", "subject": "", "sans": []}
    for line in x509_output.splitlines():
        line = line.strip()
        if line.startswith("notBefore="):
            out["not_before"] = _parse_openssl_date(line.split("=", 1)[1])
        elif line.startswith("notAfter="):
            out["not_after"] = _parse_openssl_date(line.split("=", 1)[1])
        elif line.startswith("issuer="):
            out["issuer"] = line.split("=", 1)[1].strip()
        elif line.startswith("subject="):
            out["subject"] = line.split("=", 1)[1].strip()
        elif "DNS:" in line:
            for tok in line.split(","):
                tok = tok.strip()
                if tok.startswith("DNS:"):
                    out["sans"].append(tok[4:].strip().lower().lstrip("*.").rstrip("."))
    # dedup SANs preserving order
    seen: set[str] = set()
    out["sans"] = [s for s in out["sans"] if s and not (s in seen or seen.add(s))]
    return out


def analyze_cert(parsed: dict, *, now: Optional[datetime] = None) -> dict:
    """Derive issues from a parsed cert. Returns {expired, expiring_soon,
    self_signed, days_left, sans}."""
    now = now or datetime.now(timezone.utc)
    na = parsed.get("not_after")
    days_left: Optional[int] = None
    expired = False
    expiring_soon = False
    if na is not None:
        days_left = int((na - now).total_seconds() // 86400)
        expired = days_left < 0
        expiring_soon = 0 <= days_left <= 14
    issuer = (parsed.get("issuer") or "").strip()
    subject = (parsed.get("subject") or "").strip()
    self_signed = bool(issuer) and issuer == subject
    return {"expired": expired, "expiring_soon": expiring_soon,
            "self_signed": self_signed, "days_left": days_left,
            "sans": parsed.get("sans", [])}


def fetch_and_parse(ctx: ToolContext, host: str, port: int = 443) -> Optional[dict]:
    """Fetch host:port's leaf cert via openssl and return analyze_cert() output
    (plus host). None if the cert could not be retrieved."""
    hostname = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0]
    if not hostname:
        return None
    sc = ctx.execute(
        "openssl",
        ["openssl", "s_client", "-connect", f"{hostname}:{port}",
         "-servername", hostname],
        timeout=20, log_stdout=True, input="", proxy=False)
    if not sc.ok:
        return None
    pem = extract_pem(sc.stdout or "")
    if not pem:
        return None
    x = ctx.execute(
        "openssl",
        ["openssl", "x509", "-noout", "-dates", "-issuer", "-subject",
         "-ext", "subjectAltName"],
        timeout=15, log_stdout=True, input=pem, proxy=False)
    if not x.ok:
        return None
    res = analyze_cert(parse_x509_text(x.stdout or ""))
    res["host"] = hostname
    return res
