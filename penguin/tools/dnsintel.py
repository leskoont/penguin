"""DNS intelligence (Block 1): zone transfer, email auth, DNSSEC, CAA.

Cheap, high-signal DNS-layer analysis via ``dig``. All parsing is pure so it is
unit-testable without the network; the wrappers only shell out and hand the raw
output to the parsers.
"""
from __future__ import annotations

import logging

from ._base import ToolContext

logger = logging.getLogger("penguin.tools.dnsintel")


def _dig(ctx: ToolContext, args: list[str], timeout: int = 15) -> str:
    r = ctx.execute("dig", ["dig", *args], timeout=timeout, log_stdout=True, proxy=False)
    return r.stdout or "" if r.ok else ""


def nameservers(ctx: ToolContext, domain: str) -> list[str]:
    return parse_short(_dig(ctx, ["+short", "NS", domain]))


def parse_short(output: str) -> list[str]:
    """Lines of `dig +short` output, cleaned + de-duped, order preserved."""
    out: list[str] = []
    seen: set[str] = set()
    for ln in output.splitlines():
        ln = ln.strip().rstrip(".")
        if ln and not ln.startswith(";") and ln not in seen:
            seen.add(ln)
            out.append(ln)
    return out


def axfr_records(output: str) -> list[str]:
    """Records returned by a `dig AXFR` attempt (empty => transfer refused).

    A successful transfer dumps the whole zone: many resource-record lines
    (name TTL CLASS TYPE ...). A refused/failed transfer prints only comments
    and a `; Transfer failed` / `communications error` line. We return the RR
    lines so a non-empty list means the zone leaked."""
    low = output.lower()
    if "transfer failed" in low or "communications error" in low or "connection timed out" in low:
        return []
    records: list[str] = []
    for ln in output.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith(";"):
            continue
        parts = ln.split()
        # name TTL CLASS TYPE rdata...  -> class IN, a known type in field 3
        if len(parts) >= 4 and parts[2].upper() in ("IN", "CH", "HS"):
            records.append(ln)
    # A lone SOA echo isn't a real transfer; require more than the bracketing SOA.
    non_soa = [r for r in records if len(r.split()) >= 4 and r.split()[3].upper() != "SOA"]
    return records if non_soa else []


def has_spf(txt_output: str) -> bool:
    return any("v=spf1" in ln.lower() for ln in txt_output.splitlines())


def has_dmarc(txt_output: str) -> bool:
    return any("v=dmarc1" in ln.lower() for ln in txt_output.splitlines())


def check_domain(ctx: ToolContext, domain: str) -> list[dict]:
    """Run the DNS-intel checks for one apex domain; return issue dicts:
    {"type", "domain", ["records"|"detail"]}. Only real issues are returned."""
    issues: list[dict] = []

    # Zone transfer against each authoritative NS.
    for ns in nameservers(ctx, domain):
        recs = axfr_records(_dig(ctx, ["AXFR", domain, f"@{ns}"], timeout=30))
        if recs:
            issues.append({"type": "zone_transfer", "domain": domain, "ns": ns,
                           "records": recs[:50]})
            break  # one leaking NS is enough to report

    # Email auth: missing SPF / DMARC allows spoofing.
    if not has_spf(_dig(ctx, ["+short", "TXT", domain])):
        issues.append({"type": "missing_spf", "domain": domain})
    if not has_dmarc(_dig(ctx, ["+short", "TXT", f"_dmarc.{domain}"])):
        issues.append({"type": "missing_dmarc", "domain": domain})

    # DNSSEC: no DS record => zone unsigned (informational).
    if not parse_short(_dig(ctx, ["+short", "DS", domain])):
        issues.append({"type": "dnssec_missing", "domain": domain})

    return issues
