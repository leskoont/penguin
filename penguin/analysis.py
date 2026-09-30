"""penguin - intelligent analysis layer.

Turns a flat list of Findings into triage intelligence: severity-weighted risk
scores per host and overall, correlation of related findings into higher-level
insights (attack chains), and a risk-ranked attack surface. Pure and
network-free, so it is fully unit-testable and reused by the report and the
`penguin analyze` command.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from .findings import Finding

# Severity -> risk weight. Non-linear so one critical outranks a pile of lows.
SEVERITY_WEIGHTS = {"critical": 100, "high": 40, "medium": 10, "low": 3, "info": 1}

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def host_of(finding: Finding) -> str:
    """Best-effort host extraction from a finding's url/asset for grouping.

    Handles http(s) URLs, host:port, and bare hostnames; falls back to the
    target when the asset is an opaque evidence path (e.g. a secret-scan file)."""
    raw = (finding.url or finding.asset or "").strip()
    if not raw:
        return finding.target or "?"
    s = raw
    if _SCHEME_RE.match(s):
        s = _SCHEME_RE.sub("", s)
    # strip path/query
    s = s.split("/")[0].split("?")[0]
    # strip :port
    if ":" in s and not s.count(":") > 1:  # ipv6-ish -> leave alone
        s = s.split(":")[0]
    # An evidence file path (starts with / or contains no dot) isn't a host.
    if raw.startswith("/") or ("." not in s and s not in ("localhost",)):
        return finding.target or raw
    return s.lower() or finding.target or "?"


@dataclass
class Insight:
    """A correlated, higher-level observation derived from multiple findings."""
    title: str
    severity: str
    host: str
    detail: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"title": self.title, "severity": self.severity, "host": self.host,
                "detail": self.detail, "evidence": self.evidence}


def _sev_rank(sev: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(sev, 9)


def score(findings: Iterable[Finding]) -> dict:
    """Risk-score the findings overall, per host and per type.

    Returns::
        {"overall": int,
         "by_host": {host: {"score": int, "count": int, "top_severity": str,
                            "counts": {sev: n}}},
         "by_type": {type: n}}
    """
    findings = list(findings)
    by_host: dict[str, dict] = {}
    by_type: dict[str, int] = {}
    overall = 0
    for f in findings:
        w = SEVERITY_WEIGHTS.get(f.severity, 1)
        overall += w
        by_type[f.type] = by_type.get(f.type, 0) + 1
        h = host_of(f)
        hb = by_host.setdefault(h, {"score": 0, "count": 0, "top_severity": "info",
                                    "counts": {}})
        hb["score"] += w
        hb["count"] += 1
        hb["counts"][f.severity] = hb["counts"].get(f.severity, 0) + 1
        if _sev_rank(f.severity) < _sev_rank(hb["top_severity"]):
            hb["top_severity"] = f.severity
    return {"overall": overall, "by_host": by_host, "by_type": by_type}


def rank_hosts(scored: dict, limit: int = 10) -> list[tuple[str, dict]]:
    """Top hosts by risk score (desc), tie-broken by count then name."""
    items = scored.get("by_host", {}).items()
    return sorted(items, key=lambda kv: (-kv[1]["score"], -kv[1]["count"], kv[0]))[:limit]


# --- correlation rules --------------------------------------------------------
# Each rule inspects the per-host type set and emits an Insight when a
# meaningful combination (an attack chain) is present.

def _types_by_host(findings: list[Finding]) -> dict[str, dict[str, list[Finding]]]:
    out: dict[str, dict[str, list[Finding]]] = {}
    for f in findings:
        out.setdefault(host_of(f), {}).setdefault(f.type, []).append(f)
    return out


def correlate(findings: Iterable[Finding]) -> list[Insight]:
    """Derive attack-chain insights from co-occurring findings per host."""
    findings = list(findings)
    insights: list[Insight] = []
    per_host = _types_by_host(findings)
    for host, types in per_host.items():
        has = types.__contains__
        # exposed source + leaked secret on the same host = direct compromise path
        if has("exposed_git") and (has("secret") or has("js_secret")):
            insights.append(Insight(
                "Source exposure with leaked secrets", "critical", host,
                "An exposed .git/source repo AND secret material were found on the "
                "same host — clone the source, extract the secrets, pivot.",
                [f.asset for t in ("exposed_git", "secret", "js_secret") for f in types.get(t, [])][:8]))
        # takeover is standalone-critical; surface as an insight for ranking too
        if has("subdomain_takeover"):
            insights.append(Insight(
                "Hijackable subdomain", "critical", host,
                "Dangling record points at a claimable third-party service.",
                [f.asset for f in types["subdomain_takeover"]][:8]))
        # exposed config/env next to secrets = direct credential leak
        if has("exposed_config") and (has("secret") or has("js_secret")):
            insights.append(Insight(
                "Exposed config leaking credentials", "critical", host,
                "A served config/.env AND secret material on the same host — the "
                "config likely contains live credentials.",
                [f.asset for t in ("exposed_config", "secret", "js_secret") for f in types.get(t, [])][:8]))
        # open DB = unauthenticated data store
        if has("open_database"):
            insights.append(Insight(
                "Exposed data store", "high", host,
                "A database/service port is reachable; verify auth before it is abused.",
                [f.asset for f in types["open_database"]][:8]))
        # CORS reflect-any + secrets/creds surface = token theft
        if has("cors_misconfig") and (has("js_secret") or has("xss")):
            insights.append(Insight(
                "CORS + client-side secrets = token theft", "high", host,
                "Reflect-any-origin CORS next to client-side secrets/XSS lets a "
                "malicious origin read authenticated responses.",
                [f.asset for t in ("cors_misconfig", "js_secret", "xss") for f in types.get(t, [])][:8]))
        # XSS + missing security headers (no CSP) = easier exploitation
        if has("xss") and has("missing_security_headers"):
            insights.append(Insight(
                "XSS with weak header defenses", "high", host,
                "Active XSS on a host lacking CSP/other headers — fewer mitigations "
                "stand between the payload and execution.",
                [f.asset for f in types["xss"]][:8]))
        # zone transfer leaks the whole DNS zone
        if has("zone_transfer"):
            insights.append(Insight(
                "DNS zone transfer allowed", "critical", host,
                "An authoritative nameserver served a full AXFR — the entire "
                "internal DNS map (hosts, services) is disclosed.",
                [f.asset for f in types["zone_transfer"]][:8]))
        # no SPF *and* no DMARC = domain is spoofable in email
        if has("missing_spf") and has("missing_dmarc"):
            insights.append(Insight(
                "Email domain spoofable", "medium", host,
                "Neither SPF nor DMARC is published — attackers can send mail as "
                "this domain (phishing).",
                [host]))
        # broad weak posture: many missing-header findings
        if len(types.get("missing_security_headers", [])) >= 3:
            insights.append(Insight(
                "Systemically weak security headers", "low", host,
                f"{len(types['missing_security_headers'])} endpoints missing core "
                "security headers — indicates no baseline hardening.",
                [f.asset for f in types["missing_security_headers"]][:8]))
    insights.sort(key=lambda i: (_sev_rank(i.severity), i.host))
    return insights


def risk_band(overall: int) -> str:
    """Human label for an overall risk score."""
    if overall >= 200:
        return "critical"
    if overall >= 80:
        return "high"
    if overall >= 25:
        return "elevated"
    if overall > 0:
        return "low"
    return "clean"


def analyze(findings: Iterable[Finding], *, top: int = 10) -> dict:
    """One-shot: score + rank + correlate. Returns a JSON-friendly summary."""
    findings = list(findings)
    scored = score(findings)
    ranked = rank_hosts(scored, top)
    insights = correlate(findings)
    return {
        "overall": scored["overall"],
        "risk_band": risk_band(scored["overall"]),
        "by_type": scored["by_type"],
        "top_hosts": [{"host": h, **hb} for h, hb in ranked],
        "insights": [i.to_dict() for i in insights],
    }
