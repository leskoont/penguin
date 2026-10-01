"""penguin - typed, triage-ready findings model.

Blocks report counts; triage needs the actual artifacts, typed and
severity-ranked, and deduplicated across runs so a report can show what is
*new this run* for every finding type (not just subdomains).

Findings are derived centrally from the block result dicts (see
``derive_findings``) so no per-block plumbing is required, and accumulated per
target in ``reports/<target>/findings.jsonl`` with a ``first_seen_run`` stamp.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger("penguin.findings")

# Severity ranking (lower sorts first / more urgent).
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sanitize_slug(s: str) -> str:
    return re.sub(r"[^a-z0-9._-]", "_", s.lower())


@dataclass
class Finding:
    type: str
    severity: str
    target: str
    asset: str
    source_tool: str = ""
    evidence: str = ""
    url: str = ""
    first_seen_run: str = ""

    def key(self) -> str:
        """Stable identity for cross-run dedup: a finding is 'the same' when its
        type and asset match, regardless of which run re-observed it."""
        return f"{self.type}::{self.asset}"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        known = {f: d.get(f, "") for f in (
            "type", "severity", "target", "asset", "source_tool", "evidence",
            "url", "first_seen_run")}
        return cls(**known)


# Per-finding-type metadata: severity + the tool(s) that surface it.
_TYPES = {
    "subdomain_takeover": ("critical", "nuclei/subzy"),
    "exposed_git":   ("critical", "gitdumper"),
    "secret":        ("critical", "trufflehog/gitleaks"),
    "zone_transfer": ("critical", "dig"),
    "kev_exploited": ("critical", "knowledge-bank/CISA-KEV"),
    "known_cve":     ("high",     "knowledge-bank"),
    "default_credentials": ("high", "knowledge-bank"),
    "js_secret":     ("high",     "jsluice/SecretFinder"),
    "open_database": ("high",     "nmap/masscan"),
    "xss": ("high",               "dalfox"),
    "cors_misconfig": ("high",    "webchecks"),
    "tls_expired":    ("high",    "openssl"),
    "exposed_config": ("high",    "contentintel"),
    "public_bucket": ("medium",   "s3scanner/cloud_enum"),
    "origin_ip":     ("medium",   "origin-bypass"),
    "missing_dmarc": ("medium",   "dig"),
    "tls_self_signed": ("medium", "openssl"),
    "info_disclosure": ("medium", "contentintel"),
    "directory_listing": ("medium", "contentintel"),
    "missing_security_headers": ("low", "webchecks"),
    "missing_spf":   ("low",      "dig"),
    "tls_expiring_soon": ("low",  "openssl"),
    "new_subdomain": ("info",     "diff"),
    "dnssec_missing": ("info",    "dig"),
    "security_txt":  ("info",     "contentintel"),
}


def _mk(ftype: str, target: str, asset: str, *, url: str = "", evidence: str = "") -> Finding:
    severity, tool = _TYPES[ftype]
    return Finding(type=ftype, severity=severity, target=target, asset=str(asset),
                   source_tool=tool, url=url, evidence=evidence)


def derive_findings(target: dict, b1: dict, b2: dict, b3: dict, b4: dict,
                    diff: dict) -> list[Finding]:
    """Build typed findings from the block result dicts + subdomain diff.

    Pure and central: adding a new finding type is a line here, not a change to
    every block. Asset strings are whatever the block collected (a hostname, a
    host:port, a bucket URL, or an evidence file path)."""
    tv = str(target.get("value", ""))
    out: list[Finding] = []
    for host in b1.get("takeovers", []):
        out.append(_mk("subdomain_takeover", tv, host, url=str(host),
                       evidence="dangling record claimable"))
    for iss in b1.get("dns_issues", []):
        if not isinstance(iss, dict):
            continue
        itype = iss.get("type")
        if itype not in _TYPES:
            continue
        dom = iss.get("domain", tv)
        ev = f"via {iss.get('ns')}" if iss.get("ns") else ""
        out.append(_mk(itype, tv, dom, evidence=ev))
    for iss in b1.get("tls_issues", []):
        if not isinstance(iss, dict):
            continue
        host = iss.get("host", tv)
        days = iss.get("days_left")
        if iss.get("expired"):
            out.append(_mk("tls_expired", tv, host, url=host,
                           evidence=f"certificate expired ({days}d)"))
        elif iss.get("expiring_soon"):
            out.append(_mk("tls_expiring_soon", tv, host, url=host,
                           evidence=f"expires in {days}d"))
        if iss.get("self_signed"):
            out.append(_mk("tls_self_signed", tv, host, url=host,
                           evidence="issuer == subject"))
    for host in diff.get("new", []):
        out.append(_mk("new_subdomain", tv, host))
    for sec in b2.get("js_secrets", []):
        out.append(_mk("js_secret", tv, sec, evidence="JS analysis hit"))
    for url in b2.get("active", []):
        out.append(_mk("xss", tv, url, url=str(url), evidence="dalfox active XSS"))
    for issue in b2.get("content_issues", []):
        if not isinstance(issue, dict):
            continue
        kind = issue.get("kind")
        if kind not in _TYPES:
            continue
        u = issue.get("url", "")
        out.append(_mk(kind, tv, u, url=u))
    for vec in b2.get("kb_findings", []):
        if not isinstance(vec, dict):
            continue
        kind = vec.get("kind")
        prod = vec.get("product", "")
        ver = vec.get("version") or "?"
        if kind in ("kev_exploited", "known_cve"):
            cve = vec.get("cve", "")
            # known_cve severity tracks the CVE's CVSS; KEV is always critical.
            sev = "critical" if kind == "kev_exploited" else (vec.get("severity") or "high")
            ev = f"{prod} {ver}: {vec.get('title', '')}".strip()
            epss = vec.get("epss")
            if epss is not None:
                ev += f" (EPSS {epss})"
            if kind == "kev_exploited":
                ev = "ACTIVELY EXPLOITED (CISA KEV) — " + ev
            out.append(Finding(type=kind, severity=sev, target=tv, asset=cve or f"{prod} {ver}",
                               source_tool=_TYPES[kind][1], evidence=ev))
        elif kind == "default_credentials":
            n = len(vec.get("creds", []))
            out.append(_mk("default_credentials", tv, prod,
                           evidence=f"{n} known default credential set(s) for {prod} — test manually"))
    for issue in b2.get("web_issues", []):
        if not isinstance(issue, dict):
            continue
        url = issue.get("url", "")
        if issue.get("cors_bad") or issue.get("cors_reflected"):
            out.append(_mk("cors_misconfig", tv, url, url=url,
                           evidence="reflects arbitrary Origin"
                           + (" with credentials" if issue.get("cors_credentials") else "")))
        missing = issue.get("missing") or []
        if missing:
            out.append(_mk("missing_security_headers", tv, url, url=url,
                           evidence="missing: " + ", ".join(missing)))
    for db in b3.get("open_db", []):
        out.append(_mk("open_database", tv, db, evidence="open DB service artifact"))
    for bkt in b3.get("buckets", []):
        out.append(_mk("public_bucket", tv, bkt))
    for ip in b4.get("origin_ips", []):
        out.append(_mk("origin_ip", tv, ip, evidence="candidate origin behind CDN/WAF"))
    for git in b4.get("exposed_git", []):
        out.append(_mk("exposed_git", tv, git, url=str(git)))
    for sec in b4.get("secrets", []):
        out.append(_mk("secret", tv, sec, evidence="secret scanner hit"))
    # Drop findings whose asset came from a falsy/None list entry (a degraded
    # block can hand back None/"" items); str(None) would otherwise leak a junk
    # "None" asset into the report.
    out = [f for f in out if f.asset and f.asset.lower() != "none"]
    return out


def severity_sort_key(f: Finding) -> tuple:
    return (SEVERITY_ORDER.get(f.severity, 99), f.type, f.asset)


@dataclass
class FindingStore:
    """Per-target persistent findings accumulator (findings.jsonl)."""
    path: Path
    _by_key: dict = field(default_factory=dict)

    @classmethod
    def for_target(cls, reports_root: Path, target_value: str) -> "FindingStore":
        d = Path(reports_root) / _sanitize_slug(target_value)
        d.mkdir(parents=True, exist_ok=True)
        store = cls(path=d / "findings.jsonl")
        store._load()
        return store

    def _load(self) -> None:
        self._by_key = {}
        if not self.path.exists():
            return
        for line in self.path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except (ValueError, TypeError):
                continue
            if not isinstance(d, dict):
                continue
            f = Finding.from_dict(d)
            self._by_key[f.key()] = f

    def record(self, findings: list[Finding], run_id: str) -> tuple[list[Finding], list[Finding]]:
        """Merge this run's findings into the store.

        Returns (all_current, new_this_run). Known findings keep their original
        first_seen_run; genuinely new ones are stamped with this run and
        appended to findings.jsonl. ``all_current`` is exactly this run's
        findings (each carrying the right first_seen_run), so a report reflects
        the current run while still knowing which are new."""
        new: list[Finding] = []
        current: list[Finding] = []
        for f in findings:
            existing = self._by_key.get(f.key())
            if existing is not None:
                f.first_seen_run = existing.first_seen_run or run_id
            else:
                f.first_seen_run = run_id
                self._by_key[f.key()] = f
                new.append(f)
            current.append(f)
        if new:
            try:
                with open(self.path, "a", encoding="utf-8") as fh:
                    for f in new:
                        fh.write(json.dumps(f.to_dict(), ensure_ascii=False) + "\n")
            except OSError:
                logger.debug("[findings] failed to append %d new findings", len(new))
        return current, new
