"""penguin - knowledge-bank comparison layer.

Cross-references what recon discovered (technologies + versions, services) against
public vulnerability knowledge banks and derives NEW vectors from the overlap:

  * CISA KEV           -> known_cve flagged as actively exploited (kev_exploited)
  * product -> CVE map -> known_cve (severity from CVSS; EPSS carried as context)
  * default-cred list  -> default_credentials (a service to TEST, never auto-login)

A seed subset of each bank ships under ``penguin/data/knowledge/`` and is
unit-testable offline; operators extend it via a config path and refresh it from
the live sources with ``penguin kb-update``. All matching logic is pure.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("penguin.knowledge")

_BUNDLED = Path(__file__).resolve().parent / "data" / "knowledge"

def _safe_float(v, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


# CVSS -> finding severity band.
def cvss_severity(cvss: float) -> str:
    cvss = _safe_float(cvss)
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


# ---- version constraint matching (pure) ------------------------------------

def _parse_version(v: str) -> tuple:
    """Dotted version -> comparable tuple of ints (non-numeric parts dropped)."""
    parts = []
    for chunk in re.split(r"[.\-_]", str(v).strip()):
        m = re.match(r"(\d+)", chunk)
        if m:
            parts.append(int(m.group(1)))
        else:
            break
    return tuple(parts) or (0,)


def _cmp(a: tuple, b: tuple) -> int:
    # pad to equal length for lexicographic compare
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def version_matches(detected: Optional[str], constraint: str) -> bool:
    """True if ``detected`` satisfies a constraint like '<2.4.50', '<=1.2',
    '==2.4.49', '>=1.0', or '*' (any). Unknown detected version with a specific
    constraint is treated as NOT matching (avoid false positives); '*' always
    matches even with no version."""
    constraint = (constraint or "").strip()
    if constraint in ("*", ""):
        return True
    if detected is None or str(detected).strip() == "":
        return False
    m = re.match(r"(<=|>=|==|<|>)\s*(.+)", constraint)
    if not m:
        # bare version -> treat as exact match
        return _parse_version(detected) == _parse_version(constraint)
    op, ver = m.group(1), m.group(2)
    c = _cmp(_parse_version(detected), _parse_version(ver))
    return {"<": c < 0, "<=": c <= 0, "==": c == 0, ">": c > 0, ">=": c >= 0}[op]


# ---- technology extraction from recon output (pure) ------------------------

# normalize common tech labels to the product keys used in the KB
_TECH_ALIASES = {
    "apache httpd": "apache", "apache": "apache", "httpd": "apache",
    "nginx": "nginx", "openssh": "openssh", "openssl": "openssl",
    "php": "php", "wordpress": "wordpress", "jquery": "jquery",
    "log4j": "log4j", "apache tomcat": "tomcat", "tomcat": "tomcat",
    "jenkins": "jenkins", "grafana": "grafana", "mongodb": "mongodb",
    "redis": "redis", "elasticsearch": "elasticsearch", "phpmyadmin": "phpmyadmin",
    "apache struts": "struts", "spring": "spring",
}

_TECH_VER_RE = re.compile(r"^(.*?)[\s:/]+v?(\d[\w.\-]*)$")


def normalize_tech(label: str) -> tuple[str, Optional[str]]:
    """Parse a tech label like 'Apache httpd 2.4.49' / 'nginx:1.18' / 'jQuery' ->
    (product_key, version|None). Returns ('', None) if unrecognized."""
    s = (label or "").strip().strip('"').lower()
    if not s:
        return "", None
    version = None
    m = _TECH_VER_RE.match(s)
    if m:
        s, version = m.group(1).strip(), m.group(2)
    key = _TECH_ALIASES.get(s)
    if not key:
        # try first token (e.g. "nginx (ubuntu)")
        first = re.split(r"[\s(/,]", s, 1)[0]
        key = _TECH_ALIASES.get(first, first if first in _TECH_ALIASES.values() else "")
    return key, version


def extract_technologies(*texts: str) -> list[tuple[str, Optional[str]]]:
    """Generic bracket/line tech extractor (used for tests and as a fallback).

    Accepts bracketed httpx form '[Apache:2.4.49]' and plain 'name version'
    lines. Deduplicated; unknown products dropped. NOTE: this is permissive and
    will pick a product out of free text, so the pipeline uses the precise
    header-/token-based extractors below for real tool output instead."""
    found: dict[tuple, None] = {}
    for text in texts:
        for raw in re.split(r"[\n,\]]", text or ""):
            raw = raw.strip().lstrip("[")
            if not raw:
                continue
            prod, ver = normalize_tech(raw)
            if prod:
                found[(prod, ver)] = None
    return list(found.keys())


def extract_from_httpx_csv(csv_text: str) -> list[tuple[str, Optional[str]]]:
    """Extract (product, version) pairs from ONLY the technologies column of an
    httpx ``-csv`` file (located by header name), so page titles / server banners
    in other columns can't masquerade as detected tech."""
    import csv as _csv
    import io
    found: dict[tuple, None] = {}
    try:
        reader = _csv.reader(io.StringIO(csv_text or ""))
        rows = list(reader)
    except (ValueError, _csv.Error):
        return []
    if not rows:
        return []
    header = [h.strip().lower() for h in rows[0]]
    tech_idx = next((i for i, h in enumerate(header) if "tech" in h), None)
    if tech_idx is None:
        return []  # no tech column -> contribute nothing (never guess from titles)
    for row in rows[1:]:
        if tech_idx >= len(row):
            continue
        cell = row[tech_idx].strip().strip('"').strip("[]")
        for tok in re.split(r"[,;|]", cell):
            prod, ver = normalize_tech(tok)
            if prod:
                found[(prod, ver)] = None
    return list(found.keys())


# nuclei tech-detect lines look like:
#   [tech-detect:apache] [http] [info] https://x   (template-id carries the tech)
#   [nginx] [http] [info] https://x
#   [waf-detect:cloudflare] ...
_NUCLEI_TOKEN_RE = re.compile(r"\[([^\]]+)\]")


def extract_from_nuclei(text: str) -> list[tuple[str, Optional[str]]]:
    """Extract products from nuclei ``http/technologies/`` output by reading the
    template-id / matcher tokens (``[tech-detect:apache]``, ``[nginx]``), not the
    URL/severity. Only known products survive the alias filter."""
    found: dict[tuple, None] = {}
    _skip = {"http", "https", "tcp", "info", "low", "medium", "high", "critical", "unknown"}
    for line in (text or "").splitlines():
        toks = _NUCLEI_TOKEN_RE.findall(line)
        for tok in toks:
            tok = tok.strip().lower()
            # 'tech-detect:apache' / 'waf-detect:cloudflare' -> take the value
            if ":" in tok:
                tok = tok.split(":", 1)[1].strip()
            if not tok or tok in _skip or tok.startswith(("http", "tcp")):
                continue
            # strip common detection-template suffixes
            tok = re.sub(r"-(detect|version|detection|tech)$", "", tok)
            prod, ver = normalize_tech(tok)
            if prod:
                found[(prod, ver)] = None
    return list(found.keys())


# ---- the knowledge bank ----------------------------------------------------

@dataclass
class KnowledgeBank:
    kev: dict = field(default_factory=dict)            # cve -> entry
    cve_index: dict = field(default_factory=dict)       # product -> [entry]
    default_creds: dict = field(default_factory=dict)   # product -> [cred]

    @classmethod
    def load(cls, extra_dirs: Optional[list[Path]] = None) -> "KnowledgeBank":
        bank = cls()
        dirs = [_BUNDLED] + [Path(d) for d in (extra_dirs or [])]
        for d in dirs:
            bank._merge_dir(d)
        logger.info("[kb] loaded %d KEV, %d products w/ CVEs, %d products w/ default creds",
                    len(bank.kev), len(bank.cve_index), len(bank.default_creds))
        return bank

    def _merge_dir(self, d: Path) -> None:
        if not d or not d.is_dir():
            return
        kev = _read_json(d / "kev.json")
        for e in (kev.get("entries", []) if isinstance(kev, dict) else []):
            if isinstance(e, dict) and e.get("cve"):
                self.kev[e["cve"].upper()] = e
        idx = _read_json(d / "cve_index.json")
        for prod, entries in (idx.get("products", {}) if isinstance(idx, dict) else {}).items():
            if isinstance(entries, list):
                self.cve_index.setdefault(prod.lower(), []).extend(
                    e for e in entries if isinstance(e, dict))
        dc = _read_json(d / "default_creds.json")
        for prod, creds in (dc.get("products", {}) if isinstance(dc, dict) else {}).items():
            if isinstance(creds, list):
                self.default_creds.setdefault(prod.lower(), []).extend(
                    c for c in creds if isinstance(c, dict))

    def is_kev(self, cve: str) -> bool:
        return (cve or "").upper() in self.kev

    def cves_for(self, product: str, version: Optional[str]) -> list[dict]:
        """Matching CVE entries for a product+version, each enriched with
        severity + kev flag."""
        out = []
        for e in self.cve_index.get((product or "").lower(), []):
            if version_matches(version, e.get("constraint", "*")):
                cve = e.get("cve", "")
                out.append({**e, "product": product,
                            "severity": cvss_severity(e.get("cvss", 0)),
                            "kev": self.is_kev(cve)})
        return out

    def default_creds_for(self, product: str) -> list[dict]:
        return self.default_creds.get((product or "").lower(), [])

    def match(self, technologies: list[tuple]) -> list[dict]:
        """Cross-reference detected (product, version) tech against the bank.

        Returns a flat list of derived vectors::
          {kind: 'kev_exploited'|'known_cve'|'default_credentials', product,
           version, cve?, cvss?, epss?, title?, creds?}
        """
        vectors: list[dict] = []
        seen_cves: set[str] = set()
        for product, version in technologies:
            for hit in self.cves_for(product, version):
                cve = hit.get("cve", "")
                if cve in seen_cves:
                    continue
                seen_cves.add(cve)
                kind = "kev_exploited" if hit.get("kev") else "known_cve"
                vectors.append({
                    "kind": kind, "product": product, "version": version,
                    "cve": cve, "cvss": hit.get("cvss"), "epss": hit.get("epss"),
                    "title": hit.get("title", ""), "severity": hit.get("severity"),
                })
            creds = self.default_creds_for(product)
            if creds:
                vectors.append({
                    "kind": "default_credentials", "product": product, "version": version,
                    "creds": creds,
                })
        return vectors


_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def update_kev(dest_dir: Path, url: str = _CISA_KEV_URL) -> int:
    """Fetch the live CISA KEV catalog and write it to ``dest_dir/kev.json`` in
    our schema. Returns the entry count, or -1 on failure (bundled seed still
    works). Best-effort; network-gated, not exercised by the offline tests."""
    try:
        import requests
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:  # noqa - network/parse failures are non-fatal
        logger.warning("[kb] KEV update failed: %s", exc)
        return -1
    entries = []
    for v in data.get("vulnerabilities", []) if isinstance(data, dict) else []:
        cve = v.get("cveID")
        if not cve:
            continue
        entries.append({
            "cve": cve,
            "vendor": (v.get("vendorProject") or "").lower(),
            "product": (v.get("product") or "").lower(),
            "name": v.get("vulnerabilityName", ""),
        })
    try:
        dest_dir = Path(dest_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        (dest_dir / "kev.json").write_text(
            json.dumps({"_meta": {"source": url}, "entries": entries}, indent=2),
            encoding="utf-8")
    except OSError as exc:
        logger.warning("[kb] could not write KEV: %s", exc)
        return -1
    return len(entries)


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}
