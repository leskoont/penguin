"""Passive OSINT enrichment wrappers (pure-curl, no extra binaries).

Widen block1's passive subdomain net and block2's endpoint discovery with
public aggregators that the Go tooling does not already cover:

  * AlienVault OTX passive DNS  -> historical + current subdomains
  * RapidDNS                    -> DNS-database subdomains
  * HackerTarget hostsearch     -> host/IP pairs from their DB
  * urlscan.io search           -> seen-hostnames from public scans
  * Wayback CDX                 -> every archived URL under the domain
                                   (endpoint mining, block2)

All of them query the aggregator, never the target, so they follow the same
policy as crt.sh: run DIRECT (proxy=False -- the free SOCKS pool kills these
curl calls with exit 97/35), with a couple of bounded retries for the
aggregators' transient 5xx/timeouts.

Each fetcher delegates parsing to a pure ``parse_*`` function so the
extraction logic is unit-testable without network.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional
from urllib.parse import quote

from ._base import ToolContext

# Per-aggregator curl budget: public OSINT APIs are slow but not tool-slow.
_TIMEOUT = 90
_RETRIES = 2


def _hosts_under(text: str, domain: str) -> set[str]:
    """Extract hostnames ending in ``.domain`` (or equal to it) from any text.

    Intentionally loose about the surrounding markup so one extractor serves
    the JSON / HTML / CSV shapes of the different sources."""
    rx = re.compile(
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9_-]*[a-zA-Z0-9])?\.)+" + re.escape(domain),
        re.IGNORECASE,
    )
    return {m.group(0).lower().rstrip(".") for m in rx.finditer(text)}


def parse_otx(text: str) -> list[str]:
    """Hostnames from OTX passive_dns JSON (``{"passive_dns": [{"hostname": ..}]}``)."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[str] = []
    for rec in data.get("passive_dns", []) or []:
        if isinstance(rec, dict):
            h = str(rec.get("hostname", "")).strip().lower().replace("*.", "")
            if h:
                out.append(h)
    return sorted(set(out))


def parse_hackertarget(text: str) -> list[str]:
    """Hostnames from HackerTarget hostsearch CSV-ish lines (``name,ip``).

    The free API answers with an error sentence (not CSV) once its daily
    quota is exhausted -- anything without a comma-separated hostname row
    yields nothing."""
    out: list[str] = []
    for line in (text or "").splitlines():
        name = line.strip().split(",")[0].strip().lower().replace("*.", "")
        if name and "," in line and "." in name:
            out.append(name)
    return sorted(set(out))


def parse_urlscan(text: str, domain: str) -> list[str]:
    """In-scope hostnames from a urlscan.io search response."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    hosts: set[str] = set()
    for rec in data.get("results", []) or []:
        if not isinstance(rec, dict):
            continue
        for holder in (rec.get("task", {}), rec.get("page", {})):
            if isinstance(holder, dict):
                h = str(holder.get("domain", "")).strip().lower()
                if h and (h == domain or h.endswith("." + domain)):
                    hosts.add(h)
    return sorted(hosts)


def parse_rapiddns(text: str, domain: str) -> list[str]:
    return sorted(_hosts_under(text or "", domain))


def parse_wayback_cdx(text: str) -> list[str]:
    """URLs (one per line) from a Wayback CDX ``fl=original`` dump."""
    out: set[str] = set()
    for line in (text or "").splitlines():
        u = line.strip()
        if u.startswith(("http://", "https://")):
            out.add(u)
    return sorted(out)


def _fetch(ctx: ToolContext, url: str) -> Optional[str]:
    r = ctx.execute("curl", ["curl", "-s", "--max-time", "80", url],
                    timeout=_TIMEOUT, proxy=False, retries=_RETRIES)
    return r.stdout if r.ok else None


def otx_passive_dns(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    body = _fetch(ctx, f"https://otx.alienvault.com/api/v1/indicators/domain/"
                       f"{quote(domain, safe='')}/passive_dns")
    if body is None:
        return None
    names = [h for h in parse_otx(body) if h.endswith("." + domain)]
    if not names:
        return None
    out.write_text("\n".join(names) + "\n", encoding="utf-8")
    return out


def rapiddns(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    body = _fetch(ctx, f"https://rapiddns.io/subdomain/{quote(domain, safe='')}?full=1")
    if body is None:
        return None
    names = sorted(parse_rapiddns(body, domain))
    if not names:
        return None
    out.write_text("\n".join(names) + "\n", encoding="utf-8")
    return out


def hackertarget(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    body = _fetch(ctx, f"https://api.hackertarget.com/hostsearch/?q={quote(domain, safe='')}")
    if body is None:
        return None
    names = [h for h in parse_hackertarget(body) if h == domain or h.endswith("." + domain)]
    if not names:
        return None
    out.write_text("\n".join(names) + "\n", encoding="utf-8")
    return out


def urlscan_search(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    body = _fetch(ctx, "https://urlscan.io/api/v1/search/?q=domain:"
                       + quote(domain, safe="") + "&size=1000")
    if body is None:
        return None
    names = parse_urlscan(body, domain)
    if not names:
        return None
    out.write_text("\n".join(names) + "\n", encoding="utf-8")
    return out


def wayback_cdx(ctx: ToolContext, domain: str, out: Path, *, limit: int = 20000) -> Optional[Path]:
    """Every URL archived for ``domain`` (incl. all its subdomains).

    Endpoint-mining vector for block2: a CDX dump frequently surfaces paths
    the live crawlers never see (retired endpoints, old APIs, params)."""
    url = (f"https://web.archive.org/cdx/search/cdx?url=*.{quote(domain, safe='')}/*"
           f"&output=text&fl=original&collapse=urlkey&limit={int(limit)}")
    body = _fetch(ctx, url)
    if body is None:
        return None
    urls = parse_wayback_cdx(body)
    if not urls:
        return None
    out.write_text("\n".join(urls) + "\n", encoding="utf-8")
    return out
