"""Content intelligence (Block 2): sensitive-file exposure + robots/sitemap mining.

Probes a small, curated set of high-signal paths per host and classifies the
responses. Two payoffs: it flags real exposures (.env, .git/config, actuator,
server-status, phpinfo, backups, directory listings), and it mines robots.txt /
sitemap.xml for extra endpoints — expanding the analysis surface for later
stages. All classification is pure and unit-tested.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

from ._base import ToolContext

logger = logging.getLogger("penguin.tools.contentintel")

# path -> (finding kind, body signature substrings that confirm a true positive)
# An empty signature tuple means "a 200 is enough" (path is inherently sensitive).
SENSITIVE_PATHS: dict[str, tuple] = {
    "/.env": ("exposed_config", ("=", "APP_", "DB_", "SECRET", "KEY")),
    "/.git/config": ("exposed_config", ("[core]", "repositoryformatversion")),
    "/config.json": ("exposed_config", ("{",)),
    "/server-status": ("info_disclosure", ("Apache Server Status", "Server uptime")),
    "/actuator": ("info_disclosure", ("_links", "health")),
    "/actuator/env": ("exposed_config", ("propertySources", "systemProperties")),
    "/phpinfo.php": ("info_disclosure", ("phpinfo()", "PHP Version")),
    "/.DS_Store": ("info_disclosure", ("Bud1",)),
    "/backup.zip": ("exposed_config", ("PK",)),
    "/.well-known/security.txt": ("security_txt", ("Contact:", "contact:")),
}

_DIR_LISTING_RE = re.compile(r"<title>\s*Index of /|Directory listing for", re.IGNORECASE)


def classify(path: str, status: Optional[int], body: str) -> Optional[str]:
    """Return the finding kind for a probed path, or None if not a true positive.

    Requires a 200 and, where defined, a body signature — this rejects the soft
    404s / login redirects that make naive path probing noisy."""
    if status != 200:
        return None
    spec = SENSITIVE_PATHS.get(path)
    if not spec:
        return None
    kind, sigs = spec
    if not sigs:
        return kind
    low = body or ""
    if any(sig in low for sig in sigs):
        return kind
    return None


def is_directory_listing(status: Optional[int], body: str) -> bool:
    return status == 200 and bool(_DIR_LISTING_RE.search(body or ""))


def mine_robots(text: str) -> list[str]:
    """Extract Disallow/Allow paths from robots.txt (deduped, path-only)."""
    out: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        line = line.strip()
        m = re.match(r"(?i)(?:dis)?allow\s*:\s*(\S+)", line)
        if m:
            p = m.group(1)
            if p and p != "/" and p not in seen:
                seen.add(p)
                out.append(p)
    return out


def mine_sitemap(text: str) -> list[str]:
    """Extract <loc> URLs from a sitemap.xml (deduped)."""
    out: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", text or "", re.IGNORECASE):
        u = m.group(1).strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _fetch(ctx: ToolContext, url: str, timeout: int = 15) -> tuple[Optional[int], str]:
    """GET a URL via curl, returning (status_code, body). (-w writes the status
    as the last line after the body so a single call yields both.)"""
    to = min(timeout, ctx.cfg.general.timeout)
    cmd = ["curl", "-sk", "-A", ctx.cfg.general.user_agent, "--max-time", str(int(to)),
           "-w", "\\n%{http_code}", url]
    r = ctx.execute("curl", cmd, timeout=to, log_stdout=True)
    if not r.ok:
        return None, ""
    text = r.stdout or ""
    nl = text.rfind("\n")
    if nl == -1:
        return None, text
    tail = text[nl + 1:].strip()
    status = int(tail) if tail.isdigit() else None
    return status, text[:nl]


def check_host(ctx: ToolContext, base_url: str) -> dict:
    """Probe one host for content issues + mine robots/sitemap.

    Returns {"exposed":[{path,kind}], "listing":bool_url_list, "paths":[extra endpoints]}."""
    base = base_url.rstrip("/")
    exposed: list[dict] = []
    listings: list[str] = []
    extra: list[str] = []

    for path, _spec in SENSITIVE_PATHS.items():
        status, body = _fetch(ctx, base + path)
        kind = classify(path, status, body[:4096])
        if kind:
            exposed.append({"url": base + path, "kind": kind})
        if is_directory_listing(status, body[:4096]):
            listings.append(base + path)

    rs, rb = _fetch(ctx, base + "/robots.txt")
    if rs == 200:
        extra += [base + p if p.startswith("/") else p for p in mine_robots(rb)]
    ss, sb = _fetch(ctx, base + "/sitemap.xml")
    if ss == 200:
        extra += mine_sitemap(sb)

    return {"exposed": exposed, "listing": listings, "paths": extra}
