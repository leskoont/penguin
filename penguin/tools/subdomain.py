"""Subdomain enumeration wrappers (Block 1, stage 1-3)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext


def subfinder(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    cmd = ["subfinder", "-d", domain, "-all", "-recursive", "-silent", "-o", str(out)]
    cmd += ctx.threads_flag("subfinder", 50)
    # -all -recursive fans out across 30+ passive sources and a recursive
    # brute stage -- the general 30s default timeout (meant for quick single
    # commands) made this fail every single attempt, every single run
    # ("timeout after 30s" x3, 100% of the time observed), silently dropping
    # what should be one of the best subdomain sources.
    r = ctx.execute("subfinder", cmd, timeout=300, log_stdout=False)
    return out if r.ok else None


def amass_passive(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    # -src was removed from amass v4's `enum` flag set; passing it now fails
    # with "flag provided but not defined: -src" and aborts the whole run.
    cmd = ["amass", "enum", "-passive", "-d", domain, "-o", str(out)]
    # retries=1: amass doesn't use the proxy pool (see tools/_base.py), so the
    # default 3x "re-pick a proxy" budget buys nothing here -- it just replays
    # an already-generous 600s timeout up to three times (observed timing out
    # at 600s, which would then cost 30 min of dead wall-clock on retries).
    r = ctx.execute("amass", cmd, timeout=600, retries=1)
    return out if r.ok else None


def amass_intel(ctx: ToolContext, org: str, out: Path) -> Optional[Path]:
    cmd = ["amass", "intel", "-org", org, "-o", str(out)]
    r = ctx.execute("amass", cmd, timeout=600, retries=1)  # same as amass_passive
    return out if r.ok else None


def assetfinder(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    cmd = ["assetfinder", "--subs-only", domain]
    r = ctx.execute("assetfinder", cmd)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def findomain(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    cmd = ["findomain", "-t", domain, "-q"]
    # same issue as subfinder above: certificate-transparency + API lookups
    # routinely run past the general 30s default, which made this fail every
    # attempt in both observed runs ("timeout after 30s" x3 each time).
    # retries=1: observed timing out at 120s x2 -- findomain doesn't use the
    # proxy pool either, so replaying a full 120s timeout buys nothing.
    r = ctx.execute("findomain", cmd, timeout=120, retries=1)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def chaos(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    if not ctx.cfg.paid_enabled("chaos"):
        return None
    # chaos reads CHAOS_KEY from the environment when -key is omitted -- keeps
    # the key out of argv (ps/proc/pid/cmdline).
    cmd = ["chaos", "-d", domain, "-silent", "-o", str(out)]
    r = ctx.execute("chaos", cmd, extra_env={"CHAOS_KEY": ctx.cfg.paid_key("chaos")})
    return out if r.ok else None


def crtsh(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    cmd = ["curl", "-s", f"https://crt.sh/?q=%25.{domain}&output=json"]
    # crt.sh is a public certificate-transparency aggregator (passive OSINT --
    # the query hits crt.sh, never the target), and it flat-out does not work
    # through the free SOCKS proxy pool: every attempt died with curl exit 97
    # (proxy closed connection) / 35 (SSL), so this normally-richest passive
    # source contributed zero names in every observed run. Query it directly,
    # consistent with findomain/assetfinder which already run un-proxied. The
    # 90s timeout accommodates crt.sh being slow for domains with many certs.
    r = ctx.execute("curl", cmd, timeout=90, proxy=False)
    if not r.ok:
        return None
    import json

    try:
        data = json.loads(r.stdout)
        # a single crt.sh entry's name_value can carry several newline-separated
        # SANs, so split before deduping instead of storing the blob verbatim.
        names: set[str] = set()
        for n in data:
            for nm in n.get("name_value", "").splitlines():
                nm = nm.strip().replace("*.", "")
                if nm:
                    names.add(nm)
        out.write_text("\n".join(sorted(names)) + "\n", encoding="utf-8")
        return out
    except Exception:
        return None
