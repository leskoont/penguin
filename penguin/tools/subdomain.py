"""Subdomain enumeration wrappers (Block 1, stage 1-3)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext


def subfinder(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    cmd = ["subfinder", "-d", domain, "-all", "-recursive", "-silent", "-o", str(out)]
    cmd += ctx.threads_flag("subfinder", 50)
    r = ctx.execute("subfinder", cmd, log_stdout=False)
    return out if r.ok else None


def amass_passive(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    cmd = ["amass", "enum", "-passive", "-d", domain, "-src", "-o", str(out)]
    r = ctx.execute("amass", cmd, timeout=600)
    return out if r.ok else None


def amass_intel(ctx: ToolContext, org: str, out: Path) -> Optional[Path]:
    cmd = ["amass", "intel", "-org", org, "-o", str(out)]
    r = ctx.execute("amass", cmd, timeout=600)
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
    r = ctx.execute("findomain", cmd)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def chaos(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    if not ctx.cfg.paid_enabled("chaos"):
        return None
    cmd = ["chaos", "-d", domain, "-silent", "-o", str(out), "-key", ctx.cfg.paid_key("chaos")]
    r = ctx.execute("chaos", cmd)
    return out if r.ok else None


def crtsh(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    cmd = ["curl", "-s", f"https://crt.sh/?q=%25.{domain}&output=json"]
    r = ctx.execute("curl", cmd, timeout=60)
    if not r.ok:
        return None
    import json

    try:
        data = json.loads(r.stdout)
        names = {n["name_value"].replace("*.", "") for n in data if "name_value" in n}
        out.write_text("\n".join(sorted(names)) + "\n", encoding="utf-8")
        return out
    except Exception:
        return None
