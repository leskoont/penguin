"""Origin-IP / Cloudflare-bypass wrappers (Block 4.1)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext


def dig_resolve(ctx: ToolContext, host: str, resolver: str, out: Path) -> Optional[str]:
    cmd = ["dig", host, "@" + resolver, "+short"]
    r = ctx.execute("dig", cmd, timeout=30)
    if r.ok:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"{host}@{resolver}: {r.stdout.strip()}\n")
        return r.stdout.strip()
    return None


def cloudflare_trace(ctx: ToolContext, url: str, out: Path) -> Optional[Path]:
    cmd = ["curl", "-s", f"{url}/cdn-cgi/trace"]
    r = ctx.execute("curl", cmd, timeout=30)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def historical_dns_securitytrails(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    if not ctx.cfg.paid_enabled("securitytrails"):
        return None
    cmd = ["curl", "-s",
           f"https://api.securitytrails.com/v1/domain/{domain}/history/dns/a",
           "-H", f"apikey: {ctx.cfg.paid_key('securitytrails')}"]
    r = ctx.execute("curl", cmd, timeout=60)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def viewdns_history(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    cmd = ["curl", "-s", f"https://viewdns.info/iphistory/?domain={domain}",
           "-H", "User-Agent: Mozilla/5.0"]
    r = ctx.execute("curl", cmd, timeout=60)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def censys_certs(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    if not ctx.cfg.paid_enabled("censys"):
        return None
    cmd = ["curl", "-s", "-u", f"{ctx.cfg.paid_key('censys','id')}:{ctx.cfg.paid_key('censys','secret')}",
           "https://search.censys.io/api/v2/certificates/search?per_page=25",
           "-d", f'{{"query":"parsed.issuer.common_name:\\"{domain}\\""}}', "-H", "Content-Type: application/json"]
    r = ctx.execute("curl", cmd, timeout=60)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def cloudflair(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    if not ctx.cfg.paid_enabled("censys"):
        return None
    cmd = ["python3", "cloudflair.py", domain, "-o", str(out),
           "-k", ctx.cfg.paid_key("censys", "id"), "-s", ctx.cfg.paid_key("censys", "secret")]
    r = ctx.execute("cloudflair", cmd, timeout=300)
    return out if out.exists() else None


def verify_origin(ctx: ToolContext, domain: str, origin_ip: str, out: Path) -> Optional[Path]:
    cmd = ["curl", "-vk", "--resolve", f"{domain}:443:{origin_ip}", f"https://{domain}/", "-o", "/dev/null"]
    r = ctx.execute("curl", cmd, timeout=60, log_stdout=False)
    out.write_text(f"origin={origin_ip} returncode={r.returncode}\nstderr tail:\n{r.stderr[-500:]}\n", encoding="utf-8")
    return out
