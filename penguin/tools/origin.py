"""Origin-IP / Cloudflare-bypass wrappers (Block 4.1)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext, ok_path


def _curlcfg_escape(value: str) -> str:
    """Escape a value for use inside a double-quoted curl -K config directive."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def dig_resolve(ctx: ToolContext, host: str, resolver: str, out: Path) -> Optional[str]:
    cmd = ["dig", host, "@" + resolver, "+short"]
    r = ctx.execute("dig", cmd, timeout=30)
    if r.ok:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(f"{host}@{resolver}: {r.stdout.strip()}\n")
        return r.stdout.strip()
    return None


def cloudflare_trace(ctx: ToolContext, url: str, out: Path) -> Optional[Path]:
    cmd = ["curl", "-sk", f"{url}/cdn-cgi/trace"]
    r = ctx.execute("curl", cmd, timeout=30)
    if r.ok:
        # Validate response contains actual trace data (not HTML/404 body)
        # Valid trace has key=value lines and is not HTML
        body = r.stdout.strip()
        if body and not body.lower().startswith("<") and "=" in body:
            out.write_text(r.stdout, encoding="utf-8")
            return out
    return None


def historical_dns_securitytrails(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    if not ctx.cfg.paid_enabled("securitytrails"):
        return None
    key = _curlcfg_escape(ctx.cfg.paid_key("securitytrails"))
    directives = [f'header = "apikey: {key}"']
    r = ctx.curl_with_secret(
        [f"https://api.securitytrails.com/v1/domain/{domain}/history/dns/a"], directives, timeout=60
    )
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def viewdns_history(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    cmd = ["curl", "-sk", f"https://viewdns.info/iphistory/?domain={domain}",
           "-H", "User-Agent: Mozilla/5.0"]
    r = ctx.execute("curl", cmd, timeout=60)
    if r.ok:
        # Validate response is not empty and not a WAF/error page (HTML check)
        body = r.stdout.strip()
        if body and not body.lower().startswith("<!doctype") and not body.lower().startswith("<html"):
            out.write_text(r.stdout, encoding="utf-8")
            return out
    return None


def censys_certs(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    if not ctx.cfg.paid_enabled("censys"):
        return None
    user = _curlcfg_escape(f"{ctx.cfg.paid_key('censys', 'id')}:{ctx.cfg.paid_key('censys', 'secret')}")
    directives = [f'user = "{user}"']
    r = ctx.curl_with_secret(
        [
            "https://search.censys.io/api/v2/certificates/search?per_page=25",
            "-d", f'{{"query":"parsed.issuer.common_name:\\"{domain}\\""}}',
            "-H", "Content-Type: application/json",
        ],
        directives,
        timeout=60,
    )
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def cloudflair(ctx: ToolContext, domain: str, out: Path) -> Optional[Path]:
    if not ctx.cfg.paid_enabled("censys"):
        return None
    # CloudFlair reads CENSYS_API_ID / CENSYS_API_SECRET from the environment
    # when -k/-s are omitted -- keeps the key out of argv (ps/proc/pid/cmdline).
    cmd = ["python3", "cloudflair.py", domain, "-o", str(out)]
    r = ctx.execute(
        "cloudflair", cmd, timeout=300,
        extra_env={
            "CENSYS_API_ID": ctx.cfg.paid_key("censys", "id"),
            "CENSYS_API_SECRET": ctx.cfg.paid_key("censys", "secret"),
        },
    )
    return ok_path(r, out)


def verify_origin(ctx: ToolContext, domain: str, origin_ip: str, out: Path) -> Optional[Path]:
    # retries=1: called in a loop over every IP-looking string scraped from
    # dig/cf_trace/viewdns/securitytrails/censys output -- same "loop over
    # many candidates" shape as cloud.py's azure_probe/gcs_probe, so it gets
    # the same one-shot treatment instead of the default 3x proxy-repick budget.
    cmd = ["curl", "-vk", "--resolve", f"{domain}:443:{origin_ip}", f"https://{domain}/", "-o", "/dev/null"]
    r = ctx.execute("curl", cmd, timeout=60, log_stdout=False, retries=1)
    out.write_text(f"origin={origin_ip} returncode={r.returncode}\nstderr tail:\n{r.stderr[-500:]}\n", encoding="utf-8")
    return out
