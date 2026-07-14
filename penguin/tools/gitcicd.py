"""CI/CD and Git reconnaissance wrappers (Block 4.2)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext


def exposed_git_probe(ctx: ToolContext, subs_file: Path, out: Path) -> Optional[Path]:
    import concurrent.futures

    subs = [s.strip() for s in subs_file.read_text(encoding="utf-8").splitlines() if s.strip()]
    if not subs:
        return None

    def check(sub: str) -> Optional[str]:
        # -k: cert trust doesn't matter for a read-only probe. retries=1:
        # this runs once per resolved subdomain, so a single default retry
        # budget (3x, with backoff) per host multiplies into a lot of wasted
        # time across dozens of hosts for what's just a speculative check.
        cmd = ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", f"https://{sub}/.git/HEAD"]
        r = ctx.execute("curl", cmd, timeout=30, retries=1)
        return sub if (r.ok and "200" in r.stdout) else None

    # Dozens of independent per-host probes -- sequentially these could take
    # up to len(subs) * 30s; run them concurrently instead.
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, len(subs))) as ex:
        found = [s for s in ex.map(check, subs) if s]
    if found:
        out.write_text("\n".join(found) + "\n", encoding="utf-8")
        return out
    return None


def docker_registry_catalog(ctx: ToolContext, registry: str, out: Path) -> Optional[Path]:
    cmd = ["curl", "-sk", f"https://{registry}/v2/_catalog"]
    r = ctx.execute("curl", cmd, timeout=60, retries=1)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def trivy_image(ctx: ToolContext, image: str, out: Path) -> Optional[Path]:
    cmd = ["trivy", "image", image, "--format", "json", "-o", str(out)]
    r = ctx.execute("trivy", cmd, timeout=600)
    return out if out.exists() else None


