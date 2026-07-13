"""CI/CD and Git reconnaissance wrappers (Block 4.2)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext


def exposed_git_probe(ctx: ToolContext, subs_file: Path, out: Path) -> Optional[Path]:
    found = []
    for sub in subs_file.read_text(encoding="utf-8").splitlines():
        sub = sub.strip()
        if not sub:
            continue
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"https://{sub}/.git/HEAD"]
        r = ctx.execute("curl", cmd, timeout=30)
        if r.ok and "200" in r.stdout:
            found.append(sub)
    if found:
        out.write_text("\n".join(found) + "\n", encoding="utf-8")
        return out
    return None


def docker_registry_catalog(ctx: ToolContext, registry: str, out: Path) -> Optional[Path]:
    cmd = ["curl", "-s", f"https://{registry}/v2/_catalog"]
    r = ctx.execute("curl", cmd, timeout=60)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def trivy_image(ctx: ToolContext, image: str, out: Path) -> Optional[Path]:
    cmd = ["trivy", "image", image, "--format", "json", "-o", str(out)]
    r = ctx.execute("trivy", cmd, timeout=600)
    return out if out.exists() else None


