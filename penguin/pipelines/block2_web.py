"""Block 2 - Web applications, parameters and API recon."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..config import Config
from ..state import RunState
from ..tools import content as ct
from ..tools import probe as pb
from ..tools import secrets as sc
from ..tools import api as ap
from ..tools._base import ToolContext

logger = logging.getLogger("penguin.block2")

JS_RE = re.compile(r"https?://[^\s'\"]+\.js(\?[^\s'\"]*)?")


def run_block2(cfg: Config, state: RunState, target: dict) -> dict:
    ctx = ToolContext(cfg)
    results: dict = {"endpoints": [], "js_secrets": [], "api": []}
    if not cfg.stage_enabled("web"):
        logger.info("[block2] disabled by config")
        return results

    interesting = state.read_lines("live/httpx.csv")
    # derive host list from csv (first column = url)
    hosts = []
    for line in interesting:
        m = re.match(r'"??(https?://[^",]+)', line)
        if m:
            hosts.append(m.group(1).strip('"'))
    if not hosts:
        hosts = [f"https://{target['value']}"]

    hosts_file = state.path("live_hosts.txt")
    hosts_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

    # ---- tech fingerprint already in httpx; add nuclei tech ----
    pb.nuclei_tech(ctx, hosts_file, state.path("technologies.txt"))

    # ---- collect JS ----
    js_dir = state.sub("js")
    js_all = state.path("js_urls.txt")
    lines: set[str] = set()
    for h in hosts:
        dom = re.sub(r"^https?://", "", h).split("/")[0]
        r = ct.gau(ctx, dom, js_dir / f"gau_{dom}.txt")
        r = ct.katana(ctx, hosts_file, js_dir / f"katana_{dom}.txt")
        r = ct.waybackurls(ctx, dom, js_dir / f"wb_{dom}.txt")
    for f in js_dir.glob("*.txt"):
        for l in f.read_text(encoding="utf-8").splitlines():
            if JS_RE.match(l.strip()):
                lines.add(l.strip())
    # subjs
    ct.subjs(ctx, hosts_file, js_dir / "subjs.txt")
    if (js_dir / "subjs.txt").exists():
        lines |= {l.strip() for l in (js_dir / "subjs.txt").read_text(encoding="utf-8").splitlines() if l.strip()}
    js_all.write_text("\n".join(sorted(lines)) + "\n", encoding="utf-8")

    js_alive = state.path("js_alive.txt")
    pb.httpx_simple(ctx, js_all, js_alive)

    # ---- extract endpoints + secrets ----
    endpoints_file = state.path("content/endpoints.txt")
    endpoints_file.parent.mkdir(parents=True, exist_ok=True)
    secrets_file = state.path("content/js_secrets.txt")
    for js in (js_alive.read_text(encoding="utf-8").splitlines() if js_alive.exists() else []):
        sc.linkfinder(ctx, Path(js), endpoints_file)
        sc.secretfinder(ctx, Path(js), secrets_file)
    if endpoints_file.exists():
        results["endpoints"] = endpoints_file.read_text(encoding="utf-8").splitlines()
    if secrets_file.exists():
        results["js_secrets"] = secrets_file.read_text(encoding="utf-8").splitlines()

    # ---- directory fuzz + hidden params ----
    wl = cfg.path("wordlists/directory-list-2.3-medium.txt")
    if wl.exists():
        for h in hosts[:10]:
            ct.ffuf_dirs(ctx, h, wl, state.path("content") / f"ffuf_{re.sub(r'[^a-z0-9]','',h)}.json")
            ct.feroxbuster(ctx, h, wl, state.path("content") / f"ferox_{re.sub(r'[^a-z0-9]','',h)}.txt")
            ct.arjun(ctx, h, state.path("content") / f"arjun_{re.sub(r'[^a-z0-9]','',h)}.json")

    # ---- API recon ----
    kite = cfg.path("wordlists/routes-large.kite")
    for h in hosts[:10]:
        ap.probe_swagger(ctx, h, state.path("api/swagger.txt"))
        ap.graphql_introspection(ctx, h.rstrip("/") + "/graphql", state.path("api/graphql.json"))
    if kite.exists():
        ap.kiterunner(ctx, hosts_file, kite, state.path("api/kiterunner.json"))
        results["api"].append("kiterunner")
    return results
