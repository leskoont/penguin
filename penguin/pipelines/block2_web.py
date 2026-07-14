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
from ..tools import nuclei_custom as nu
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
    # nuclei_tech's -t technologies/ needs the official templates repo, which
    # only custom_only=False scans would otherwise trigger -- block4's
    # nuclei_scan is always custom_only=True, so this is the one remaining
    # call site that needs it fetched first (best-effort).
    nu.nuclei_update(ctx)
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
        ct.paramspider(ctx, dom, js_dir / f"paramspider_{dom}.txt")
    ct.hakrawler(ctx, hosts_file, js_dir / "hakrawler.txt")
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

    # paramspider mines parametrized URLs (not just .js) -- fold those into endpoints too
    param_urls: set[str] = set()
    for f in js_dir.glob("paramspider_*.txt"):
        param_urls |= {l.strip() for l in f.read_text(encoding="utf-8").splitlines() if l.strip()}
    if param_urls:
        with open(endpoints_file, "a", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(param_urls)) + "\n")

    js_dl_dir = state.sub("js/downloaded")
    for i, js in enumerate(js_alive.read_text(encoding="utf-8").splitlines() if js_alive.exists() else []):
        sc.linkfinder(ctx, Path(js), endpoints_file)
        sc.secretfinder(ctx, Path(js), secrets_file)
        local_js = js_dl_dir / f"{i}.js"
        # retries=1: this runs in a loop over every discovered JS URL (can be
        # 50-100+), each re-picking a proxy on retry -- at the default 3
        # attempts, a proxy pool with a high dead-proxy rate turns this single
        # best-effort download step into the dominant cost of the whole block
        # (observed: 30+ min, still running, on a pool full of SOCKS-closed /
        # SSL-handshake failures). One shot per file, same pattern as the
        # cloud.py/api.py/gitcicd.py per-candidate curl loops.
        ctx.execute("curl", ["curl", "-s", "-o", str(local_js), js], timeout=30, retries=1)
    js_files = list(js_dl_dir.glob("*.js"))
    if js_files:
        sc.jsluice(ctx, " ".join(str(f) for f in js_files), state.path("content/jsluice.txt"))
    if endpoints_file.exists():
        results["endpoints"] = endpoints_file.read_text(encoding="utf-8").splitlines()
    if secrets_file.exists():
        results["js_secrets"] = secrets_file.read_text(encoding="utf-8").splitlines()

    # ---- directory fuzz + hidden params ----
    wl = cfg.path("wordlists/directory-list-2.3-medium.txt")
    params_wl = cfg.path("wordlists/params.txt")
    if wl.exists():
        for h in hosts[:10]:
            safe = re.sub(r'[^a-z0-9]', '', h)
            ct.ffuf_dirs(ctx, h, wl, state.path("content") / f"ffuf_{safe}.json")
            ct.feroxbuster(ctx, h, wl, state.path("content") / f"ferox_{safe}.txt")
            ct.arjun(ctx, h, state.path("content") / f"arjun_{safe}.json")
            if params_wl.exists():
                ct.x8(ctx, h, params_wl, state.path("content") / f"x8_{safe}.json")

    # ---- API recon ----
    kite = cfg.path("wordlists/routes-large.kite")
    api_dir = state.sub("api")
    for h in hosts[:10]:
        safe = re.sub(r'[^a-z0-9]', '', h)
        swagger_out = ap.probe_swagger(ctx, h, api_dir / f"swagger_{safe}.txt")
        if swagger_out:
            results["api"].append(str(swagger_out))
        graphql_out = ap.graphql_introspection(ctx, h.rstrip("/") + "/graphql", api_dir / f"graphql_{safe}.json")
        if graphql_out:
            results["api"].append(str(graphql_out))
        grpc_host = re.sub(r"^https?://", "", h).split("/")[0]
        grpc_out = ap.grpcurl_list(ctx, f"{grpc_host}:443", api_dir / f"grpc_{safe}.txt")
        if grpc_out:
            results["api"].append(str(grpc_out))
    if kite.exists():
        ap.kiterunner(ctx, hosts_file, kite, state.path("api/kiterunner.json"))
        results["api"].append("kiterunner")
    return results
