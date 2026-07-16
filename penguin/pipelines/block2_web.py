"""Block 2 - Web applications, parameters and API recon."""
from __future__ import annotations

import logging
import re
from functools import partial
from pathlib import Path

from ..config import Config
from ..parallel import run_parallel
from ..state import ARTIFACTS, RunState, read_live_urls
from ..tools import content as ct
from ..tools import probe as pb
from ..tools import secrets as sc
from ..tools import api as ap
from ..tools import nuclei_custom as nu
from ..tools._base import ToolContext

logger = logging.getLogger("penguin.block2")

JS_RE = re.compile(r"https?://[^\s'\"]+\.js(\?[^\s'\"]*)?")


def _sanitize_slug(s: str) -> str:
    """Replace Windows-illegal filename characters with underscores."""
    import re as re_
    return re_.sub(r"[^a-z0-9._-]", "_", s.lower())


def _host_labels(h: str) -> list[str]:
    host = re.sub(r"^https?://", "", h).split("/")[0].split(":")[0].lower()
    return [p for p in host.split(".") if p]


def _service_label(h: str) -> str:
    """Group key: the service (subdomain immediately left of the registrable
    domain), with numbered instances clustered together.

    `api.example.com` and `a.api.example.com` both -> `api`; `api0`/`api1`/
    `web-01`/`dev_2` all normalise to `api`/`web`/`dev` so the same service's
    instances form one coverage unit instead of N. `www.example.com` -> `www`
    and `example.com` -> `example`. This is purely structural -- it makes no
    assumption about *which* names are "interesting" (they can be anything:
    hashes, brand names, random tokens), it only groups same-service hosts.
    """
    labels = _host_labels(h)
    raw = labels[-3] if len(labels) >= 3 else (labels[0] if labels else h)
    norm = re.sub(r"[-_.\s]?\d+$", "", raw).rstrip("-_.")
    return norm or raw


def _select_hosts(hosts: list[str], max_hosts: Optional[int]) -> list[str]:
    """Coverage-maximising, cap-aware host selection (name-agnostic).

    A head-only slice (`hosts[:max_hosts]`) keeps e.g. 10x `www` and drops the
    rest of the attack surface, and any keyword/"interesting-name" heuristic
    assumes hostnames look a certain way (they don't -- they can be hashes,
    brand names, random tokens). So selection is driven purely by *coverage*:

       1. group hosts by their (normalised) service label,
       2. take ONE representative per group first -- guarantees every distinct
          service is covered (breadth), no matter what it's called,
       3. distribute the remaining budget round-robin across groups so depth
          is balanced and no service starves,
       4. order groups largest-first as a name-agnostic prioritisation: a
          service with hundreds of instances is clearly a major one, so when
          the budget is smaller than the number of groups it still wins a slot,
       5. top up from anywhere if groups under-fill.

    Deterministic for a given input order.
    """
    if not max_hosts or len(hosts) <= max_hosts:
        return list(hosts)

    from collections import defaultdict

    groups: dict[str, list[str]] = defaultdict(list)
    for h in hosts:
        groups[_service_label(h)].append(h)

    # Largest services first (name-agnostic): when the cap is below the number
    # of distinct services, the biggest ones still get represented. Ties keep
    # input order via stable sort.
    ordered = sorted(groups.items(), key=lambda kv: -len(kv[1]))

    chosen: list[str] = []
    seen: set[str] = set()

    # 1) one representative per group -> every distinct service covered
    for svc, members in ordered:
        if len(chosen) >= max_hosts:
            break
        pick = members[0]
        chosen.append(pick)
        seen.add(pick)

    # 2) round-robin depth across groups (balanced, no starvation)
    if len(chosen) < max_hosts:
        cursors: dict[str, list[str]] = {
            svc: [m for m in members if m not in seen] for svc, members in ordered
        }
        order = [svc for svc, _ in ordered]
        while len(chosen) < max_hosts:
            progressed = False
            for svc in order:
                if len(chosen) >= max_hosts:
                    break
                cur = cursors[svc]
                if cur:
                    nxt = cur.pop(0)
                    chosen.append(nxt)
                    seen.add(nxt)
                    progressed = True
            if not progressed:
                break

    # 3) top up from anywhere if groups under-filled (duplicate hosts, etc.)
    for h in hosts:
        if len(chosen) >= max_hosts:
            break
        if h not in seen:
            chosen.append(h)
            seen.add(h)
    return chosen


def run_block2(cfg: Config, state: RunState, target: dict) -> dict:
    ctx = ToolContext(cfg)
    results: dict = {"endpoints": [], "js_secrets": [], "api": []}
    if not cfg.stage_enabled("web"):
        logger.info("[block2] disabled by config")
        return results

    # #83: use read_live_urls() helper instead of duplicated regex
    hosts = read_live_urls(state.path(ARTIFACTS.LIVE_HTTPX_CSV))
    if not hosts:
        hosts = [f"https://{target['value']}"]

    hosts_file = state.path(ARTIFACTS.LIVE_HOSTS)
    hosts_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

    # ---- tech fingerprint already in httpx; add nuclei tech ----
    # nuclei_tech's -t technologies/ needs the official templates repo, which
    # only custom_only=False scans would otherwise trigger -- block4's
    # nuclei_scan is always custom_only=True, so this is the one remaining
    # call site that needs it fetched first (best-effort).
    nu.nuclei_update(ctx)
    pb.nuclei_tech(ctx, hosts_file, state.path("technologies.txt"))

    # ---- collect JS ----
    # Cap hosts here so both JS-URL collection (below) and dir-fuzz (below)
    # stay bounded on targets with thousands of live hosts. Use an intelligent
    # selection (high-value hosts + even stride sampling) rather than a raw
    # head-slice so coverage is preserved under the cap.
    max_hosts = cfg.general.max_hosts_per_block
    limited_hosts = _select_hosts(hosts, max_hosts)

    js_dir = state.sub("js")
    js_all = state.path("js_urls.txt")
    lines: set[str] = set()

    def _collect_js_for_host(h: str) -> None:
        # Each host writes its own distinct output files, so hosts overlap
        # safely. paramspider relocates results/<domain>.txt internally but the
        # domain is unique per host, so concurrent runs don't clash.
        dom = re.sub(r"^https?://", "", h).split("/")[0]
        dom_safe = _sanitize_slug(dom)
        # #83: removed dead r= assignments on gau/waybackurls (outputs written to file, not used)
        ct.gau(ctx, dom, js_dir / f"gau_{dom_safe}.txt")
        ct.waybackurls(ctx, dom, js_dir / f"wb_{dom_safe}.txt")
        ct.paramspider(ctx, dom, js_dir / f"paramspider_{dom_safe}.txt")

    run_parallel([partial(_collect_js_for_host, h) for h in limited_hosts],
                 max_workers=cfg.general.max_parallel_tools,
                 label="block2 js url collection")
    # katana takes -list of all hosts in one shot, not per-host
    ct.katana(ctx, hosts_file, js_dir / "katana.txt")
    ct.hakrawler(ctx, hosts_file, js_dir / "hakrawler.txt")
    for f in js_dir.glob("*.txt"):
        for l in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            if JS_RE.match(l.strip()):
                lines.add(l.strip())
    # subjs
    ct.subjs(ctx, hosts_file, js_dir / "subjs.txt")
    if (js_dir / "subjs.txt").exists():
        lines |= {l.strip() for l in (js_dir / "subjs.txt").read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()}
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
        param_urls |= {l.strip() for l in f.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()}
    endpoint_chunks: list[str] = []
    if param_urls:
        endpoint_chunks.append("\n".join(sorted(param_urls)) + "\n")
    secret_chunks: list[str] = []

    js_dl_dir = state.sub("js/downloaded")
    js_list = js_alive.read_text(encoding="utf-8", errors="ignore").splitlines() if js_alive.exists() else []

    def _process_js(idx: int, js: str) -> "tuple[Optional[str], Optional[str]]":
        # One task per JS URL: linkfinder + secretfinder analyse the remote URL
        # and curl downloads it to its own distinct {idx}.js file. These are
        # independent across URLs, so the whole fan-out overlaps safely; the
        # per-file output files never collide. Returns the found text per tool
        # so the merged chunks list is identical to the old sequential loop.
        lf = sc.linkfinder(ctx, Path(js))
        sf = sc.secretfinder(ctx, Path(js))
        local_js = js_dl_dir / f"{idx}.js"
        # retries=1: this runs once per discovered JS URL (can be 50-100+), each
        # re-picking a proxy on retry -- at the default 3 attempts, a proxy pool
        # with a high dead-proxy rate turns this single best-effort download
        # step into the dominant cost of the whole block (observed: 30+ min,
        # still running, on a pool full of SOCKS-closed / SSL-handshake
        # failures). One shot per file, same pattern as the cloud.py/api.py/
        # gitcicd.py per-candidate curl loops.
        ctx.execute("curl", ["curl", "-s", "-o", str(local_js), js], timeout=30, retries=1)
        return (lf, sf)

    for out in run_parallel([partial(_process_js, i, js) for i, js in enumerate(js_list)],
                            max_workers=cfg.general.max_parallel_tools,
                            label="block2 js download"):
        if not out:
            continue
        lf, sf = out
        if lf:
            endpoint_chunks.append(lf)
        if sf:
            secret_chunks.append(sf)
    if endpoint_chunks:
        endpoints_file.write_text("".join(endpoint_chunks), encoding="utf-8")
    if secret_chunks:
        secrets_file.write_text("".join(secret_chunks), encoding="utf-8")
    js_files = list(js_dl_dir.glob("*.js"))
    if js_files:
        sc.jsluice(ctx, " ".join(str(f) for f in js_files), state.path("content/jsluice.txt"))
    if endpoints_file.exists():
        results["endpoints"] = endpoints_file.read_text(encoding="utf-8").splitlines()
    if secrets_file.exists():
        results["js_secrets"] = secrets_file.read_text(encoding="utf-8").splitlines()

    # ---- directory fuzz + hidden params ----
    # Configurable wordlist (default raft-medium-directories ~30k instead of the
    # ~220k directory-list-2.3-medium); fall back to the old list if the chosen
    # one isn't present so a missing raft wordlist doesn't silently skip fuzzing.
    wl = cfg.path(cfg.general.dirfuzz_wordlist)
    if not wl.exists():
        fallback = cfg.path("wordlists/directory-list-2.3-medium.txt")
        if fallback.exists():
            wl = fallback
    params_wl = cfg.path("wordlists/params.txt")
    run_ferox = cfg.general.dirfuzz_feroxbuster

    # Split the global HTTP budget across the concurrent per-host fan-out so the
    # *aggregate* outbound socket/request volume stays under the router's
    # NAT/conntrack ceiling. Unbounded (ffuf -t 100 -rate 300 x
    # max_parallel_tools hosts = ~800 live sockets + thousands of TIME_WAIT/sec)
    # this is what dropped the WAN link in block2 -- the HTTP analogue of
    # block1's DNS flood. The per-host tools run serially within a host, so at
    # any instant at most `fanout` of them are live; dividing the global budget
    # by `fanout` keeps the sum at ~threads sockets and ~rate_limit rps overall.
    fanout = max(1, min(cfg.general.max_parallel_tools, len(limited_hosts)))
    per_host_threads = max(1, cfg.general.threads // fanout)
    per_host_rate = max(1, cfg.general.rate_limit // fanout)

    def _dirfuzz_host(h: str) -> None:
        # Tools within a single host stay serial (ffuf+feroxbuster hammer the
        # same target / WAF), but different hosts overlap via run_parallel.
        safe = re.sub(r'[^a-z0-9]', '', h)
        ct.ffuf_dirs(ctx, h, wl, state.path("content") / f"ffuf_{safe}.json",
                     threads=per_host_threads, rate=per_host_rate)
        # feroxbuster is a redundant dir brute by default; gate it behind a flag
        # (issue #2) so we don't pay its cost twice.
        if run_ferox:
            ct.feroxbuster(ctx, h, wl, state.path("content") / f"ferox_{safe}.txt",
                           threads=per_host_threads, rate=per_host_rate)
        ct.arjun(ctx, h, state.path("content") / f"arjun_{safe}.json",
                 threads=per_host_threads)
        if params_wl.exists():
            ct.x8(ctx, h, params_wl, state.path("content") / f"x8_{safe}.json")

    if wl.exists():
        run_parallel([partial(_dirfuzz_host, h) for h in limited_hosts],
                     max_workers=cfg.general.max_parallel_tools,
                     label="block2 dir fuzz")
    else:
        logger.warning("[block2] no dir-fuzz wordlist found (%s, fallback "
                       "directory-list-2.3-medium.txt also missing); skipping "
                       "directory fuzzing -- run scripts/install.sh to fetch wordlists",
                       cfg.general.dirfuzz_wordlist)

    # ---- API recon ----
    kite = cfg.path("wordlists/routes-large.kite")
    api_dir = state.sub("api")

    def _api_probe(idx: int, h: str) -> list[str]:
        # One task per host: the three probes stay serial *within* a host (so a
        # single server is never hammered by concurrent probes) while different
        # hosts overlap. Each probe writes its own distinct file. Returns the
        # found-output paths in order so the merged results list is identical to
        # the old sequential loop.
        # Slug alone can collide (e.g. "api.example.com" and "api-example.com"
        # both -> "apiexamplecom"), which would let two concurrent tasks clobber
        # the same file; key on host index too, same as block3's bucket parts.
        safe = re.sub(r'[^a-z0-9]', '', h.lower())
        found: list[str] = []
        swagger_out = ap.probe_swagger(ctx, h, api_dir / f"swagger_{idx}_{safe}.txt")
        if swagger_out:
            found.append(str(swagger_out))
        graphql_out = ap.graphql_introspection(ctx, h.rstrip("/") + "/graphql", api_dir / f"graphql_{idx}_{safe}.json")
        if graphql_out:
            found.append(str(graphql_out))
        grpc_host = re.sub(r"^https?://", "", h).split("/")[0]
        grpc_out = ap.grpcurl_list(ctx, f"{grpc_host}:443", api_dir / f"grpc_{idx}_{safe}.txt")
        if grpc_out:
            found.append(str(grpc_out))
        return found

    for found in run_parallel([partial(_api_probe, i, h) for i, h in enumerate(limited_hosts)],
                              max_workers=cfg.general.max_parallel_tools,
                              label="block2 api recon"):
        if found:
            results["api"].extend(found)
    if kite.exists():
        ap.kiterunner(ctx, hosts_file, kite, state.path("api/kiterunner.json"))
        results["api"].append("kiterunner")
    return results
