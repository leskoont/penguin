"""Block 3 - Database & cloud storage recon."""
from __future__ import annotations

import logging
import re
from functools import partial
from pathlib import Path

from ..config import Config
from ..parallel import run_parallel
from ..state import ARTIFACTS, RunState
from ..tools import ports as pt
from ..tools import cloud as cl
from ..tools import resolve as rs
from ..tools._base import ToolContext

logger = logging.getLogger("penguin.block3")

DB_PORTS = pt.DB_PORTS


def run_block3(cfg: Config, state: RunState, target: dict) -> dict:
    ctx = ToolContext(cfg)
    results: dict = {"open_db": [], "buckets": []}
    if not cfg.stage_enabled("cloud_db"):
        logger.info("[block3] disabled by config")
        return results

    value = target["value"]
    domain = re.sub(r"^https?://", "", value).split("/")[0]

    # ---- open DB scan (masscan over prefixes if cidr, else over live hosts) ----
    hosts = state.read_lines(ARTIFACTS.RESOLVED) or state.read_lines(ARTIFACTS.LIVE_HTTPX_CSV)
    if hosts:
        ip_file = state.path("db_hosts.txt")
        ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        # resolved.txt (puredns resolve -w) holds hostnames, not IPs -- pull any
        # literal IPs directly (e.g. cidr/ip targets), then resolve the rest via dnsx
        ips: set[str] = {h.strip() for h in hosts[:200] if ip_re.match(h.strip())}
        resolved_txt = state.path(ARTIFACTS.RESOLVED)
        resolvers = cfg.path(cfg.general.resolvers_file)
        if resolved_txt.exists() and resolvers.exists():
            dnsx_ips_out = state.path("cloud/db_hosts_dnsx.txt")
            rs.dnsx_ips(ctx, resolved_txt, resolvers, dnsx_ips_out)
            if dnsx_ips_out.exists():
                ips |= {l.strip() for l in dnsx_ips_out.read_text(encoding="utf-8").splitlines() if ip_re.match(l.strip())}
        ips = sorted(ips)[:200]
        if ips:
            ip_file.write_text("\n".join(ips) + "\n", encoding="utf-8")
            masscan_out = state.path("cloud/db_masscan.txt")
            pt.masscan(ctx, ip_file, masscan_out, ports=DB_PORTS)
            nmap_out = state.path("cloud/db_nmap.txt")
            pt.nmap_nse(ctx, ip_file, nmap_out, ports=DB_PORTS)
            if nmap_out.exists():
                results["open_db"].append(str(nmap_out))

            redis_hosts: set[str] = set()
            if masscan_out.exists():
                results["open_db"].append(str(masscan_out))
                for line in masscan_out.read_text(encoding="utf-8").splitlines():
                    # masscan -oL format: "open tcp <port> <ip> <timestamp>"
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == "open" and parts[2] == "6379":
                        redis_hosts.add(parts[3])
            if redis_hosts:
                redis_out = state.path("cloud/redis_info.txt")
                for rh in sorted(redis_hosts):
                    info = pt.redis_cli(ctx, rh)
                    if info:
                        with open(redis_out, "a", encoding="utf-8") as fh:
                            fh.write(f"=== {rh} ===\n{info}\n")
                if redis_out.exists():
                    results["open_db"].append(str(redis_out))

    # ---- bucket discovery ----
    bucket_out = state.path("cloud/buckets.txt")
    bucket_out.parent.mkdir(parents=True, exist_ok=True)
    candidates = [domain, domain.replace(".", "-"), domain.split(".")[0]]
    # aws/azure/gcs probe cloud-provider endpoints (s3/blob/storage), not the
    # target, so they overlap safely. Each only *appends* to its `out` on a hit,
    # so concurrent writes to one shared file would interleave -- give every
    # probe its own part file (keyed by candidate *index*, since slugs of
    # "x.com" and "x-com" could collide), fan them out, then merge.
    bucket_parts: list[Path] = []
    bucket_tasks: list = []
    for ci, b in enumerate(candidates):
        for pname, pfn in (("aws", cl.aws_s3_ls), ("azure", cl.azure_probe), ("gcs", cl.gcs_probe)):
            part = state.path(f"cloud/_bucket_{pname}_{ci}.txt")
            bucket_parts.append(part)
            bucket_tasks.append(partial(pfn, ctx, b, part))
    run_parallel(bucket_tasks, max_workers=cfg.general.max_parallel_tools,
                 label="block3 bucket probes")
    merged = [p.read_text(encoding="utf-8") for p in bucket_parts if p.exists()]
    if merged:
        # only (re)create buckets.txt when something was actually found, matching
        # the old append-on-hit semantics the downstream `.exists()` guard relies on
        bucket_out.write_text("".join(merged), encoding="utf-8")
    cl.cloud_enum(ctx, domain.split(".")[0], state.path("cloud/cloud_enum.txt"))

    cand_file = state.path("cloud/bucket_candidates.txt")
    cand_file.write_text("\n".join(candidates) + "\n", encoding="utf-8")
    s3scan_out = state.path("cloud/s3scanner.txt")
    cl.s3scanner(ctx, cand_file, s3scan_out)
    if s3scan_out.exists():
        results["buckets"].append(str(s3scan_out))

    if bucket_out.exists():
        results["buckets"] += bucket_out.read_text(encoding="utf-8").splitlines()
        loot_dir = state.sub("cloud/loot")
        for line in bucket_out.read_text(encoding="utf-8").splitlines():
            # BucketLoot requires a fully-qualified https:// URL, not a bare
            # bucket name/s3:// scheme -- reconstruct the provider-specific
            # URL the same way aws_s3_ls/gcs_probe already build it above.
            s3_m = re.search(r"s3://(\S+)", line)
            gcs_m = re.search(r"GCS:\s*(\S+)", line)
            if s3_m:
                bucket = s3_m.group(1)
                # path-style addressing avoids virtual-hosted-style breaking
                # AWS's wildcard TLS cert when `bucket` is itself a dotted
                # domain (e.g. "example.com.s3.amazonaws.com" fails hostname
                # verification against the single-label wildcard cert).
                bucket_url = f"https://s3.amazonaws.com/{bucket}"
            elif gcs_m:
                bucket = gcs_m.group(1)
                bucket_url = f"https://storage.googleapis.com/{bucket}"
            else:
                continue
            # tag the filename with the provider: candidates are probed
            # against aws/azure/gcs in parallel, so an s3 hit and a gcs hit
            # for the same bucket-name candidate would otherwise collide on
            # the same loot_dir path and silently overwrite each other.
            loot_out = loot_dir / f"{'s3' if s3_m else 'gcs'}_{bucket.replace('/', '_')}.json"
            cl.bucketloot(ctx, bucket_url, loot_out)
    return results
