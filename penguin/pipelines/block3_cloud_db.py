"""Block 3 - Database & cloud storage recon."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..config import Config
from ..state import RunState
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
    hosts = state.read_lines("resolved.txt") or state.read_lines("live/httpx.csv")
    if hosts:
        ip_file = state.path("db_hosts.txt")
        ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        # resolved.txt (puredns resolve -w) holds hostnames, not IPs -- pull any
        # literal IPs directly (e.g. cidr/ip targets), then resolve the rest via dnsx
        ips: set[str] = {h.strip() for h in hosts[:200] if ip_re.match(h.strip())}
        resolved_txt = state.path("resolved.txt")
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
    for b in candidates:
        cl.aws_s3_ls(ctx, b, bucket_out)
        cl.azure_probe(ctx, b, bucket_out)
        cl.gcs_probe(ctx, b, bucket_out)
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
            m = re.search(r"s3://(\S+)", line) or re.search(r"GCS:\s*(\S+)", line)
            if m:
                cl.bucketloot(ctx, m.group(1), loot_dir / m.group(1).replace("/", "_"))
    return results
