"""Block 3 - Database & cloud storage recon."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..config import Config
from ..state import RunState
from ..tools import ports as pt
from ..tools import cloud as cl
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
        # take IPs from resolved file (one per line)
        ip_file = state.path("db_hosts.txt")
        ips = []
        for h in hosts[:200]:
            h = h.strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h):
                ips.append(h)
        if ips:
            ip_file.write_text("\n".join(ips) + "\n", encoding="utf-8")
            nmap_out = state.path("cloud/db_nmap.txt")
            pt.nmap_nse(ctx, ip_file, nmap_out, ports=DB_PORTS)
            if nmap_out.exists():
                results["open_db"].append(str(nmap_out))

    # ---- bucket discovery ----
    bucket_out = state.path("cloud/buckets.txt")
    bucket_out.parent.mkdir(parents=True, exist_ok=True)
    candidates = [domain, domain.replace(".", "-"), domain.split(".")[0]]
    for b in candidates:
        cl.aws_s3_ls(ctx, b, bucket_out)
        cl.azure_probe(ctx, b, bucket_out)
        cl.gcs_probe(ctx, b, bucket_out)
    cl.cloud_enum(ctx, domain.split(".")[0], state.path("cloud/cloud_enum.txt"))
    if bucket_out.exists():
        results["buckets"] = bucket_out.read_text(encoding="utf-8").splitlines()
    return results
