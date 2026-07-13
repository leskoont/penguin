"""Port scanning wrappers (Block 1.1, Block 3.1)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext

DB_PORTS = "22,80,443,1433,1521,2375,2376,2379,3000,3306,5000,5432,5984,6379,7474,8080,8443,8529,9042,9200,9300,11211,27017"


def masscan(ctx: ToolContext, ranges_file: Path, out: Path, ports: str = "80,443,8080,8443") -> Optional[Path]:
    cmd = ["masscan", "-iL", str(ranges_file), "-p", ports, "--rate=10000", "-oL", str(out)]
    r = ctx.execute("masscan", cmd, timeout=1800)
    return out if out.exists() else None


def nmap_nse(ctx: ToolContext, hosts_file: Path, out: Path, ports: str = DB_PORTS) -> Optional[Path]:
    cmd = ["nmap", "-sV", "-sC", "-Pn", "-T4", "-p", ports,
           "--script", "*-info,*-enum,mongodb-info,redis-info,mysql-info,pgsql-brute,vulners",
           "-iL", str(hosts_file), "-oN", str(out)]
    r = ctx.execute("nmap", cmd, timeout=1800)
    return out if out.exists() else None


def redis_cli(ctx: ToolContext, host: str) -> Optional[str]:
    cmd = ["redis-cli", "-h", host, "INFO", "server"]
    r = ctx.execute("redis-cli", cmd, timeout=30)
    return r.stdout if r.ok else None
