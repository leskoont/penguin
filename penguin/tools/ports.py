"""Port scanning wrappers (Block 1.1, Block 3.1)."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ._base import ToolContext, ok_path

DB_PORTS = "22,80,443,1433,1521,2375,2376,2379,3000,3306,5000,5432,5984,6379,7474,8080,8443,8529,9042,9200,9300,11211,27017"

_NMAP_HOST_RE = re.compile(r"Nmap scan report for (\S+)")
_NMAP_PORT_RE = re.compile(r"^(\d+)/tcp\s+open\b")


def parse_masscan_open(out: Optional[Path]) -> list[str]:
    """Open ``ip:port`` entries from masscan ``-oL`` output.

    masscan always writes the output file (with a ``#masscan`` header/footer)
    even when nothing is open, so the file merely *existing* is not a hit --
    only ``open tcp <port> <ip>`` lines are. Returns a deduped list."""
    if not out or not out.exists():
        return []
    found: list[str] = []
    seen: set[str] = set()
    for line in out.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split()
        # "open tcp <port> <ip> <timestamp>"
        if len(parts) >= 4 and parts[0] == "open" and parts[2].isdigit():
            hp = f"{parts[3]}:{parts[2]}"
            if hp not in seen:
                seen.add(hp)
                found.append(hp)
    return found


def parse_nmap_open(out: Optional[Path]) -> list[str]:
    """Open ``host:port`` entries from nmap ``-oN`` normal output.

    nmap always writes the report file even when every port is closed/filtered,
    so presence is not a hit -- only ``<port>/tcp open`` rows are, attributed to
    the most recent ``Nmap scan report for <host>`` line. Returns a deduped list."""
    if not out or not out.exists():
        return []
    found: list[str] = []
    seen: set[str] = set()
    host = ""
    for line in out.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = _NMAP_HOST_RE.search(line)
        if m:
            host = m.group(1)
            continue
        pm = _NMAP_PORT_RE.match(line.strip())
        if pm and host:
            hp = f"{host}:{pm.group(1)}"
            if hp not in seen:
                seen.add(hp)
                found.append(hp)
    return found


def masscan(ctx: ToolContext, ranges_file: Path, out: Path, ports: str = "80,443,8080,8443") -> Optional[Path]:
    cmd = ["masscan", "-iL", str(ranges_file), "-p", ports, "--rate=10000", "-oL", str(out)]
    r = ctx.execute("masscan", cmd, timeout=1800)
    return ok_path(r, out)


def nmap_nse(ctx: ToolContext, hosts_file: Path, out: Path, ports: str = DB_PORTS) -> Optional[Path]:
    cmd = ["nmap", "-sV", "-sC", "-Pn", "-T4", "-p", ports,
           "--script", "*-info,*-enum,mongodb-info,redis-info,mysql-info,pgsql-brute,vulners",
           "-iL", str(hosts_file), "-oN", str(out)]
    r = ctx.execute("nmap", cmd, timeout=1800)
    return ok_path(r, out)


def redis_cli(ctx: ToolContext, host: str) -> Optional[str]:
    cmd = ["redis-cli", "-h", host, "INFO", "server"]
    r = ctx.execute("redis-cli", cmd, timeout=30)
    return r.stdout if r.ok else None
