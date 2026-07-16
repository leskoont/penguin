"""penguin - configuration loader.

Loads ``config/config.yaml`` and overlays environment variables.
Paid/OSINT API keys are read from the environment ONLY and are never
stored in the yaml file. Every paid integration is disabled by default.
"""
from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = ROOT / "config" / "config.yaml"


@dataclass
class ProxyConfig:
    enabled: bool = True
    proxifly: str = "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt"
    iplocate: str = "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt"
    validate: bool = True
    test_url: str = "http://example.com"
    # #3: 5s -> 3s. Validation is pure I/O wait; a shorter per-candidate timeout
    # drops dead proxies faster so the working pool converges sooner.
    timeout: int = 3
    # #87/#3: 50 -> 200 concurrent validation workers (I/O-bound, not
    # CPU-bound). 4000 candidates at a 3s timeout across 200 workers is ~60s
    # instead of ~7 min.
    validate_workers: int = 200
    # #3: reuse a previously validated pool within this many minutes instead of
    # re-validating ~4000 candidates on every run (0 disables the cache).
    cache_ttl_minutes: int = 60
    protocol_preference: str = "http"  # http | socks5 | any
    pool_file: str = "results/proxies/proxies_valid.txt"
    rotate: str = "roundrobin"  # roundrobin | random | fastest


@dataclass
class PaidService:
    enabled: bool = False
    api_key_env: str = ""
    api_id_env: str = ""
    api_secret_env: str = ""


@dataclass
class NotifyConfig:
    enabled: bool = False
    provider: str = "slack"  # slack | discord | telegram
    webhook_env: str = "PENGUIN_NOTIFY_WEBHOOK"
    notify_on: list = field(default_factory=lambda: ["new_subdomains", "critical_findings"])


@dataclass
class ContinuousConfig:
    enabled: bool = False
    interval: str = "6h"  # parsed as N[h|m|d]


@dataclass
class GeneralConfig:
    threads: int = 50
    rate_limit: int = 100
    timeout: int = 30
    resolvers_file: str = "wordlists/resolvers.txt"
    output_dir: str = "results"
    user_agent: str = "penguin-recon"
    wordlists_dir: str = "wordlists"
    retry_attempts: int = 2
    retry_backoff: float = 2.0
    screenshots: bool = False
    # Max independent tool subprocesses to fan out concurrently at the *safe*
    # parallel points (block1 passive enum, permutation generators, block4
    # origin discovery, block2 js/api/dir-fuzz/gau, block1 dnsx resolve).
    # These are network-bound waits on distinct output files, so overlapping
    # them shortens wall-clock without contending for CPU. Kept modest by
    # default; raise if the host/network can take it. Set to 1 to force the
    # old fully-sequential behaviour.
    max_parallel_tools: int = 8
    # Max number of hosts to process per block (e.g. directory brute-force,
    # API probes in block2, open DB scanning in block3). Set to None for
    # unlimited. Keeps scanning time bounded when target has thousands of
    # live hosts. Used as: hosts[:max_hosts_per_block].
    max_hosts_per_block: Optional[int] = 50
    # Block3 (open-DB/cloud) fans out over many IPs via masscan/nmap and gets a
    # larger cap than the web/infra stages. Its own knob so an explicit
    # max_hosts_per_block value is never silently overridden. None = unlimited.
    max_hosts_block3: Optional[int] = 100
    # Dir-fuzz wordlist knob (issue #2). Default raft-medium-directories (~30k)
    # instead of directory-list-2.3-medium (~220k). If the chosen file is
    # missing, block2 falls back to wordlists/directory-list-2.3-medium.txt.
    dirfuzz_wordlist: str = "wordlists/raft-medium-directories.txt"
    # feroxbuster is a redundant dir brute vs ffuf; keep it off by default and
    # enable only when a second engine is explicitly wanted (issue #2).
    dirfuzz_feroxbuster: bool = False


@dataclass
class Config:
    general: GeneralConfig = field(default_factory=GeneralConfig)
    stages: dict = field(default_factory=lambda: {
        "infra": True, "web": True, "cloud_db": True, "elite": True
    })
    tools: dict = field(default_factory=dict)
    proxies: ProxyConfig = field(default_factory=ProxyConfig)
    paid: dict = field(default_factory=lambda: {
        "shodan": PaidService(api_key_env="SHODAN_KEY"),
        "censys": PaidService(api_id_env="CENSYS_ID", api_secret_env="CENSYS_SECRET"),
        "securitytrails": PaidService(api_key_env="SECURITYTRAILS_KEY"),
        "chaos": PaidService(api_key_env="CHAOS_KEY"),
        "github": PaidService(api_key_env="GITHUB_TOKEN"),
        "grayhat": PaidService(api_key_env="GRAYHAT_KEY"),
        "netlas": PaidService(api_key_env="NETLAS_KEY"),
        "fofa": PaidService(api_key_env="FOFA_KEY"),
    })
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    continuous: ContinuousConfig = field(default_factory=ContinuousConfig)
    raw: dict = field(default_factory=dict)

    # ----- resolved paths -----
    def root(self) -> Path:
        return ROOT

    def path(self, *parts: str) -> Path:
        p = Path(*parts)
        if p.is_absolute():
            return p
        return (ROOT / p)

    # ----- helpers -----
    def stage_enabled(self, name: str) -> bool:
        return bool(self.stages.get(name, False))

    def tool_setting(self, tool: str, key: str, default: Any = None) -> Any:
        return self.tools.get(tool, {}).get(key, default)

    def paid_enabled(self, name: str) -> bool:
        svc = self.paid.get(name)
        if not svc:
            return False
        if not svc.enabled:
            return False
        # require at least one key present in env
        for env_name in (svc.api_key_env, svc.api_id_env, svc.api_secret_env):
            if env_name and os.environ.get(env_name):
                return True
        return False

    def paid_key(self, name: str, kind: str = "key") -> str:
        svc = self.paid.get(name)
        if not svc:
            return ""
        env = svc.api_key_env if kind == "key" else (svc.api_id_env if kind == "id" else svc.api_secret_env)
        return os.environ.get(env, "") if env else ""


def _apply_section(obj: Any, data: dict) -> None:
    for f in fields(obj):
        if f.name in data:
            val = data[f.name]
            if isinstance(val, dict) and isinstance(getattr(obj, f.name), dict):
                getattr(obj, f.name).update(val)
            elif isinstance(val, dict) and hasattr(getattr(obj, f.name), "__dataclass_fields__"):
                _apply_section(getattr(obj, f.name), val)
            else:
                setattr(obj, f.name, val)


def load(config_path: str | Path | None = None) -> Config:
    cfg = Config()
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    if path.exists():
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        cfg.raw = data
        if "general" in data:
            _apply_section(cfg.general, data["general"])
        if "stages" in data:
            cfg.stages.update(data["stages"])
        if "tools" in data:
            cfg.tools.update(data["tools"])
        if "proxies" in data:
            _apply_section(cfg.proxies, data["proxies"])
        if "paid" in data:
            for name, svc in data["paid"].items():
                if name in cfg.paid:
                    _apply_section(cfg.paid[name], svc)
                else:
                    if isinstance(svc, dict):
                        # Filter to only known PaidService fields to avoid crashes on unknown YAML keys
                        known_fields = {f.name for f in dataclasses.fields(PaidService)}
                        svc_filtered = {k: v for k, v in svc.items() if k in known_fields}
                        cfg.paid[name] = PaidService(**svc_filtered)
                    else:
                        cfg.paid[name] = svc
        if "notify" in data:
            _apply_section(cfg.notify, data["notify"])
        if "continuous" in data:
            _apply_section(cfg.continuous, data["continuous"])
    return cfg


def load_targets(targets_file: str | Path | None = None) -> list[dict]:
    """Parse targets.txt. Each non-comment line: ``<type>:<value>`` or bare ``<value>``.

    type is one of: domain, asn, cidr, org, url. Default type = domain.
    Bare URLs (starting with http://, https://, or containing ://) are auto-detected.
    """
    path = Path(targets_file) if targets_file else (ROOT / "config" / "targets.txt")
    targets: list[dict] = []
    if not path.exists():
        return targets
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # #89: Check for explicit type prefix
        if ":" in line:
            prefix, value = line.split(":", 1)
            if prefix in ("domain", "asn", "cidr", "org", "url"):
                targets.append({"type": prefix, "value": value.strip()})
                continue
        # #89: Auto-detect URLs (http://, https://, or any string containing ://)
        if line.startswith(("http://", "https://")) or "://" in line:
            targets.append({"type": "url", "value": line})
        else:
            # Default to domain for bare values
            targets.append({"type": "domain", "value": line})
    return targets
