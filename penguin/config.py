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
    # Concurrent validation workers (I/O-bound). Worker count sets the peak
    # simultaneous-socket burst, which is exactly what SLIRP's small NAT table
    # cannot absorb -- 100 parallel proxy SYNs at startup is a link-drop risk on
    # a VirtualBox NAT VM. 40 keeps the burst under SLIRP's ceiling; the run is
    # gated on max_candidates for total volume anyway. Raise off SLIRP.
    validate_workers: int = 40
    # Cap on how many candidates to actually validate per refresh. Every attempt
    # opens a TCP flow to the proxy IP; dead proxies (the bulk of any free list)
    # leave that flow in SYN_SENT on the router's NAT/conntrack table for ~120s,
    # so attempting thousands piles up lingering entries and overflows a SOHO
    # router's table ~a minute later -- dropping the WAN link right *after*
    # validation "completes". A random sample keeps the pool representative;
    # keeping the net alive also stops the valid-rate collapse (a flooded link
    # fails even good proxies mid-test). Raise for a bigger pool if the router
    # tolerates it; 0 = unbounded (the old flooding behaviour).
    max_candidates: int = 800
    # Stop validating early once this many working proxies are found -- no point
    # loading the router past what the pool needs. 0 = validate the whole
    # (capped) candidate set.
    target_valid: int = 150
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
    # SLIRP-SAFE PROFILE. The real bottleneck turned out to be VirtualBox's
    # user-mode NAT (SLIRP, the 10.0.2.15 gateway): it keeps a tiny concurrent
    # socket table and collapses the *whole* VM link when a recon burst exceeds
    # it (proven: `From 10.0.2.15 ... Destination Host Unreachable` mid-run).
    # Bridged mode would bypass SLIRP but is impossible on a Wi-Fi / TUN-proxy
    # host, so the fix is to bound total concurrency under SLIRP's ceiling. All
    # four knobs below are the safety valve; raise them only off SLIRP (wired
    # bridge / VMware NAT / WSL2 / VPS), where the old 50/300/1000/8 are fine.
    threads: int = 15
    # HTTP request rate (block2 ffuf/feroxbuster/arjun + nuclei tech-detect).
    # Aggregate ceiling: block2 divides it across the live-host fan-out so the
    # sum stays here. TCP is heavier on SLIRP than UDP (sockets linger), so keep
    # this at/below dns_rate_limit. 100 keeps concurrent TCP flows well under
    # what collapsed the SLIRP socket table.
    rate_limit: int = 100
    # DNS query rate (qps) for puredns/dnsx -- SEPARATE from the HTTP rate above.
    # massdns/dnsx default to *unbounded* and open ~10k concurrent UDP:53 flows,
    # which SLIRP cannot forward -- it drops the whole VM link. Even a moderate
    # rate matters here: at ~150 qps concurrency stays ~= rate*RTT (tens of
    # flows), which SLIRP survives. This slows DNS brute (a 100k list ~= 11 min)
    # but preserves full coverage via the size-scaled timeout below. Raise well
    # past this only off SLIRP.
    dns_rate_limit: int = 150
    # Ceiling (seconds) for a single rate-limited puredns/dnsx call. The wall is
    # scaled to (wordlist lines / dns_rate_limit) so the *entire* list resolves
    # instead of being silently truncated at a flat 1200s -- truncation is the
    # single biggest silent cause of low subdomain counts. This just caps that
    # scaling so a pathological multi-million-line list can't wedge a run.
    dns_max_timeout: int = 5400
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
    # them shortens wall-clock without contending for CPU. On SLIRP this is the
    # dominant knob: 8 sources each opening their own connection burst is what
    # peaks the concurrent-socket count past SLIRP's table and drops the VM
    # link. 3 keeps the passive fan-out from opening everything at once; raise
    # only off SLIRP (bridge / VMware NAT / WSL2 / VPS). Set to 1 for fully
    # sequential.
    max_parallel_tools: int = 3
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
