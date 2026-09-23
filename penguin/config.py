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
    # Named network profile that sets a coherent bundle of the concurrency /
    # rate knobs below (threads, rate_limit, dns_rate_limit, max_parallel_tools,
    # max_global_concurrency + the proxy validation burst). Pick one instead of
    # hand-tuning six numbers per environment. Applied *before* explicit
    # config.yaml values, so any knob you set by hand still wins over the
    # profile. See NET_PROFILES for the presets:
    #   minimal / throttle -> smallest footprint (use when the host's own
    #                         network starts lagging under a run)
    #   slirp (default)    -> VirtualBox user-mode NAT safe (today's values)
    #   wsl                -> WSL2 / VMware NAT / wired bridge
    #   vps                -> dedicated host / datacenter (old aggressive)
    net_profile: str = "slirp"
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
    # Global ceiling on how many penguin-spawned network operations may run at
    # once, ACROSS every fan-out point (proxy validation + all block loops).
    # The other concurrency knobs are per-phase; without a global cap their
    # bursts can stack and overrun a small NAT/conntrack table (the SLIRP link
    # drop, and a lagging host network in general). Every fan-out clamps its
    # worker count to this, so no phase ever exceeds it. Keep it >= the largest
    # per-phase count you want (default 40 == the slirp proxy-validation burst,
    # so it never binds tighter than today's behaviour); lower it to hard-cap
    # total socket pressure on a fragile link. 0 = no global clamp.
    max_global_concurrency: int = 40
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

    def clamp_workers(self, requested: int) -> int:
        """Clamp a fan-out worker count to the global concurrency ceiling.

        Every parallel fan-out (proxy validation, per-block loops) routes its
        requested worker count through here so no single phase opens more
        concurrent operations than ``max_global_concurrency`` allows. A value
        of 0 (or negative) disables the global clamp. The result is always at
        least 1 so a positive request never collapses to "do nothing".
        """
        try:
            requested = int(requested)
        except (TypeError, ValueError):
            requested = 1
        requested = max(1, requested)
        ceiling = self.max_global_concurrency
        if ceiling and ceiling > 0:
            return min(requested, ceiling)
        return requested


# --- Named network profiles --------------------------------------------------
# Each profile is a coherent bundle of the concurrency / rate knobs for one
# class of network environment. Applied before the config.yaml overlay so any
# value set explicitly in config.yaml still wins over the profile. The "slirp"
# profile intentionally reproduces the historical defaults so selecting it (the
# default) changes nothing. "general" keys map onto GeneralConfig fields,
# "proxies" keys onto ProxyConfig fields.
NET_PROFILES: dict[str, dict[str, dict[str, Any]]] = {
    # Smallest footprint. For when the host's own network starts lagging under
    # a run (tiny NAT/conntrack table, weak Wi-Fi, metered link): near-serial,
    # low rates, a small proxy-validation burst.
    "minimal": {
        "general": {
            "threads": 8,
            "rate_limit": 40,
            "dns_rate_limit": 60,
            "max_parallel_tools": 1,
            "max_global_concurrency": 8,
        },
        "proxies": {
            "validate_workers": 8,
            "max_candidates": 300,
            "target_valid": 60,
        },
    },
    # VirtualBox user-mode NAT (SLIRP) safe. Historical default values.
    "slirp": {
        "general": {
            "threads": 15,
            "rate_limit": 100,
            "dns_rate_limit": 150,
            "max_parallel_tools": 3,
            "max_global_concurrency": 40,
        },
        "proxies": {
            "validate_workers": 40,
            "max_candidates": 800,
            "target_valid": 150,
        },
    },
    # WSL2 / VMware NAT / wired bridge: a real NAT stack, moderate headroom.
    "wsl": {
        "general": {
            "threads": 30,
            "rate_limit": 200,
            "dns_rate_limit": 400,
            "max_parallel_tools": 5,
            "max_global_concurrency": 80,
        },
        "proxies": {
            "validate_workers": 80,
            "max_candidates": 1500,
            "target_valid": 150,
        },
    },
    # Dedicated host / datacenter: the old aggressive profile.
    "vps": {
        "general": {
            "threads": 50,
            "rate_limit": 300,
            "dns_rate_limit": 1000,
            "max_parallel_tools": 8,
            "max_global_concurrency": 128,
        },
        "proxies": {
            "validate_workers": 120,
            "max_candidates": 2000,
            "target_valid": 200,
        },
    },
}
# Friendly aliases.
NET_PROFILE_ALIASES = {"throttle": "minimal", "low": "minimal", "safe": "slirp",
                       "default": "slirp", "bridge": "wsl", "vpn": "wsl"}


def resolve_profile_name(name: str | None) -> str | None:
    """Normalise a profile name/alias; return None if unknown or empty."""
    if not name:
        return None
    key = str(name).strip().lower()
    key = NET_PROFILE_ALIASES.get(key, key)
    return key if key in NET_PROFILES else None


def apply_net_profile(cfg: "Config", name: str) -> bool:
    """Overlay a named network profile onto ``cfg``. Returns True if applied."""
    resolved = resolve_profile_name(name)
    if resolved is None:
        return False
    profile = NET_PROFILES[resolved]
    _apply_section(cfg.general, profile.get("general", {}))
    _apply_section(cfg.proxies, profile.get("proxies", {}))
    cfg.general.net_profile = resolved
    return True


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


def load(config_path: str | Path | None = None, profile: str | None = None) -> Config:
    """Load config, overlaying (in increasing priority): the net profile,
    then the on-disk config.yaml, then nothing else here.

    Profile selection priority: explicit ``profile`` arg (CLI) > the
    ``PENGUIN_NET_PROFILE`` env var > ``general.net_profile`` in config.yaml >
    the built-in default ("slirp"). The profile is applied *before* the YAML
    overlay so any knob set by hand in config.yaml still wins over the profile.
    """
    cfg = Config()
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    data: dict = {}
    if path.exists():
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        cfg.raw = data

    # Profile selection has two tiers with different precedence vs. the
    # config.yaml knobs:
    #   * A RUNTIME request -- the --net-profile/--throttle CLI flag (``profile``
    #     arg) or the PENGUIN_NET_PROFILE env var -- is a deliberate override for
    #     THIS run and wins over knobs pinned in config.yaml. Otherwise the
    #     shipped config.yaml (which pins every SLIRP value explicitly) would
    #     make --throttle a no-op.
    #   * A FILE/DEFAULT profile -- general.net_profile in config.yaml, or the
    #     built-in default -- sits below the file's own explicit knobs, so a
    #     hand-set threads:/rate_limit: still wins over it.
    yaml_profile = None
    if isinstance(data.get("general"), dict):
        yaml_profile = data["general"].get("net_profile")
    runtime_choice = profile or os.environ.get("PENGUIN_NET_PROFILE")
    file_choice = yaml_profile or cfg.general.net_profile

    # Tier 1: apply the file/default profile BEFORE the YAML overlay so pinned
    # knobs can still override it.
    file_resolved = resolve_profile_name(file_choice)
    if file_resolved is not None:
        apply_net_profile(cfg, file_resolved)

    if data:
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

    # Tier 2: a runtime-requested profile is applied AFTER the YAML overlay so it
    # wins over knobs pinned in config.yaml.
    if runtime_choice:
        runtime_resolved = resolve_profile_name(runtime_choice)
        if runtime_resolved is not None:
            apply_net_profile(cfg, runtime_resolved)
            cfg.general.net_profile = runtime_resolved
        else:
            # Unknown name (typo): keep whatever values are in effect, but record
            # the request rather than crashing.
            cfg.general.net_profile = str(runtime_choice)
    elif file_resolved is not None:
        # No runtime override: reflect the file/default profile whose values were
        # applied (the overlay may have re-set the label from config.yaml).
        cfg.general.net_profile = file_resolved
    elif file_choice:
        cfg.general.net_profile = str(file_choice)
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
