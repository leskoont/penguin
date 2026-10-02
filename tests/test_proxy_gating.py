"""Regression tests for proxy routing eligibility (ToolContext).

A tool with no CLI proxy flag (nmap, amass, puredns, dig, subzy, feroxbuster,
arjun, kr, the cloud/git scanners, ...) must NEVER be routed through the proxy
pool: otherwise it burns a rotation pick for a proxy that is never applied and,
worse, gets skipped entirely ("no proxy available") whenever the free SOCKS
pool is empty -- silently gutting core coverage (e.g. puredns resolution, nmap
scanning). Only tools in ToolContext._PROXY_FLAG_TOOLS are proxyable.

These assertions use a bare ``Config()`` (proxies enabled, no per-tool config)
so they prove the *default* behaviour, independent of config/config.yaml.
"""
from penguin.config import Config
from penguin.runner import RunResult
from penguin.tools import _base
from penguin.tools._base import ToolContext

# Tools invoked across the pipeline that have no proxy flag of their own.
UNPROXYABLE = (
    "nmap", "masscan", "amass", "puredns", "dig", "subzy", "arjun", "feroxbuster",
    "subjs", "waybackurls", "assetfinder", "findomain", "chaos", "kr", "aws",
    "cloud_enum", "s3scanner", "bucketloot", "trivy", "gitdumper", "trufflehog",
    "gitleaks",
)
PROXYABLE = tuple(ToolContext._PROXY_FLAG_TOOLS)


def test_proxyable_set_matches_proxy_flag_mapping():
    """_PROXY_FLAG_TOOLS must stay in lockstep with proxy_flag()'s mapping, so
    the eligibility gate and the actual flag builder can never disagree."""
    ctx = ToolContext(Config())
    for tool in PROXYABLE:
        assert ctx.proxy_flag(tool, "socks5://127.0.0.1:9050"), tool
    # And nothing outside the set yields a flag.
    for tool in UNPROXYABLE:
        assert ctx.proxy_flag(tool, "socks5://127.0.0.1:9050") == [], tool


def test_unproxyable_tools_are_not_proxy_gated():
    cfg = Config()
    assert cfg.proxies.enabled  # default on -- the condition that triggered the bug
    ctx = ToolContext(cfg)
    for tool in UNPROXYABLE:
        assert ctx.proxy_applies(tool) is False, tool
        assert ctx.proxy_for(tool) is None, tool


def test_proxyable_tools_still_apply_when_enabled():
    ctx = ToolContext(Config())
    for tool in PROXYABLE:
        # subfinder has a flag but is proxy:false in shipped config; with a bare
        # Config() (no per-tool opt-out) every mapped tool is eligible.
        assert ctx.proxy_applies(tool) is True, tool


def test_unproxyable_tool_runs_direct_even_with_empty_pool(monkeypatch):
    """The core guarantee: an un-proxyable tool executes directly (it is NOT
    skipped) even when the proxy pool is empty."""
    ctx = ToolContext(Config())
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return RunResult(cmd, 0, "out", "", 1, 0.1, True)

    # If anything consulted the pool for these tools, that is the bug.
    def boom(_cfg):
        raise AssertionError("pool must not be consulted for an un-proxyable tool")

    monkeypatch.setattr(_base, "run", fake_run)
    monkeypatch.setattr(_base, "get_pool", boom)

    r = ctx.execute("nmap", ["nmap", "-p-", "example.com"])
    assert r.ok is True
    assert captured["cmd"] == ["nmap", "-p-", "example.com"]  # no proxy flag appended


def test_proxyable_tool_is_skipped_when_pool_empty(monkeypatch):
    """Counterpart: a proxyable tool must still refuse to run (no IP leak) when
    the pool is exhausted -- the gating that the fix deliberately preserves."""
    ctx = ToolContext(Config())

    class _EmptyPool:
        def pick(self):
            return None

    monkeypatch.setattr(_base, "get_pool", lambda _cfg: _EmptyPool())
    monkeypatch.setattr(_base, "run", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("proxyable tool must not run with an empty pool")))

    r = ctx.execute("httpx", ["httpx", "-l", "hosts.txt"])
    assert r.ok is False
    assert r.stderr == "no proxy available"
