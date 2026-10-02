"""Regression: block1 TLS cert intel must run even when proxies are enabled.

openssl s_client can't be routed through the SOCKS pool, but it egresses through
the host's own system/TUN proxy (exactly like the direct dig DNS-intel and the
un-proxied OSINT sources). Gating it on ``proxies.enabled`` silently disabled
cert-expiry findings AND the SAN subdomain-discovery vector on every default
(proxied) run. This test drives run_block1 with the whole toolchain stubbed and
asserts the TLS path still fires with proxies ON.
"""
from __future__ import annotations

import penguin.config as C
import penguin.pipelines.block1_infra as b1
from penguin.config import Config
from penguin.state import RunState


def _neutralize(monkeypatch):
    """Stub every external tool block1 drives, so run_block1 reaches the TLS
    section without touching the network. run_parallel is stubbed wholesale so
    the passive/permutation fan-outs do nothing."""
    monkeypatch.setattr(b1, "run_parallel", lambda tasks, **k: [])
    for name in ("dnsvalidator", "puredns_bruteforce", "puredns_resolve",
                 "dnsx", "dnsx_ips", "gotator"):
        if hasattr(b1.rs, name):
            monkeypatch.setattr(b1.rs, name, lambda *a, **k: None)
    for name in ("httpx", "httpx_simple", "nuclei_tech"):
        if hasattr(b1.pb, name):
            monkeypatch.setattr(b1.pb, name, lambda *a, **k: None)
    monkeypatch.setattr(b1.tk, "nuclei_takeover", lambda *a, **k: None)
    monkeypatch.setattr(b1.tk, "subzy_takeover", lambda *a, **k: None)
    monkeypatch.setattr(b1.di, "check_domain", lambda *a, **k: [])


def _run(tmp_path, monkeypatch, *, proxies_enabled: bool):
    monkeypatch.setattr(C, "ROOT", tmp_path)
    cfg = Config()
    cfg.proxies.enabled = proxies_enabled
    cfg.general.output_dir = str(tmp_path / "results")
    cfg.general.wordlists_dir = str(tmp_path / "wl")
    _neutralize(monkeypatch)

    calls: list[str] = []

    def fake_cert(ctx, tgt, port=443):
        calls.append(tgt)
        return {"host": tgt, "expired": True, "expiring_soon": False,
                "self_signed": True, "days_left": -3, "sans": ["san.ex.com"]}

    monkeypatch.setattr(b1.tls, "fetch_and_parse", fake_cert)

    state = RunState(cfg, "ex.com")
    target = {"type": "domain", "value": "ex.com"}
    results = b1.run_block1(cfg, state, target)
    return calls, results


def test_tls_intel_runs_with_proxies_enabled(tmp_path, monkeypatch):
    calls, results = _run(tmp_path, monkeypatch, proxies_enabled=True)
    assert "ex.com" in calls                      # NOT skipped under proxies
    assert results["tls_issues"], "expected a tls issue to be recorded"
    iss = results["tls_issues"][0]
    assert iss["host"] == "ex.com" and iss["expired"] is True
    # SAN in scope is folded back into the subdomain set (discovery vector).
    assert "san.ex.com" in results["subdomains"]


def test_tls_intel_also_runs_with_proxies_disabled(tmp_path, monkeypatch):
    calls, results = _run(tmp_path, monkeypatch, proxies_enabled=False)
    assert "ex.com" in calls
    assert results["tls_issues"]
