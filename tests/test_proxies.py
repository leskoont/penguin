"""Tests for penguin.proxies - the global-concurrency clamp on validation.

The proxy-validation burst is the single largest per-run socket burst, so its
worker count must be clamped to general.max_global_concurrency. These tests
lock that wiring in without touching the network (``_validate_one`` is stubbed).
"""
import concurrent.futures

import pytest

from penguin.config import Config, apply_net_profile
from penguin.proxies import Proxy, ProxyPool


class _RecordingExecutor(concurrent.futures.ThreadPoolExecutor):
    """A ThreadPoolExecutor that records the max_workers it was built with."""

    last_max_workers = None

    def __init__(self, max_workers=None, *args, **kwargs):
        type(self).last_max_workers = max_workers
        super().__init__(max_workers=max_workers, *args, **kwargs)


def _fake_proxies(n: int) -> list[Proxy]:
    return [Proxy(host=f"10.0.0.{i}", port=8080, protocol="http") for i in range(n)]


def _run_validate(monkeypatch, cfg: Config, n_candidates: int) -> int:
    pool = ProxyPool(cfg)
    # No network: every candidate "fails" instantly.
    monkeypatch.setattr(pool, "_validate_one", lambda *a, **k: None)
    monkeypatch.setattr(concurrent.futures, "ThreadPoolExecutor", _RecordingExecutor)
    _RecordingExecutor.last_max_workers = None
    pool.validate(_fake_proxies(n_candidates))
    return _RecordingExecutor.last_max_workers


def test_validate_workers_clamped_by_global_budget(monkeypatch):
    cfg = Config()
    apply_net_profile(cfg, "vps")          # validate_workers=120
    cfg.general.max_global_concurrency = 10  # but the operator hard-caps it
    workers = _run_validate(monkeypatch, cfg, n_candidates=50)
    assert workers == 10


def test_validate_workers_unclamped_when_budget_high(monkeypatch):
    cfg = Config()
    apply_net_profile(cfg, "slirp")        # validate_workers=40, global=40
    workers = _run_validate(monkeypatch, cfg, n_candidates=50)
    assert workers == 40


def test_minimal_profile_shrinks_validation_burst(monkeypatch):
    cfg = Config()
    apply_net_profile(cfg, "minimal")      # validate_workers=8, global=8
    workers = _run_validate(monkeypatch, cfg, n_candidates=50)
    assert workers == 8
