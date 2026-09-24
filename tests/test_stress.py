"""Hellish stress tests: concurrency (RMW races), huge inputs, malformed data.

These deliberately hammer the code paths the pipeline runs under threads
(run_parallel) or over untrusted tool output, to surface data-loss races and
parser blow-ups that ordinary unit tests miss.
"""
import concurrent.futures
import json
import random
import string
import threading

import pytest

from penguin.config import Config, load
from penguin.findings import FindingStore, derive_findings
from penguin.pipelines.block1_infra import _augment_wordlist, _extract_scoped, _scope_regex
from penguin.runner import RunResult
from penguin.state import RunState
from penguin.tools import takeover as tk
from penguin.tools._base import ToolContext
from penguin.wordlists import WordlistManager


def _cfg(tmp_path):
    cfg = Config()
    cfg.general.output_dir = str(tmp_path)
    cfg.general.wordlists_dir = str(tmp_path / "wl")
    return cfg


# ---------------------------------------------------------------- concurrency

class TestAddLinesConcurrency:
    def test_concurrent_accumulate_loses_no_lines(self, tmp_path):
        """20 threads each add 100 unique lines to the same accumulator; all
        2000 must survive (RMW race would drop some)."""
        st = RunState(_cfg(tmp_path), "ex.com")
        n_threads, per = 20, 100
        batches = [[f"t{t}-h{i}.ex.com" for i in range(per)] for t in range(n_threads)]

        def worker(b):
            st.add_lines("all_subdomains.txt", b)

        with concurrent.futures.ThreadPoolExecutor(max_workers=n_threads) as ex:
            list(ex.map(worker, batches))

        got = st._read_set(st.base / "all_subdomains.txt")
        assert len(got) == n_threads * per, f"lost lines: {n_threads*per - len(got)}"

    def test_concurrent_run_file_no_loss(self, tmp_path):
        st = RunState(_cfg(tmp_path), "ex.com")
        n = 16

        def worker(t):
            st.add_lines("urls.txt", [f"u{t}-{i}" for i in range(50)], accumulate=False)

        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            list(ex.map(worker, range(n)))
        got = st._read_set(st.run_dir / "urls.txt")
        assert len(got) == n * 50


class TestWordlistConcurrency:
    def test_concurrent_learn_no_loss(self, tmp_path):
        wm = WordlistManager(_cfg(tmp_path))
        n = 20

        def worker(t):
            wm.add({f"tok{t}x{i}" for i in range(50)})

        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            list(ex.map(worker, range(n)))
        # reload from disk to check nothing was lost to a RMW race
        wm2 = WordlistManager(_cfg(tmp_path))
        assert len(wm2.learned()) == n * 50


class TestLedgerConcurrency:
    def test_concurrent_ledger_writes_intact(self, tmp_path):
        cfg = Config()
        cfg.proxies.enabled = False
        ctx = ToolContext(cfg, run_dir=tmp_path)
        import penguin.tools._base as base
        base.run = lambda cmd, **kw: RunResult(cmd, 0, "x", "", 1, 0.01, True)
        n = 40

        def worker(t):
            for _ in range(10):
                ctx.execute(f"tool{t}", ["tool", "-x"])

        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            list(ex.map(worker, range(n)))
        lines = (tmp_path / base.LEDGER_NAME).read_text().strip().splitlines()
        assert len(lines) == n * 10
        # every line must be valid JSON (no interleaved/torn writes)
        for ln in lines:
            json.loads(ln)


class TestFindingStoreConcurrency:
    def test_concurrent_record_no_dupe_no_loss(self, tmp_path):
        target = {"type": "domain", "value": "ex.com"}
        store = FindingStore.for_target(tmp_path, "ex.com")
        lock = threading.Lock()

        def worker(t):
            b1 = {"takeovers": [], "subdomains": []}
            b2 = {"js_secrets": [f"s{t}"]}
            fs = derive_findings(target, b1, b2, {}, {}, {"new": [f"h{t}.ex.com"]})
            with lock:  # FindingStore is not itself thread-safe; serialize record
                store.record(fs, f"run_{t}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            list(ex.map(worker, range(16)))
        reloaded = FindingStore.for_target(tmp_path, "ex.com")
        # 16 secrets + 16 new subdomains, all distinct
        assert len(reloaded._by_key) == 32


# ------------------------------------------------------------------- huge/edge

class TestHugeInputs:
    def test_scope_extract_on_huge_graph(self):
        rx = _scope_regex(["ex.com"])
        # 50k lines of amass-graph noise with real hosts buried in it
        lines = []
        for i in range(50000):
            if i % 1000 == 0:
                lines.append(f"h{i}.ex.com (FQDN) --> a_record --> 1.2.3.{i%255} (IPAddress)")
            else:
                lines.append(f"{i} (ASN) --> announces --> 10.0.0.0/8 (Netblock)")
        got = _extract_scoped("\n".join(lines), rx)
        assert all(h.endswith("ex.com") for h in got)
        assert len(got) == 50  # only the buried FQDNs, no ASN/netblock junk

    def test_augment_wordlist_huge(self, tmp_path):
        base = tmp_path / "base.txt"
        base.write_text("\n".join(f"w{i}" for i in range(100000)), encoding="utf-8")
        learned = [f"L{i}" for i in range(50000)]
        out = tmp_path / "merged.txt"
        res = _augment_wordlist(base, learned, out)
        got = res.read_text().split()
        assert len(got) == 150000

    def test_rollup_huge_ledger(self):
        from penguin import diagnostics
        recs = [{"tool": f"t{i%20}", "outcome": random.choice(diagnostics.OUTCOMES),
                 "duration": random.random(), "attempts": 1} for i in range(100000)]
        r = diagnostics.rollup(recs)
        assert r["totals"]["calls"] == 100000
        assert sum(r["totals"][o] for o in diagnostics.OUTCOMES) == 100000


# ------------------------------------------------------------- malformed/fuzz

class TestMalformed:
    def test_config_garbage_yaml_types(self, tmp_path):
        cf = tmp_path / "config.yaml"
        cf.write_text("general:\n  threads: not_a_number\n  keep_runs: [1,2]\n"
                      "  net_profile: 12345\n", encoding="utf-8")
        cfg = load(cf)  # must not raise
        # clamp_workers must survive a non-int threads value
        assert cfg.general.clamp_workers(cfg.general.threads) >= 1

    def test_extract_scoped_binary_junk(self):
        rx = _scope_regex(["ex.com"])
        junk = "".join(random.choice(string.printable) for _ in range(20000))
        _extract_scoped(junk, rx)  # must not raise

    def test_parse_takeovers_fuzz(self, tmp_path):
        out = tmp_path / "t.jsonl"
        out.write_text("\n".join(
            random.choice([
                json.dumps({"host": f"h{i}.ex.com"}),
                "garbage {not json",
                "",
                json.dumps([1, 2, 3]),           # wrong shape (list)
                json.dumps("just a string"),      # wrong shape (str)
            ]) for i in range(5000)
        ), encoding="utf-8")
        tk.parse_nuclei_takeovers(out)  # must not raise

    def test_clamp_workers_fuzz(self):
        cfg = Config()
        for _ in range(1000):
            cfg.general.max_global_concurrency = random.randint(-5, 200)
            req = random.randint(-5, 500)
            out = cfg.general.clamp_workers(req)
            assert out >= 1

    def test_findstore_torn_jsonl(self, tmp_path):
        d = tmp_path / "ex.com"
        d.mkdir()
        (d / "findings.jsonl").write_text(
            '{"type":"secret","asset":"a"}\n'
            'TORN LINE {"type"\n'
            '{"type":"js_secret","asset":"b"}\n', encoding="utf-8")
        store = FindingStore.for_target(tmp_path, "ex.com")
        assert len(store._by_key) == 2  # torn line skipped, others load


# ---------------------------------------------------------- more concurrency

class TestProxyPoolConcurrency:
    def test_pick_and_mark_dead_hammered(self, tmp_path):
        from penguin.proxies import Proxy, ProxyPool
        cfg = Config()
        cfg.general.output_dir = str(tmp_path)
        pool = ProxyPool(cfg)
        with pool._lock:
            pool._pool = [Proxy(host=f"10.0.0.{i}", port=8080, protocol="http") for i in range(50)]

        def picker():
            for _ in range(2000):
                pool.pick()

        def killer():
            for i in range(1000):
                pool.mark_dead(f"http://10.0.0.{i % 50}:8080")

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
            futs = [ex.submit(picker) for _ in range(8)] + [ex.submit(killer) for _ in range(4)]
            for f in futs:
                f.result()  # must not raise (no index-out-of-range races)


class TestReDoS:
    def test_scope_regex_no_catastrophic_backtracking(self):
        import time
        rx = _scope_regex(["ex.com", "example.org", "test.net"])
        # adversarial: long run of label-like chars that could trigger
        # catastrophic backtracking in a poorly-written alternation
        evil = ("a-" * 5000) + "!"
        start = time.time()
        _extract_scoped(evil, rx)
        assert time.time() - start < 2.0, "possible ReDoS in _scope_regex"


class TestRunTargetIntegration:
    def _isolate(self, tmp_path, monkeypatch):
        import penguin.config as C
        monkeypatch.setattr(C, "ROOT", tmp_path)
        cfg = Config()
        cfg.proxies.enabled = False
        cfg.general.output_dir = str(tmp_path / "results")
        cfg.general.wordlists_dir = str(tmp_path / "wl")
        return cfg

    def _patch_blocks(self, m, monkeypatch, fns):
        # run_target iterates m._BLOCKS, which captured the original function
        # references at import; patch the list itself, not the module attributes.
        monkeypatch.setattr(m, "_BLOCKS", [
            (1, "infra", fns[0]), (2, "web", fns[1]),
            (3, "cloud_db", fns[2]), (4, "elite", fns[3]),
        ])

    def test_all_blocks_degrade_to_empty(self, tmp_path, monkeypatch):
        import penguin.pipelines.master as m
        cfg = self._isolate(tmp_path, monkeypatch)

        def boom(*a, **k):
            raise RuntimeError("boom")

        # every block raises -> must degrade, still produce a summary + manifest
        self._patch_blocks(m, monkeypatch, [boom, boom, boom, boom])
        summary = m.run_target(cfg, {"type": "domain", "value": "ex.com"})
        assert summary["subdomains"] == 0
        assert "findings" in summary
        rd = tmp_path / "results" / "ex.com"
        # a manifest was written for the run
        assert any(p.name == "_manifest.json" for p in rd.rglob("_manifest.json"))

    def test_blocks_return_findings_end_to_end(self, tmp_path, monkeypatch):
        import penguin.pipelines.master as m
        from penguin.pipelines.report import build_report
        cfg = self._isolate(tmp_path, monkeypatch)
        self._patch_blocks(m, monkeypatch, [
            lambda *a, **k: {"subdomains": ["a.ex.com", "b.ex.com"], "resolved": [],
                             "live": [], "takeovers": ["gone.ex.com"]},
            lambda *a, **k: {"endpoints": ["/api/v1"], "js_secrets": ["AKIA..."], "api": []},
            lambda *a, **k: {"open_db": ["1.2.3.4:6379"], "buckets": []},
            lambda *a, **k: {"origin_ips": [], "exposed_git": ["http://ex.com/.git/"], "secrets": []},
        ])
        target = {"type": "domain", "value": "ex.com"}
        summary = m.run_target(cfg, target)
        assert summary["takeovers"] == 1
        assert summary["exposed_git"] == 1
        assert len(summary["findings"]) >= 4
        # report builds from the summary without error
        md = build_report(cfg, target, summary)
        assert md.exists()
        assert "CRITICAL" in md.read_text()


class TestReadLiveUrlsMalformed:
    def test_garbage_csv_never_raises(self, tmp_path):
        from penguin.state import read_live_urls
        f = tmp_path / "httpx.csv"
        f.write_text('url,input\n"https://a.com",a\nGARBAGE LINE\n,,,\n'
                     '"not-a-url",x\nhttps://b.com,b\n', encoding="utf-8")
        urls = read_live_urls(f)
        assert "https://a.com" in urls
        assert "https://b.com" in urls
