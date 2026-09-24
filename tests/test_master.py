"""Tests for penguin.pipelines.master - critical-findings detection."""
from penguin.pipelines.master import _critical_findings

_EMPTY1 = {"subdomains": [], "resolved": [], "live": [], "takeovers": []}
_EMPTY2 = {"endpoints": [], "js_secrets": [], "api": []}
_EMPTY3 = {"open_db": [], "buckets": []}
_EMPTY4 = {"origin_ips": [], "exposed_git": [], "secrets": []}


class TestCriticalFindings:
    def test_all_empty_returns_nothing(self):
        assert _critical_findings(_EMPTY1, _EMPTY2, _EMPTY3, _EMPTY4) == {}

    def test_secrets_combine_js_and_block4(self):
        b2 = {**_EMPTY2, "js_secrets": ["aws_key"]}
        b4 = {**_EMPTY4, "secrets": ["gh_token", "db_pw"]}
        hits = _critical_findings(_EMPTY1, b2, _EMPTY3, b4)
        assert hits == {"secrets": 3}

    def test_open_db_and_buckets_and_git(self):
        b3 = {"open_db": ["1.2.3.4:6379"], "buckets": ["s3://x", "s3://y"]}
        b4 = {**_EMPTY4, "exposed_git": ["http://h/.git/"]}
        hits = _critical_findings(_EMPTY1, _EMPTY2, b3, b4)
        assert hits == {
            "open databases": 1,
            "exposed .git": 1,
            "public buckets": 2,
        }

    def test_takeovers_are_critical(self):
        b1 = {**_EMPTY1, "takeovers": ["gone.ex.com", "dead.ex.com"]}
        hits = _critical_findings(b1, _EMPTY2, _EMPTY3, _EMPTY4)
        assert hits == {"subdomain takeovers": 2}

    def test_only_nonzero_categories_included(self):
        b3 = {"open_db": ["1.2.3.4:27017"], "buckets": []}
        hits = _critical_findings(_EMPTY1, _EMPTY2, b3, _EMPTY4)
        assert hits == {"open databases": 1}

    def test_tolerates_missing_keys(self):
        # blocks that degraded may hand back partial dicts
        assert _critical_findings({}, {}, {}, {}) == {}
        assert _critical_findings({}, {"js_secrets": ["x"]}, {}, {}) == {"secrets": 1}
        assert _critical_findings({"takeovers": ["t"]}, {}, {}, {}) == {"subdomain takeovers": 1}


class TestResume:
    """--resume: checkpoint completed blocks, skip them on a re-run."""

    def _isolate(self, tmp_path, monkeypatch):
        import penguin.config as C
        from penguin.config import Config
        monkeypatch.setattr(C, "ROOT", tmp_path)
        cfg = Config()
        cfg.proxies.enabled = False
        cfg.general.output_dir = str(tmp_path / "results")
        cfg.general.wordlists_dir = str(tmp_path / "wl")
        return cfg

    def test_resume_skips_checkpointed_reruns_crashed(self, tmp_path, monkeypatch):
        import penguin.pipelines.master as m
        cfg = self._isolate(tmp_path, monkeypatch)
        calls = {1: 0, 2: 0, 3: 0, 4: 0}

        def mk(n, ok=True):
            def fn(*a, **k):
                calls[n] += 1
                if not ok:
                    raise RuntimeError(f"crash{n}")
                shapes = {
                    1: {"subdomains": ["a.ex.com"], "resolved": [], "live": [], "takeovers": []},
                    2: {"endpoints": [], "js_secrets": [], "api": []},
                    3: {"open_db": [], "buckets": []},
                    4: {"origin_ips": [], "exposed_git": [], "secrets": []},
                }
                return shapes[n]
            return fn

        target = {"type": "domain", "value": "ex.com"}
        # run 1: block3 crashes -> no checkpoint for 3
        monkeypatch.setattr(m, "_BLOCKS", [(1, "infra", mk(1)), (2, "web", mk(2)),
                                           (3, "cloud_db", mk(3, ok=False)), (4, "elite", mk(4))])
        s1 = m.run_target(cfg, target)
        from pathlib import Path
        rid = Path(s1["run_dir"]).name
        rd = Path(s1["run_dir"])
        assert (rd / "_block1_result.json").exists()
        assert not (rd / "_block3_result.json").exists()

        # run 2: resume -> 1/2/4 skipped, only 3 re-runs
        for k in calls:
            calls[k] = 0
        monkeypatch.setattr(m, "_BLOCKS", [(1, "infra", mk(1)), (2, "web", mk(2)),
                                           (3, "cloud_db", mk(3, ok=True)), (4, "elite", mk(4))])
        s2 = m.run_target(cfg, target, resume_run_id=rid)
        assert calls == {1: 0, 2: 0, 3: 1, 4: 0}
        assert Path(s2["run_dir"]).name == rid

    def test_run_meta_written_for_resume(self, tmp_path, monkeypatch):
        import json
        from pathlib import Path

        import penguin.pipelines.master as m
        cfg = self._isolate(tmp_path, monkeypatch)
        monkeypatch.setattr(m, "_BLOCKS", [
            (1, "infra", lambda *a, **k: {"subdomains": [], "resolved": [], "live": [], "takeovers": []}),
            (2, "web", lambda *a, **k: {"endpoints": [], "js_secrets": [], "api": []}),
            (3, "cloud_db", lambda *a, **k: {"open_db": [], "buckets": []}),
            (4, "elite", lambda *a, **k: {"origin_ips": [], "exposed_git": [], "secrets": []}),
        ])
        target = {"type": "url", "value": "https://ex.com/app"}
        s = m.run_target(cfg, target)
        meta = Path(s["run_dir"]) / "_run_meta.json"
        assert meta.exists()
        assert json.loads(meta.read_text())["target"] == target
