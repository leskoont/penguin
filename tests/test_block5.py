"""Tests for penguin.pipelines.block5_feedback - the data-driven re-run pass."""
import json

import pytest

import penguin.pipelines.block5_feedback as b5
from penguin.config import Config
from penguin.pipelines.block5_feedback import compute_stragglers, run_block5
from penguin.pipelines.master import _BLOCK_FALLBACKS
from penguin.tools import nuclei_custom as nu


class TestComputeStragglers:
    def test_subdomains_not_resolved(self):
        assert compute_stragglers(["a.ex.com", "b.ex.com", "c.ex.com"],
                                  ["b.ex.com"]) == ["a.ex.com", "c.ex.com"]

    def test_empty_inputs(self):
        assert compute_stragglers([], []) == []
        assert compute_stragglers(["a.ex.com"], []) == ["a.ex.com"]

    def test_dedup(self):
        assert compute_stragglers(["a.ex.com", "a.ex.com"], []) == ["a.ex.com"]


class TestFallbackShape:
    def test_block5_has_fallback(self):
        # master degrades a crashed block to exactly this shape; block5's own
        # disabled/empty return must match it so downstream lookups never KeyError
        assert set(_BLOCK_FALLBACKS[5]) == {"stragglers", "new_live",
                                            "service_vectors", "cve_hits",
                                            "web_issues"}

    def test_disabled_stage_returns_fallback_shape(self, tmp_path):
        cfg = Config()
        cfg.stages = {"feedback": False}
        state = _mk_state(tmp_path, cfg)
        assert run_block5(cfg, state, {"type": "domain", "value": "ex.com"}) == _BLOCK_FALLBACKS[5]


class TestReadBlockResult:
    def test_reads_checkpoint(self, tmp_path):
        cfg = Config()
        state = _mk_state(tmp_path, cfg)
        (state.run_dir / "_block3_result.json").write_text(
            json.dumps({"open_db": ["1.2.3.4:6379"]}), encoding="utf-8")
        assert b5._read_block_result(state, 3) == {"open_db": ["1.2.3.4:6379"]}

    def test_missing_or_corrupt_checkpoint(self, tmp_path):
        cfg = Config()
        state = _mk_state(tmp_path, cfg)
        assert b5._read_block_result(state, 3) == {}
        (state.run_dir / "_block3_result.json").write_text("{bogus", encoding="utf-8")
        assert b5._read_block_result(state, 3) == {}


class TestRunBlock5:
    def _isolate(self, tmp_path, monkeypatch):
        import penguin.config as C
        monkeypatch.setattr(C, "ROOT", tmp_path)
        cfg = Config()
        cfg.proxies.enabled = False
        cfg.general.output_dir = str(tmp_path / "results")
        cfg.general.wordlists_dir = str(tmp_path / "wl")
        cfg.stages = {"feedback": True}
        return cfg

    def test_service_vectors_from_open_db(self, tmp_path, monkeypatch):
        cfg = self._isolate(tmp_path, monkeypatch)
        state = _mk_state(tmp_path, cfg)
        (state.run_dir / "_block3_result.json").write_text(
            json.dumps({"open_db": ["1.2.3.4:6379", "5.6.7.8:27017"]}), encoding="utf-8")
        res = run_block5(cfg, state, {"type": "domain", "value": "ex.com"})
        prods = {v["product"] for v in res["service_vectors"]}
        assert prods == {"redis", "mongodb"}
        for v in res["service_vectors"]:
            assert v["host"] in ("1.2.3.4:6379", "5.6.7.8:27017")
            assert v["creds"]

    def test_no_stragglers_when_all_resolved(self, tmp_path, monkeypatch):
        cfg = self._isolate(tmp_path, monkeypatch)
        state = _mk_state(tmp_path, cfg)
        (state.run_dir / "_block1_result.json").write_text(
            json.dumps({"subdomains": ["a.ex.com"], "resolved": ["a.ex.com"]}),
            encoding="utf-8")
        res = run_block5(cfg, state, {"type": "domain", "value": "ex.com"})
        assert res["stragglers"] == []
        assert res["new_live"] == []

    def test_cve_scan_skipped_without_kb_hits(self, tmp_path, monkeypatch):
        cfg = self._isolate(tmp_path, monkeypatch)
        state = _mk_state(tmp_path, cfg)
        (state.run_dir / "_block1_result.json").write_text(
            json.dumps({"subdomains": [], "resolved": []}), encoding="utf-8")
        called = {"n": 0}

        def fake_scan(*a, **k):
            called["n"] += 1
            return None

        monkeypatch.setattr(nu, "nuclei_cves", fake_scan)
        res = run_block5(cfg, state, {"type": "domain", "value": "ex.com"})
        assert called["n"] == 0
        assert res["cve_hits"] == []


class TestNucleiJsonlParsing:
    def test_parse_hits(self, tmp_path):
        p = tmp_path / "nuclei.jsonl"
        p.write_text(
            json.dumps({"template-id": "CVE-2021-44228", "host": "https://a.ex.com",
                        "info": {"name": "log4j RCE", "severity": "critical",
                                 "classification": {"cve-id": ["CVE-2021-44228"]}},
                        "matcher-status": 1.0}) + "\n"
            + "not json\n"
            + json.dumps({"template-id": "xss-reflected", "host": "https://b.ex.com",
                          "info": {"name": "reflected xss", "severity": "medium"},
                          "matcher-status": 0.0}) + "\n",
            encoding="utf-8")
        hits = nu.parse_nuclei_jsonl(p)
        assert len(hits) == 2
        assert hits[0]["cve"] == "CVE-2021-44228"
        assert hits[0]["severity"] == "critical"
        assert hits[0]["matcher_status"] is True
        assert hits[1]["cve"] == ""
        assert hits[1]["matcher_status"] is False

    def test_missing_file(self):
        assert nu.parse_nuclei_jsonl(None) == []


def _mk_state(tmp_path, cfg):
    from penguin.state import RunState
    return RunState(cfg, "ex.com")


@pytest.mark.parametrize("open_db,expected", [
    (["1.2.3.4:6379"], {"redis"}),
    (["1.2.3.4:8080"], set()),  # generic ports claim nothing
    (["h.ex.com:9200"], {"elasticsearch"}),
    ([], set()),
])
def test_port_product_mapping(open_db, expected):
    from penguin.knowledge import products_for_ports
    got = set(products_for_ports(open_db))
    assert got == expected
