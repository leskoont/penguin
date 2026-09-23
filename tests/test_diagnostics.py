"""Tests for penguin.diagnostics - ledger rollup and source counting."""
import json

from penguin import diagnostics


def _write_ledger(run_dir, records):
    p = run_dir / diagnostics.LEDGER_NAME
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return p


class TestReadLedger:
    def test_missing_returns_empty(self, tmp_path):
        assert diagnostics.read_ledger(tmp_path) == []

    def test_skips_malformed_lines(self, tmp_path):
        p = tmp_path / diagnostics.LEDGER_NAME
        p.write_text('{"tool":"a","outcome":"ok"}\nNOT JSON\n{"tool":"b","outcome":"timeout"}\n',
                     encoding="utf-8")
        recs = diagnostics.read_ledger(tmp_path)
        assert [r["tool"] for r in recs] == ["a", "b"]


class TestRollup:
    def test_empty(self):
        r = diagnostics.rollup([])
        assert r["totals"]["calls"] == 0
        assert r["per_tool"] == {}

    def test_aggregates_per_tool_and_totals(self):
        recs = [
            {"tool": "subfinder", "outcome": "ok", "duration": 1.0, "attempts": 1},
            {"tool": "subfinder", "outcome": "timeout", "duration": 30.0, "attempts": 2},
            {"tool": "amass", "outcome": "ok", "duration": 5.5, "attempts": 1},
        ]
        r = diagnostics.rollup(recs)
        assert r["totals"]["calls"] == 3
        assert r["totals"]["ok"] == 2
        assert r["totals"]["timeout"] == 1
        assert r["totals"]["duration"] == 36.5
        sf = r["per_tool"]["subfinder"]
        assert sf["calls"] == 2 and sf["ok"] == 1 and sf["timeout"] == 1
        assert sf["duration"] == 31.0 and sf["attempts"] == 3

    def test_unknown_outcome_bucketed_as_error(self):
        r = diagnostics.rollup([{"tool": "x", "outcome": "weird", "duration": 0, "attempts": 1}])
        assert r["totals"]["error"] == 1


class TestSubdomainSources:
    def test_counts_per_source_and_skips_helpers(self, tmp_path):
        sub = tmp_path / "subdomains"
        sub.mkdir()
        (sub / "subfinder_x.txt").write_text("a.x.com\nb.x.com\n", encoding="utf-8")
        (sub / "crtsh_x.txt").write_text("c.x.com\n", encoding="utf-8")
        (sub / "brute_wordlist.txt").write_text("admin\napi\ndev\n", encoding="utf-8")  # helper, skipped
        counts = diagnostics.subdomain_sources(tmp_path)
        assert counts == {"subfinder_x.txt": 2, "crtsh_x.txt": 1}

    def test_missing_dir_returns_empty(self, tmp_path):
        assert diagnostics.subdomain_sources(tmp_path) == {}
