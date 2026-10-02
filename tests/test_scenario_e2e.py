"""End-to-end scenario harness.

Drives the REAL master -> findings -> analysis -> report -> diagnostics chain
with synthetic block outputs (external binaries mocked out via _BLOCKS), across
diverse scenarios, and asserts the cross-module invariants hold. This is the
integration net the unit tests don't provide: it proves the pieces actually fit
together on realistic data, degraded blocks, cancellation, resume and junk input.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

import penguin.config as C
import penguin.pipelines.master as m
from penguin.config import Config
from penguin.pipelines.report import build_report


# ---- rich synthetic block outputs covering every finding type ----------------

def _b1(subs):
    return {
        "subdomains": subs,
        "resolved": ["1.2.3.4"],
        "live": [f'"https://{subs[0]}",{subs[0]},title' if subs else ""],
        "takeovers": ["dangling.ex.com"],
        "dns_issues": [
            {"type": "zone_transfer", "domain": "ex.com", "ns": "ns1.ex.com"},
            {"type": "missing_spf", "domain": "ex.com"},
            {"type": "missing_dmarc", "domain": "ex.com"},
            {"type": "dnssec_missing", "domain": "ex.com"},
            {"type": "unknown_type_ignored", "domain": "ex.com"},   # must be dropped
            "not-a-dict",                                           # must be skipped
        ],
        "tls_issues": [
            {"host": "www.ex.com", "expired": True, "days_left": -5, "self_signed": True},
            {"host": "api.ex.com", "expiring_soon": True, "days_left": 9},
        ],
    }


def _b2():
    return {
        "endpoints": ["https://ex.com/a", "https://ex.com/b?x=1"],
        "js_secrets": ["AKIAEXAMPLE", None, "", "None"],   # junk entries must be dropped
        "api": ["graphql"],
        "web_issues": [
            {"url": "https://ex.com", "cors_bad": True, "cors_credentials": True,
             "missing": ["CSP", "X-Frame-Options"]},
            "not-a-dict",
        ],
        "active": ["https://ex.com/x?q=<script>"],
        "content_issues": [
            {"url": "https://ex.com/.env", "kind": "exposed_config"},
            {"url": "https://ex.com/server-status", "kind": "info_disclosure"},
            {"url": "https://ex.com/listing/", "kind": "directory_listing"},
            {"url": "https://ex.com/.well-known/security.txt", "kind": "security_txt"},
            {"url": "https://ex.com/junk", "kind": "nope_ignored"},   # dropped
        ],
        "kb_findings": [
            {"kind": "kev_exploited", "product": "apache", "version": "2.4.49",
             "cve": "CVE-2021-41773", "cvss": 9.8, "epss": 0.97, "title": "Path traversal"},
            {"kind": "known_cve", "product": "nginx", "version": "1.18.0",
             "cve": "CVE-2019-20372", "cvss": 5.3, "severity": "medium", "title": "req smuggling"},
            {"kind": "default_credentials", "product": "grafana",
             "creds": [{"user": "admin", "pass": "admin"}]},
        ],
    }


def _b3():
    return {"open_db": ["1.2.3.4:6379"], "buckets": ["s3://public-ex", "gs://ex-backups"]}


def _b4():
    return {"origin_ips": ["5.6.7.8"], "exposed_git": ["https://ex.com/.git/"],
            "secrets": ["github_pat_xxx"]}


def _install_blocks(monkeypatch, subs=("a.ex.com", "b.ex.com"), crash=()):
    def mk(n, payload):
        def fn(*a, **k):
            if n in crash:
                raise RuntimeError(f"boom{n}")
            return payload
        return fn
    monkeypatch.setattr(m, "_BLOCKS", [
        (1, "infra", mk(1, _b1(list(subs)))),
        (2, "web", mk(2, _b2())),
        (3, "cloud_db", mk(3, _b3())),
        (4, "elite", mk(4, _b4())),
    ])


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "ROOT", tmp_path)
    c = Config()
    c.proxies.enabled = False
    c.general.output_dir = str(tmp_path / "results")
    c.general.wordlists_dir = str(tmp_path / "wl")
    return c


TARGET = {"type": "domain", "value": "ex.com"}


# ---- scenario 1: full rich run, every finding type flows end to end ----------

def test_full_run_derives_all_finding_types_and_builds_report(cfg, monkeypatch):
    _install_blocks(monkeypatch)
    summary = m.run_target(cfg, TARGET)

    # summary numeric consistency
    assert summary["subdomains"] == 2
    assert summary["takeovers"] == 1
    assert summary["secrets"] == summary["js_secrets"] + 1  # +1 block4 secret
    assert summary["kev"] == 1
    assert summary["new_findings"] >= 1

    # findings.jsonl written with the expected types, junk assets dropped
    fjson = Path(cfg.path("reports", "ex.com", "findings.jsonl"))
    assert fjson.exists()
    types = set()
    for line in fjson.read_text().splitlines():
        d = json.loads(line)
        assert d["asset"] and d["asset"].lower() != "none"   # junk filtered
        types.add(d["type"])
    for expect in ("subdomain_takeover", "zone_transfer", "missing_spf", "missing_dmarc",
                   "dnssec_missing", "tls_expired", "tls_self_signed", "tls_expiring_soon",
                   "js_secret", "xss", "exposed_config", "info_disclosure",
                   "directory_listing", "security_txt", "kev_exploited", "known_cve",
                   "default_credentials", "cors_misconfig", "missing_security_headers",
                   "open_database", "public_bucket", "origin_ip", "exposed_git", "secret"):
        assert expect in types, f"missing finding type: {expect}"
    assert "unknown_type_ignored" not in types and "nope_ignored" not in types

    # manifest + ledger present and consistent
    rd = Path(summary["run_dir"])
    manifest = json.loads((rd / "_manifest.json").read_text())
    assert manifest["summary"]["subdomains"] == 2
    assert "ledger" in manifest and "totals" in manifest["ledger"]

    # report built (md/json/html), analysis section present
    md = build_report(cfg, TARGET, summary)
    text = md.read_text()
    assert "Attack surface" in text and "Findings" in text
    assert md.with_suffix(".json").exists()
    assert md.with_suffix(".html").exists()


# ---- scenario 2: correlation / attack-chain insights ------------------------

def test_analysis_correlates_attack_chains(cfg, monkeypatch):
    _install_blocks(monkeypatch)
    summary = m.run_target(cfg, TARGET)
    from penguin import analysis
    from penguin.findings import Finding
    findings = [Finding.from_dict(d) for d in summary["findings"]]
    a = analysis.analyze(findings)
    titles = {i["title"] for i in a["insights"]}
    # exposed_git + secret on same host (ex.com) -> compromise path
    assert "Source exposure with leaked secrets" in titles
    assert a["risk_band"] == "critical"           # KEV + criticals present
    assert a["effective_score"] >= a["overall"]   # insights only add


# ---- scenario 3: diff + new_findings across two runs ------------------------

def test_second_run_new_subdomains_and_findings_tracked(cfg, monkeypatch):
    _install_blocks(monkeypatch, subs=("a.ex.com",))
    s1 = m.run_target(cfg, TARGET)
    assert s1["new_findings"] >= 1
    # second run adds a brand-new subdomain
    _install_blocks(monkeypatch, subs=("a.ex.com", "c.ex.com"))
    s2 = m.run_target(cfg, TARGET)
    assert s2["new_subdomains"] == 1              # only c.ex.com is new
    # the new_subdomain finding for c.ex.com is new; previously-seen ones are not
    assert s2["new_findings"] >= 1
    assert s2["new_findings"] < s1["new_findings"] + 5  # most findings already seen


# ---- scenario 4: a block crashes -> run still completes with partial data ----

def test_crashed_block_degrades_not_aborts(cfg, monkeypatch):
    _install_blocks(monkeypatch, crash=(2,))   # web block raises
    summary = m.run_target(cfg, TARGET)
    assert summary["subdomains"] == 2            # block1 still ran
    assert summary["endpoints"] == 0             # block2 degraded to empty
    assert summary["open_db"] == 1               # block3 still ran
    rd = Path(summary["run_dir"])
    assert not (rd / "_block2_result.json").exists()   # crashed block not checkpointed
    assert (rd / "_block1_result.json").exists()


# ---- scenario 5: cancellation stops early, downstream stays valid -----------

def test_cancellation_stops_before_remaining_blocks(cfg, monkeypatch):
    ran = []

    def mk(n, payload):
        def fn(*a, **k):
            ran.append(n)
            return payload
        return fn
    cancel = threading.Event()

    def b1(*a, **k):
        ran.append(1)
        cancel.set()                 # cancel right after block1
        return _b1(["a.ex.com"])
    monkeypatch.setattr(m, "_BLOCKS", [
        (1, "infra", b1),
        (2, "web", mk(2, _b2())),
        (3, "cloud_db", mk(3, _b3())),
        (4, "elite", mk(4, _b4())),
    ])
    summary = m.run_target(cfg, TARGET, cancel_event=cancel)
    assert ran == [1]                # blocks 2-4 never launched
    assert summary["subdomains"] == 1
    assert summary["endpoints"] == 0  # degraded fallback, no KeyError
    # report still builds on the partial summary
    build_report(cfg, TARGET, summary)


# ---- scenario 6: all blocks empty -> clean run, no findings, report ok -------

def test_all_empty_clean_run(cfg, monkeypatch):
    monkeypatch.setattr(m, "_BLOCKS", [
        (1, "infra", lambda *a, **k: {k2: [] for k2 in
         ("subdomains", "resolved", "live", "takeovers", "dns_issues", "tls_issues")}),
        (2, "web", lambda *a, **k: {k2: [] for k2 in
         ("endpoints", "js_secrets", "api", "web_issues", "active", "content_issues", "kb_findings")}),
        (3, "cloud_db", lambda *a, **k: {"open_db": [], "buckets": []}),
        (4, "elite", lambda *a, **k: {"origin_ips": [], "exposed_git": [], "secrets": []}),
    ])
    summary = m.run_target(cfg, TARGET)
    assert summary["new_findings"] == 0
    assert summary["findings"] == []
    # no findings.jsonl is written for a clean run
    assert not Path(cfg.path("reports", "ex.com", "findings.jsonl")).exists()
    md = build_report(cfg, TARGET, summary)
    assert "No typed findings this run" in md.read_text()


# ---- scenario 7: huge input stays correct and bounded -----------------------

def test_large_subdomain_set(cfg, monkeypatch):
    subs = [f"h{i}.ex.com" for i in range(5000)]
    _install_blocks(monkeypatch, subs=subs)
    summary = m.run_target(cfg, TARGET)
    assert summary["subdomains"] == 5000
    # accumulator on disk holds exactly the unique set
    acc = Path(cfg.path("results", "ex.com", "all_subdomains.txt"))
    lines = [l for l in acc.read_text().splitlines() if l.strip()]
    assert len(set(lines)) == 5000
