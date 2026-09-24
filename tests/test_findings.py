"""Tests for penguin.findings - derivation and cross-run dedup."""
from penguin.findings import (
    Finding,
    FindingStore,
    derive_findings,
    severity_sort_key,
)

_TARGET = {"type": "domain", "value": "ex.com"}


def _blocks(js_secrets=(), open_db=(), buckets=(), origin=(), git=(), secrets=()):
    b1 = {"subdomains": [], "resolved": [], "live": []}
    b2 = {"endpoints": [], "js_secrets": list(js_secrets), "api": []}
    b3 = {"open_db": list(open_db), "buckets": list(buckets)}
    b4 = {"origin_ips": list(origin), "exposed_git": list(git), "secrets": list(secrets)}
    return b1, b2, b3, b4


class TestDerive:
    def test_maps_each_artifact_to_typed_finding(self):
        b1, b2, b3, b4 = _blocks(js_secrets=["k"], open_db=["1:6379"],
                                 buckets=["s3://x"], origin=["1.2.3.4"],
                                 git=["http://h/.git/"], secrets=["/s.txt"])
        diff = {"new": ["a.ex.com"], "removed": []}
        fs = derive_findings(_TARGET, b1, b2, b3, b4, diff)
        types = {f.type for f in fs}
        assert types == {"new_subdomain", "js_secret", "open_database",
                         "public_bucket", "origin_ip", "exposed_git", "secret"}

    def test_severities(self):
        b1, b2, b3, b4 = _blocks(git=["g"], secrets=["s"], js_secrets=["j"],
                                 open_db=["d"], buckets=["b"], origin=["o"])
        sev = {f.type: f.severity for f in derive_findings(_TARGET, b1, b2, b3, b4, {"new": []})}
        assert sev["exposed_git"] == "critical"
        assert sev["secret"] == "critical"
        assert sev["js_secret"] == "high"
        assert sev["open_database"] == "high"
        assert sev["public_bucket"] == "medium"
        assert sev["origin_ip"] == "medium"

    def test_empty_blocks_no_findings(self):
        b1, b2, b3, b4 = _blocks()
        assert derive_findings(_TARGET, b1, b2, b3, b4, {"new": []}) == []

    def test_web_issues_map_to_cors_and_header_findings(self):
        b1, b2, b3, b4 = _blocks()
        b2["web_issues"] = [
            {"url": "https://a.ex.com", "cors_bad": True, "cors_credentials": True, "missing": []},
            {"url": "https://b.ex.com", "cors_bad": False, "missing": ["content-security-policy"]},
        ]
        fs = derive_findings(_TARGET, b1, b2, b3, b4, {"new": []})
        by = {f.type: f for f in fs}
        assert by["cors_misconfig"].severity == "high"
        assert "credentials" in by["cors_misconfig"].evidence
        assert by["missing_security_headers"].severity == "low"

    def test_takeover_is_critical_finding(self):
        b1, b2, b3, b4 = _blocks()
        b1["takeovers"] = ["gone.ex.com"]
        fs = derive_findings(_TARGET, b1, b2, b3, b4, {"new": []})
        assert len(fs) == 1
        assert fs[0].type == "subdomain_takeover"
        assert fs[0].severity == "critical"
        assert fs[0].url == "gone.ex.com"

    def test_severity_sort_orders_critical_first(self):
        fs = [Finding("new_subdomain", "info", "t", "a"),
              Finding("exposed_git", "critical", "t", "b")]
        fs.sort(key=severity_sort_key)
        assert fs[0].type == "exposed_git"


class TestFindingStore:
    def test_first_run_all_new(self, tmp_path):
        store = FindingStore.for_target(tmp_path, "ex.com")
        b1, b2, b3, b4 = _blocks(git=["http://h/.git/"], secrets=["/s"])
        fs = derive_findings(_TARGET, b1, b2, b3, b4, {"new": ["a.ex.com"]})
        current, new = store.record(fs, "run_1")
        assert len(new) == len(fs) == 3
        assert all(f.first_seen_run == "run_1" for f in current)

    def test_second_run_dedups_and_preserves_first_seen(self, tmp_path):
        b1, b2, b3, b4 = _blocks(git=["http://h/.git/"])
        fs1 = derive_findings(_TARGET, b1, b2, b3, b4, {"new": ["a.ex.com"]})
        FindingStore.for_target(tmp_path, "ex.com").record(fs1, "run_1")

        # reload from disk; add one new subdomain, keep the git finding
        store2 = FindingStore.for_target(tmp_path, "ex.com")
        fs2 = derive_findings(_TARGET, b1, b2, b3, b4, {"new": ["b.ex.com"]})
        current, new = store2.record(fs2, "run_2")
        assert [f.asset for f in new] == ["b.ex.com"]
        git = [f for f in current if f.type == "exposed_git"][0]
        assert git.first_seen_run == "run_1"

    def test_persistence_roundtrip(self, tmp_path):
        b1, b2, b3, b4 = _blocks(secrets=["/s"])
        fs = derive_findings(_TARGET, b1, b2, b3, b4, {"new": []})
        FindingStore.for_target(tmp_path, "ex.com").record(fs, "run_1")
        reloaded = FindingStore.for_target(tmp_path, "ex.com")
        # a re-record of the same finding yields zero new
        _, new = reloaded.record(fs, "run_2")
        assert new == []
