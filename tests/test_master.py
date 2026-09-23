"""Tests for penguin.pipelines.master - critical-findings detection."""
from penguin.pipelines.master import _critical_findings

_EMPTY2 = {"endpoints": [], "js_secrets": [], "api": []}
_EMPTY3 = {"open_db": [], "buckets": []}
_EMPTY4 = {"origin_ips": [], "exposed_git": [], "secrets": []}


class TestCriticalFindings:
    def test_all_empty_returns_nothing(self):
        assert _critical_findings(_EMPTY2, _EMPTY3, _EMPTY4) == {}

    def test_secrets_combine_js_and_block4(self):
        b2 = {**_EMPTY2, "js_secrets": ["aws_key"]}
        b4 = {**_EMPTY4, "secrets": ["gh_token", "db_pw"]}
        hits = _critical_findings(b2, _EMPTY3, b4)
        assert hits == {"secrets": 3}

    def test_open_db_and_buckets_and_git(self):
        b3 = {"open_db": ["1.2.3.4:6379"], "buckets": ["s3://x", "s3://y"]}
        b4 = {**_EMPTY4, "exposed_git": ["http://h/.git/"]}
        hits = _critical_findings(_EMPTY2, b3, b4)
        assert hits == {
            "open databases": 1,
            "exposed .git": 1,
            "public buckets": 2,
        }

    def test_only_nonzero_categories_included(self):
        b3 = {"open_db": ["1.2.3.4:27017"], "buckets": []}
        hits = _critical_findings(_EMPTY2, b3, _EMPTY4)
        assert hits == {"open databases": 1}

    def test_tolerates_missing_keys(self):
        # blocks that degraded may hand back partial dicts
        assert _critical_findings({}, {}, {}) == {}
        assert _critical_findings({"js_secrets": ["x"]}, {}, {}) == {"secrets": 1}
