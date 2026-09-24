"""Tests for penguin.tools.webchecks - header parsing + CORS/security analysis."""
from penguin.config import Config
from penguin.tools import webchecks as wc
from penguin.tools._base import ToolContext

PROBE = wc.CORS_PROBE_ORIGIN


def _resp(status=200, headers=None):
    lines = [f"HTTP/1.1 {status} OK"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    return "\r\n".join(lines) + "\r\n"


class TestAnalyzeHeaders:
    def test_all_present_no_cors(self):
        raw = _resp(headers={
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=63072000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        })
        r = wc.analyze_headers(raw)
        assert r["missing"] == []
        assert not r["cors_reflected"] and not r["cors_wildcard"]
        assert r["status"] == 200

    def test_missing_headers_listed(self):
        raw = _resp(headers={"X-Frame-Options": "DENY"})
        r = wc.analyze_headers(raw)
        assert "content-security-policy" in r["missing"]
        assert "x-frame-options" not in r["missing"]

    def test_cors_reflects_probe_origin(self):
        raw = _resp(headers={"Access-Control-Allow-Origin": PROBE,
                             "Access-Control-Allow-Credentials": "true"})
        r = wc.analyze_headers(raw)
        assert r["cors_reflected"] is True
        assert r["cors_credentials"] is True

    def test_cors_wildcard(self):
        raw = _resp(headers={"Access-Control-Allow-Origin": "*"})
        r = wc.analyze_headers(raw)
        assert r["cors_wildcard"] is True
        assert r["cors_reflected"] is False

    def test_multi_block_keeps_last(self):
        # proxy CONNECT 200 then real 301 then final 200 headers
        raw = (_resp(200) + _resp(301, {"Location": "https://x"})
               + _resp(200, {"X-Frame-Options": "DENY"}))
        r = wc.analyze_headers(raw)
        assert r["status"] == 200
        assert "x-frame-options" not in r["missing"]

    def test_case_insensitive_header_names(self):
        raw = _resp(headers={"content-security-policy": "x",
                             "STRICT-TRANSPORT-SECURITY": "y",
                             "X-Frame-Options": "z",
                             "x-content-type-options": "nosniff"})
        assert wc.analyze_headers(raw)["missing"] == []


class TestCheckHost:
    def _ctx(self):
        return ToolContext(Config())

    def test_returns_none_when_clean(self, monkeypatch):
        ctx = self._ctx()
        monkeypatch.setattr(wc, "fetch_headers", lambda c, u, **k: _resp(headers={
            "Content-Security-Policy": "x", "Strict-Transport-Security": "y",
            "X-Frame-Options": "z", "X-Content-Type-Options": "nosniff",
        }))
        assert wc.check_host(ctx, "https://x.com") is None

    def test_flags_missing_headers(self, monkeypatch):
        ctx = self._ctx()
        monkeypatch.setattr(wc, "fetch_headers", lambda c, u, **k: _resp(headers={}))
        issue = wc.check_host(ctx, "https://x.com")
        assert issue is not None
        assert issue["url"] == "https://x.com"
        assert len(issue["missing"]) == 4

    def test_flags_cors(self, monkeypatch):
        ctx = self._ctx()
        monkeypatch.setattr(wc, "fetch_headers", lambda c, u, **k: _resp(headers={
            "Content-Security-Policy": "x", "Strict-Transport-Security": "y",
            "X-Frame-Options": "z", "X-Content-Type-Options": "nosniff",
            "Access-Control-Allow-Origin": PROBE,
        }))
        issue = wc.check_host(ctx, "https://x.com")
        assert issue is not None and issue["cors_bad"] is True

    def test_none_on_fetch_failure(self, monkeypatch):
        ctx = self._ctx()
        monkeypatch.setattr(wc, "fetch_headers", lambda c, u, **k: None)
        assert wc.check_host(ctx, "https://x.com") is None
