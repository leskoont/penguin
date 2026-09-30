"""Tests for penguin.tools.tlsintel - pure cert parsing/analysis."""
from datetime import datetime, timezone

from penguin.tools import tlsintel as T

_SCLIENT = """CONNECTED(00000003)
Certificate chain
 0 s:CN=ex.com
-----BEGIN CERTIFICATE-----
MIIBfakebase64==
-----END CERTIFICATE-----
---
"""

_X509 = """notBefore=Jan  1 00:00:00 2024 GMT
notAfter=Dec 31 23:59:59 2025 GMT
issuer=C=US, O=Let's Encrypt, CN=R3
subject=CN=ex.com
X509v3 Subject Alternative Name:
    DNS:ex.com, DNS:www.ex.com, DNS:*.api.ex.com
"""

_X509_SELF = """notBefore=Jan  1 00:00:00 2024 GMT
notAfter=Dec 31 23:59:59 2030 GMT
issuer=CN=ex.com
subject=CN=ex.com
"""


class TestExtractPem:
    def test_extracts_block(self):
        assert T.extract_pem(_SCLIENT).startswith("-----BEGIN CERTIFICATE-----")

    def test_none_when_absent(self):
        assert T.extract_pem("no cert here") is None


class TestParseX509:
    def test_dates_and_sans(self):
        p = T.parse_x509_text(_X509)
        assert p["not_after"].year == 2025
        assert p["sans"] == ["ex.com", "www.ex.com", "api.ex.com"]  # wildcard stripped
        assert "Let's Encrypt" in p["issuer"]

    def test_missing_fields(self):
        p = T.parse_x509_text("")
        assert p["not_after"] is None and p["sans"] == []


class TestAnalyzeCert:
    def test_expired(self):
        p = T.parse_x509_text(_X509)
        a = T.analyze_cert(p, now=datetime(2026, 6, 1, tzinfo=timezone.utc))
        assert a["expired"] is True and a["days_left"] < 0

    def test_valid_not_expired(self):
        p = T.parse_x509_text(_X509)
        a = T.analyze_cert(p, now=datetime(2025, 1, 1, tzinfo=timezone.utc))
        assert a["expired"] is False and a["self_signed"] is False

    def test_expiring_soon(self):
        p = T.parse_x509_text(_X509)
        a = T.analyze_cert(p, now=datetime(2025, 12, 25, tzinfo=timezone.utc))
        assert a["expiring_soon"] is True and a["expired"] is False

    def test_self_signed(self):
        p = T.parse_x509_text(_X509_SELF)
        a = T.analyze_cert(p, now=datetime(2025, 1, 1, tzinfo=timezone.utc))
        assert a["self_signed"] is True
