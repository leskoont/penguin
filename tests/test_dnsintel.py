"""Tests for penguin.tools.dnsintel - pure DNS-output parsers."""
from penguin.tools import dnsintel as di

_AXFR_OK = """; <<>> DiG <<>> AXFR ex.com @ns1
ex.com.        3600 IN SOA ns1.ex.com. hostmaster.ex.com. 1 7200 3600 1209600 3600
ex.com.        3600 IN NS  ns1.ex.com.
www.ex.com.    3600 IN A   1.2.3.4
mail.ex.com.   3600 IN A   1.2.3.5
ex.com.        3600 IN SOA ns1.ex.com. hostmaster.ex.com. 1 7200 3600 1209600 3600
"""

_AXFR_REFUSED = """; <<>> DiG <<>> AXFR ex.com @ns1
; Transfer failed.
"""

_AXFR_SOA_ONLY = """ex.com.  3600 IN SOA ns1.ex.com. hostmaster.ex.com. 1 7200 3600 1209600 3600
"""


class TestAxfr:
    def test_successful_transfer_returns_records(self):
        recs = di.axfr_records(_AXFR_OK)
        assert any("www.ex.com" in r for r in recs)
        assert any("mail.ex.com" in r for r in recs)

    def test_refused_returns_empty(self):
        assert di.axfr_records(_AXFR_REFUSED) == []

    def test_soa_only_is_not_a_transfer(self):
        assert di.axfr_records(_AXFR_SOA_ONLY) == []

    def test_timeout_returns_empty(self):
        assert di.axfr_records("; connection timed out; no servers could be reached") == []


class TestSpfDmarc:
    def test_has_spf(self):
        assert di.has_spf('"v=spf1 include:_spf.google.com ~all"') is True
        assert di.has_spf('"some other txt"') is False

    def test_has_dmarc(self):
        assert di.has_dmarc('"v=DMARC1; p=reject"') is True
        assert di.has_dmarc('"v=spf1 ~all"') is False

    def test_empty(self):
        assert di.has_spf("") is False
        assert di.has_dmarc("") is False


class TestParseShort:
    def test_cleans_and_dedups(self):
        out = "ns1.ex.com.\nns2.ex.com.\nns1.ex.com.\n; comment\n\n"
        assert di.parse_short(out) == ["ns1.ex.com", "ns2.ex.com"]
