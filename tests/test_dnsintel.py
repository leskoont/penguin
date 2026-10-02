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


class _FakeCtx:
    """Minimal ToolContext stand-in: maps dig args -> (ok, stdout)."""
    def __init__(self, responses):
        self.responses = responses  # list of (match_substr, ok, stdout)
        from penguin.config import Config
        self.cfg = Config()

    def execute(self, tool, cmd, **kw):
        from penguin.runner import RunResult
        joined = " ".join(cmd)
        for sub, ok, out in self.responses:
            if sub in joined:
                return RunResult(cmd, 0 if ok else -1, out if ok else "", "" if ok else "missing", 1, 0.1, ok)
        return RunResult(cmd, -1, "", "no match", 1, 0.1, False)


class TestCheckDomainNoFalsePositives:
    def test_dig_missing_emits_nothing(self):
        from penguin.tools import dnsintel as di
        ctx = _FakeCtx([])  # every dig call fails (dig absent)
        assert di.check_domain(ctx, "ex.com") == []  # NO false missing_spf/dmarc/dnssec

    def test_successful_queries_with_no_records_flag_missing(self):
        from penguin.tools import dnsintel as di
        ctx = _FakeCtx([
            ("NS ex.com", True, ""),               # no NS -> no AXFR
            ("TXT ex.com", True, '"unrelated"'),   # no SPF -> missing_spf
            ("TXT _dmarc.ex.com", True, ""),       # no DMARC -> missing_dmarc
            ("DS ex.com", True, ""),               # no DS -> dnssec_missing
        ])
        types = {i["type"] for i in di.check_domain(ctx, "ex.com")}
        assert types == {"missing_spf", "missing_dmarc", "dnssec_missing"}

    def test_present_records_flag_nothing(self):
        from penguin.tools import dnsintel as di
        ctx = _FakeCtx([
            ("NS ex.com", True, ""),
            ("TXT ex.com", True, '"v=spf1 -all"'),
            ("TXT _dmarc.ex.com", True, '"v=DMARC1; p=reject"'),
            ("DS ex.com", True, "12345 13 2 ABCDEF"),
        ])
        assert di.check_domain(ctx, "ex.com") == []

    def test_partial_failure_only_flags_successful_queries(self):
        from penguin.tools import dnsintel as di
        ctx = _FakeCtx([
            ("NS ex.com", True, ""),
            ("TXT ex.com", False, ""),             # SPF query FAILED -> no missing_spf
            ("TXT _dmarc.ex.com", True, ""),       # DMARC ok, absent -> missing_dmarc
            ("DS ex.com", False, ""),              # DS query FAILED -> no dnssec_missing
        ])
        types = {i["type"] for i in di.check_domain(ctx, "ex.com")}
        assert types == {"missing_dmarc"}
