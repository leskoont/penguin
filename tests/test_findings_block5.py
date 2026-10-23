"""Tests for the block5 finding derivation + correlation wiring."""
from penguin.analysis import correlate
from penguin.findings import derive_findings

TARGET = {"type": "domain", "value": "ex.com"}


class TestDeriveBlock5:
    def test_cve_hits_become_nuclei_cve_findings(self):
        b5 = {"cve_hits": [{"cve": "CVE-2021-44228", "host": "https://a.ex.com",
                            "name": "log4j RCE", "severity": "critical"}],
              "service_vectors": [], "stragglers": [], "new_live": [], "web_issues": []}
        out = derive_findings(TARGET, {}, {}, {}, {}, {}, b5=b5)
        hits = [f for f in out if f.type == "nuclei_cve"]
        assert len(hits) == 1
        f = hits[0]
        assert f.asset == "CVE-2021-44228"
        assert f.severity == "critical"
        assert f.url == "https://a.ex.com"
        assert f.evidence == "log4j RCE"

    def test_cve_hit_without_cve_id_falls_back_to_host(self):
        b5 = {"cve_hits": [{"cve": "", "template_id": "tech-detect-x", "host": "h.ex.com",
                            "name": "", "severity": "medium"}]}
        out = derive_findings(TARGET, {}, {}, {}, {}, {}, b5=b5)
        assert out[0].asset == "tech-detect-x"
        assert out[0].severity == "high"

    def test_service_vectors_attribute_host(self):
        b5 = {"service_vectors": [{"kind": "default_credentials", "product": "redis",
                                   "version": None, "creds": [{"user": "a", "pass": "b"}],
                                   "host": "1.2.3.4:6379"}],
              "cve_hits": []}
        out = derive_findings(TARGET, {}, {}, {}, {}, {}, b5=b5)
        assert len(out) == 1
        f = out[0]
        assert f.type == "default_credentials"
        assert f.asset == "redis @ 1.2.3.4:6379"
        assert f.url == "1.2.3.4:6379"

    def test_no_b5_keeps_old_call_signature(self):
        # callers predating block5 must keep working
        out = derive_findings(TARGET, {}, {}, {}, {}, {"new": ["x.ex.com"]})
        assert [f.type for f in out] == ["new_subdomain"]

    def test_non_dict_entries_tolerated(self):
        b5 = {"cve_hits": [None, "junk", {"cve": "CVE-2024-0001", "host": "h", "severity": "low"}],
              "service_vectors": [None]}
        out = derive_findings(TARGET, {}, {}, {}, {}, {}, b5=b5)
        assert [f.type for f in out] == ["nuclei_cve"]


class TestCorrelation:
    def test_nuclei_cve_chains_with_exposure(self):
        from penguin.findings import Finding
        findings = [
            Finding(type="nuclei_cve", severity="high", target="ex.com",
                    asset="CVE-2024-0001", url="https://a.ex.com"),
            Finding(type="open_database", severity="high", target="ex.com",
                    asset="a.ex.com:6379"),
        ]
        insights = correlate(findings)
        titles = [i.title for i in insights]
        assert "Known CVE on an already-exposed asset" in titles
