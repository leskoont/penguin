"""Tests for penguin.knowledge - version matching, tech extraction, KB matching."""
from penguin import knowledge as K
from penguin.knowledge import KnowledgeBank


class TestVersionMatches:
    def test_operators(self):
        assert K.version_matches("2.4.49", "==2.4.49")
        assert K.version_matches("1.17.0", "<1.17.7")
        assert not K.version_matches("1.18.0", "<1.17.7")
        assert K.version_matches("2.4.50", "<=2.4.50")
        assert K.version_matches("9.4", ">=9.3")
        assert not K.version_matches("9.2", ">=9.3")

    def test_wildcard_matches_even_without_version(self):
        assert K.version_matches(None, "*")
        assert K.version_matches("", "*")

    def test_unknown_version_specific_constraint_no_match(self):
        # avoid false positives: no version + a real constraint -> not vulnerable
        assert not K.version_matches(None, "<2.0")
        assert not K.version_matches("", "==1.0")

    def test_bare_version_is_exact(self):
        assert K.version_matches("1.0", "1.0")
        assert not K.version_matches("1.1", "1.0")


class TestCvssSeverity:
    def test_bands(self):
        assert K.cvss_severity(9.8) == "critical"
        assert K.cvss_severity(7.5) == "high"
        assert K.cvss_severity(5.0) == "medium"
        assert K.cvss_severity(2.0) == "low"
        assert K.cvss_severity(0) == "info"


class TestNormalizeTech:
    def test_name_and_version(self):
        assert K.normalize_tech("Apache httpd 2.4.49") == ("apache", "2.4.49")
        assert K.normalize_tech("nginx:1.18") == ("nginx", "1.18")
        assert K.normalize_tech("jQuery") == ("jquery", None)

    def test_unknown(self):
        assert K.normalize_tech("SomeRandomThing")[0] == ""
        assert K.normalize_tech("") == ("", None)


class TestExtractTechnologies:
    def test_httpx_bracket_and_lines(self):
        techs = K.extract_technologies("[Apache:2.4.49],[jQuery:3.4.1]",
                                       "OpenSSH 8.0\nWordPress 5.7")
        assert ("apache", "2.4.49") in techs
        assert ("jquery", "3.4.1") in techs
        assert ("openssh", "8.0") in techs

    def test_dedup_and_unknown_dropped(self):
        techs = K.extract_technologies("nginx 1.18, nginx 1.18, TotallyUnknown 1.0")
        assert techs.count(("nginx", "1.18")) == 1
        assert all(p for p, _ in techs)


class TestKnowledgeBankMatch:
    def setup_method(self):
        self.kb = KnowledgeBank.load()

    def test_seed_loaded(self):
        assert len(self.kb.kev) >= 5
        assert "apache" in self.kb.cve_index

    def test_kev_flagged(self):
        vec = self.kb.match([("apache", "2.4.49")])
        kinds = {v["kind"] for v in vec}
        assert "kev_exploited" in kinds  # CVE-2021-41773 is in seed KEV
        kev = [v for v in vec if v["kind"] == "kev_exploited"][0]
        assert kev["cve"] == "CVE-2021-41773" and kev["severity"] == "critical"

    def test_log4shell_kev(self):
        vec = self.kb.match([("log4j", "2.14.0")])
        assert any(v["kind"] == "kev_exploited" and v["cve"] == "CVE-2021-44228" for v in vec)

    def test_non_vulnerable_version_no_match(self):
        # nginx 1.18 is NOT < 1.17.7 -> no CVE
        vec = [v for v in self.kb.match([("nginx", "1.18.0")]) if v["kind"] in ("known_cve", "kev_exploited")]
        assert vec == []

    def test_default_credentials_vector(self):
        vec = self.kb.match([("tomcat", "9.0")])
        assert any(v["kind"] == "default_credentials" for v in vec)

    def test_cve_dedup_across_tech(self):
        vec = self.kb.match([("apache", "2.4.49"), ("apache", "2.4.49")])
        cves = [v["cve"] for v in vec if v.get("cve")]
        assert len(cves) == len(set(cves))

    def test_extra_dir_merge(self, tmp_path):
        import json
        (tmp_path / "cve_index.json").write_text(json.dumps({
            "products": {"customapp": [{"cve": "CVE-9999-0001", "constraint": "*", "cvss": 9.1}]}}),
            encoding="utf-8")
        kb = KnowledgeBank.load([tmp_path])
        vec = kb.match([("customapp", "1.0")])
        assert any(v.get("cve") == "CVE-9999-0001" for v in vec)


class TestKbEndToEnd:
    """detected tech -> KB vectors -> findings -> correlated critical insight."""

    def test_kev_drives_critical_insight(self):
        from penguin import analysis as A
        from penguin.findings import derive_findings
        kb = KnowledgeBank.load()
        techs = K.extract_technologies("[Apache:2.4.49]")  # vulnerable + in KEV
        b2 = {"endpoints": [], "js_secrets": [], "api": [], "web_issues": [],
              "active": [], "content_issues": [], "kb_findings": kb.match(techs)}
        b1 = {"subdomains": [], "resolved": [], "live": [], "takeovers": [],
              "dns_issues": [], "tls_issues": []}
        fs = derive_findings({"type": "domain", "value": "ex.com"}, b1, b2,
                             {"open_db": [], "buckets": []},
                             {"origin_ips": [], "exposed_git": [], "secrets": []}, {"new": []})
        assert any(f.type == "kev_exploited" and f.severity == "critical" for f in fs)
        a = A.analyze(fs)
        assert a["risk_band"] in ("high", "critical")
        assert any(i["title"] == "Actively-exploited CVE present" for i in a["insights"])
