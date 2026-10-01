"""Tests for penguin.analysis - scoring, host grouping, correlation."""
from penguin import analysis as A
from penguin.findings import Finding


def F(type_, sev, target="ex.com", asset="", url="", evidence=""):
    return Finding(type=type_, severity=sev, target=target, asset=asset, url=url, evidence=evidence)


class TestHostOf:
    def test_url(self):
        assert A.host_of(F("x", "low", url="https://a.ex.com/p?q=1")) == "a.ex.com"

    def test_host_port(self):
        assert A.host_of(F("open_database", "high", asset="1.2.3.4:6379")) == "1.2.3.4"

    def test_bare_host(self):
        assert A.host_of(F("new_subdomain", "info", asset="b.ex.com")) == "b.ex.com"

    def test_evidence_path_falls_back_to_target(self):
        assert A.host_of(F("secret", "critical", target="ex.com", asset="/run/s.txt")) == "ex.com"


class TestScore:
    def test_weights_and_overall(self):
        fs = [F("exposed_git", "critical"), F("open_database", "high"),
              F("public_bucket", "medium"), F("missing_security_headers", "low"),
              F("new_subdomain", "info")]
        s = A.score(fs)
        assert s["overall"] == 100 + 40 + 10 + 3 + 1

    def test_per_host_top_severity(self):
        fs = [F("open_database", "high", asset="h.ex.com:1"),
              F("missing_security_headers", "low", url="https://h.ex.com")]
        s = A.score(fs)
        assert s["by_host"]["h.ex.com"]["top_severity"] == "high"
        assert s["by_host"]["h.ex.com"]["count"] == 2

    def test_rank_hosts_orders_by_score(self):
        fs = [F("exposed_git", "critical", url="https://big.ex.com"),
              F("missing_security_headers", "low", url="https://small.ex.com")]
        ranked = A.rank_hosts(A.score(fs))
        assert ranked[0][0] == "big.ex.com"


class TestCorrelate:
    def test_git_plus_secret_chain(self):
        fs = [F("exposed_git", "critical", url="https://a.ex.com/.git/"),
              F("js_secret", "high", url="https://a.ex.com/app.js")]
        ins = A.correlate(fs)
        assert any(i.title == "Source exposure with leaked secrets" and i.severity == "critical"
                   for i in ins)

    def test_takeover_insight(self):
        ins = A.correlate([F("subdomain_takeover", "critical", url="gone.ex.com")])
        assert any(i.title == "Hijackable subdomain" for i in ins)

    def test_cors_plus_secret(self):
        fs = [F("cors_misconfig", "high", url="https://a.ex.com"),
              F("js_secret", "high", url="https://a.ex.com/x.js")]
        ins = A.correlate(fs)
        assert any("token theft" in i.title for i in ins)

    def test_systemic_weak_headers(self):
        fs = [F("missing_security_headers", "low", url=f"https://a.ex.com/{i}") for i in range(3)]
        # all same host -> one host with 3 missing-header findings
        fs = [F("missing_security_headers", "low", url="https://a.ex.com") for _ in range(3)]
        ins = A.correlate(fs)
        assert any(i.title == "Systemically weak security headers" for i in ins)

    def test_kev_insight(self):
        ins = A.correlate([F("kev_exploited", "critical", target="ex.com", asset="CVE-2021-41773")])
        assert any(i.title == "Actively-exploited CVE present" for i in ins)

    def test_known_cve_on_exposed_asset_chain(self):
        fs = [F("known_cve", "high", target="ex.com", asset="CVE-x", url="https://a.ex.com"),
              F("open_database", "high", asset="a.ex.com:6379", url="")]
        # put both on same host a.ex.com
        fs = [F("known_cve", "high", url="https://a.ex.com"),
              F("exposed_config", "high", url="https://a.ex.com/.env")]
        ins = A.correlate(fs)
        assert any(i.title == "Known CVE on an already-exposed asset" for i in ins)

    def test_config_plus_secret_chain(self):
        fs = [F("exposed_config", "high", url="https://a.ex.com/.env"),
              F("js_secret", "high", url="https://a.ex.com/app.js")]
        ins = A.correlate(fs)
        assert any(i.title == "Exposed config leaking credentials" for i in ins)

    def test_zone_transfer_insight(self):
        ins = A.correlate([F("zone_transfer", "critical", target="ex.com", asset="ex.com")])
        assert any(i.title == "DNS zone transfer allowed" for i in ins)

    def test_email_spoofable_insight(self):
        fs = [F("missing_spf", "low", target="ex.com", asset="ex.com"),
              F("missing_dmarc", "medium", target="ex.com", asset="ex.com")]
        ins = A.correlate(fs)
        assert any(i.title == "Email domain spoofable" for i in ins)

    def test_no_false_chain(self):
        # git on one host, secret on another -> no chain
        fs = [F("exposed_git", "critical", url="https://a.ex.com/.git/"),
              F("js_secret", "high", url="https://b.ex.com/x.js")]
        ins = A.correlate(fs)
        assert not any(i.title == "Source exposure with leaked secrets" for i in ins)


class TestRiskBand:
    def test_bands(self):
        assert A.risk_band(0) == "clean"
        assert A.risk_band(10) == "low"
        assert A.risk_band(50) == "elevated"
        assert A.risk_band(120) == "high"
        assert A.risk_band(500) == "critical"


class TestAnalyze:
    def test_shape(self):
        a = A.analyze([F("exposed_git", "critical", url="https://a.ex.com/.git/")])
        assert a["risk_band"] == "high"
        assert a["top_hosts"][0]["host"] == "a.ex.com"
        assert isinstance(a["insights"], list)

    def test_empty(self):
        a = A.analyze([])
        assert a["overall"] == 0 and a["risk_band"] == "clean"
        assert a["top_hosts"] == [] and a["insights"] == []
