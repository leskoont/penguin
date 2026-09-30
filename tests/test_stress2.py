"""Hardcore stress round for the analytics + intel vectors.

Adversarial: fuzzed/binary/huge/malformed inputs and an end-to-end run_target
with every new vector populated, to surface crashes the happy-path tests miss.
"""
import random
import string

from penguin import analysis as A
from penguin.findings import Finding, FindingStore, derive_findings
from penguin.tools import contentintel as ci
from penguin.tools import dnsintel as di
from penguin.tools import tlsintel as tls


def _rand(n):
    return "".join(random.choice(string.printable) for _ in range(n))


# ------------------------------------------------------------------- analysis

class TestAnalysisFuzz:
    def test_host_of_weird_inputs(self):
        for asset, url in [("", ""), (":::", ""), ("http://", ""),
                           ("[::1]:8080", ""), ("a b c", ""), ("//////", ""),
                           ("HTTPS://A.EX.COM/P", ""), ("nodothost", "")]:
            f = Finding("x", "low", "ex.com", asset, url=url)
            h = A.host_of(f)
            assert isinstance(h, str) and h  # never empty / never raises

    def test_score_huge(self):
        sev = ["critical", "high", "medium", "low", "info"]
        fs = [Finding(f"t{i%12}", random.choice(sev), "ex.com",
                      f"h{i%500}.ex.com", url=f"https://h{i%500}.ex.com/{i}")
              for i in range(100000)]
        a = A.analyze(fs, top=20)
        assert a["overall"] > 0
        assert len(a["top_hosts"]) == 20

    def test_correlate_tolerates_unknown_severity(self):
        fs = [Finding("weird", "banana", "ex.com", "a.ex.com", url="https://a.ex.com")]
        A.analyze(fs)  # must not raise on unknown severity

    def test_correlate_empty_and_missing_fields(self):
        assert A.correlate([]) == []
        # Finding with blank asset/url/target
        A.correlate([Finding("exposed_git", "critical", "", "", url="")])


# ------------------------------------------------------------------- dns intel

class TestDnsFuzz:
    def test_axfr_binary_junk(self):
        di.axfr_records(_rand(20000))  # must not raise

    def test_axfr_huge_zone(self):
        lines = [f"h{i}.ex.com. 3600 IN A 1.2.3.{i%255}" for i in range(50000)]
        recs = di.axfr_records("\n".join(lines))
        assert len(recs) == 50000

    def test_parse_short_junk(self):
        di.parse_short(_rand(10000))

    def test_spf_dmarc_junk(self):
        assert di.has_spf(_rand(5000)) in (True, False)
        assert di.has_dmarc(_rand(5000)) in (True, False)


# ------------------------------------------------------------------- tls intel

class TestTlsFuzz:
    def test_parse_x509_garbage(self):
        tls.parse_x509_text(_rand(10000))  # must not raise

    def test_parse_x509_malformed_dates(self):
        p = tls.parse_x509_text("notAfter=not a date\nnotBefore=\n")
        assert p["not_after"] is None
        a = tls.analyze_cert(p)
        assert a["days_left"] is None and a["expired"] is False

    def test_huge_san_list(self):
        sans = ", ".join(f"DNS:h{i}.ex.com" for i in range(20000))
        p = tls.parse_x509_text(f"X509v3 Subject Alternative Name:\n    {sans}\n")
        assert len(p["sans"]) == 20000

    def test_extract_pem_partial(self):
        assert tls.extract_pem("-----BEGIN CERTIFICATE-----\nno end") is None


# --------------------------------------------------------------- content intel

class TestContentFuzz:
    def test_classify_binary_body(self):
        for path in ci.SENSITIVE_PATHS:
            ci.classify(path, 200, _rand(4096))  # must not raise

    def test_mine_robots_huge(self):
        txt = "\n".join(f"Disallow: /p{i}" for i in range(20000))
        assert len(ci.mine_robots(txt)) == 20000

    def test_mine_sitemap_malformed(self):
        ci.mine_sitemap("<loc>unclosed" * 1000)  # must not raise
        assert ci.mine_sitemap("<loc></loc>") == []


# --------------------------------------------------------------- findings fuzz

class TestFindingsFuzz:
    def test_derive_all_vectors_with_malformed_entries(self):
        b1 = {
            "subdomains": ["a.ex.com"], "resolved": [], "live": [],
            "takeovers": ["gone.ex.com", None],  # None entry
            "dns_issues": [{"type": "zone_transfer", "domain": "ex.com"}, "notadict", 42],
            "tls_issues": [{"host": "a.ex.com", "expired": True, "days_left": -1}, None],
        }
        b2 = {
            "endpoints": [], "js_secrets": ["AKIA"], "api": [],
            "web_issues": [{"url": "https://a.ex.com", "missing": ["csp"]}, "bad"],
            "active": ["https://a.ex.com/?q=x"],
            "content_issues": [{"url": "https://a.ex.com/.env", "kind": "exposed_config"}, None, "x"],
        }
        b3 = {"open_db": ["1.2.3.4:6379"], "buckets": []}
        b4 = {"origin_ips": [], "exposed_git": ["http://a.ex.com/.git/"], "secrets": ["/s"]}
        fs = derive_findings({"type": "domain", "value": "ex.com"}, b1, b2, b3, b4,
                             {"new": ["n.ex.com"]})
        # must not crash and must include a spread of types
        types = {f.type for f in fs}
        assert "zone_transfer" in types and "exposed_config" in types and "xss" in types
        # None list entries must NOT leak junk "None"-asset findings
        assert all(f.asset and f.asset.lower() != "none" for f in fs)
        # and the analysis layer must consume them cleanly
        a = A.analyze(fs)
        assert a["overall"] > 0


class TestEndToEndAllVectors:
    """run_target with every new vector populated -> report/analyze/manifest OK."""

    def _isolate(self, tmp_path, monkeypatch):
        import penguin.config as C
        from penguin.config import Config
        monkeypatch.setattr(C, "ROOT", tmp_path)
        cfg = Config()
        cfg.proxies.enabled = False
        cfg.general.output_dir = str(tmp_path / "results")
        cfg.general.wordlists_dir = str(tmp_path / "wl")
        return cfg

    def test_full_pipeline_all_vectors(self, tmp_path, monkeypatch):
        import penguin.pipelines.master as m
        from penguin.pipelines.report import build_report
        cfg = self._isolate(tmp_path, monkeypatch)
        monkeypatch.setattr(m, "_BLOCKS", [
            (1, "infra", lambda *a, **k: {
                "subdomains": ["a.ex.com", "b.ex.com"], "resolved": ["a.ex.com"],
                "live": [], "takeovers": ["gone.ex.com"],
                "dns_issues": [{"type": "zone_transfer", "domain": "ex.com", "ns": "ns1"},
                               {"type": "missing_spf", "domain": "ex.com"},
                               {"type": "missing_dmarc", "domain": "ex.com"}],
                "tls_issues": [{"host": "a.ex.com", "expired": True, "self_signed": True, "days_left": -3}]}),
            (2, "web", lambda *a, **k: {
                "endpoints": ["/api"], "js_secrets": ["AKIA"], "api": [],
                "web_issues": [{"url": "https://a.ex.com", "cors_bad": True, "missing": ["csp"]}],
                "active": ["https://a.ex.com/?q=x"],
                "content_issues": [{"url": "https://a.ex.com/.env", "kind": "exposed_config"}]}),
            (3, "cloud_db", lambda *a, **k: {"open_db": ["1.2.3.4:6379"], "buckets": ["s3://x"]}),
            (4, "elite", lambda *a, **k: {"origin_ips": ["1.1.1.1"], "exposed_git": ["http://a.ex.com/.git/"],
                                          "secrets": ["/s.txt"]}),
        ])
        target = {"type": "domain", "value": "ex.com"}
        summary = m.run_target(cfg, target)
        # every new count present
        for k in ("takeovers", "dns_issues", "tls_issues", "web_issues", "content_issues", "active_xss"):
            assert k in summary
        assert summary["findings"], "findings should be derived"
        # report renders with the attack-surface section and correlated insights
        md = build_report(cfg, target, summary)
        text = md.read_text()
        assert "Attack surface" in text
        assert "Correlated insights" in text
        # the html + json siblings exist
        assert md.with_suffix(".html").exists() or list(md.parent.glob("*_report.html"))

    def test_store_all_types_roundtrip(self, tmp_path):
        b1 = {"takeovers": [], "dns_issues": [{"type": "missing_spf", "domain": "ex.com"}],
              "tls_issues": [{"host": "a.ex.com", "self_signed": True}]}
        b2 = {"content_issues": [{"url": "https://a.ex.com/.env", "kind": "exposed_config"}]}
        fs = derive_findings({"type": "domain", "value": "ex.com"}, b1, b2, {}, {}, {"new": []})
        st = FindingStore.for_target(tmp_path, "ex.com")
        cur, new = st.record(fs, "run_1")
        assert len(new) == len(fs)
        # reload -> zero new
        st2 = FindingStore.for_target(tmp_path, "ex.com")
        _, new2 = st2.record(fs, "run_2")
        assert new2 == []


class TestReportRobustness:
    """Round 3: report must not be injectable or crash on hostile finding text."""

    def _summary(self, findings):
        return {"target": "ex.com", "run_dir": "", "subdomains": 1, "live": 0,
                "endpoints": 0, "js_secrets": 0, "open_db": 0, "buckets": 0,
                "new_subdomains": 0, "exposed_git": 0, "secrets": 0, "takeovers": 0,
                "web_issues": 0, "active_xss": 0, "dns_issues": 0, "tls_issues": 0,
                "content_issues": 0, "new_findings": 0,
                "findings": [f.to_dict() for f in findings]}

    def test_html_report_escapes_injection(self, tmp_path, monkeypatch):
        import penguin.config as C
        from penguin.pipelines.report import build_report
        monkeypatch.setattr(C, "ROOT", tmp_path)
        cfg = C.Config()
        evil = '<script>alert(1)</script>'
        f = Finding("xss", "high", "ex.com", evil, url=f"https://a.ex.com/?x={evil}",
                    evidence=evil)
        md = build_report(cfg, {"type": "domain", "value": "ex.com"}, self._summary([f]))
        htmls = list(md.parent.glob("*_report.html"))
        assert htmls
        html = htmls[0].read_text()
        # raw <script> must never appear unescaped; the escaped form must
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_report_huge_findings(self, tmp_path, monkeypatch):
        import time

        import penguin.config as C
        from penguin.pipelines.report import build_report
        monkeypatch.setattr(C, "ROOT", tmp_path)
        cfg = C.Config()
        fs = [Finding("missing_security_headers", "low", "ex.com",
                      f"https://h{i%2000}.ex.com/{i}", url=f"https://h{i%2000}.ex.com/{i}")
              for i in range(30000)]
        t0 = time.time()
        md = build_report(cfg, {"type": "domain", "value": "ex.com"}, self._summary(fs))
        assert md.exists()
        assert time.time() - t0 < 20  # must render a big finding set in reasonable time

    def test_report_weird_chars_no_crash(self, tmp_path, monkeypatch):
        import penguin.config as C
        from penguin.pipelines.report import build_report
        monkeypatch.setattr(C, "ROOT", tmp_path)
        cfg = C.Config()
        weird = ["|pipe", "back`tick", "new\nline", "uni☃code", "a"*5000, ""]
        fs = [Finding("info_disclosure", "medium", "ex.com", w or "x", url=w) for w in weird]
        md = build_report(cfg, {"type": "domain", "value": "ex.com"}, self._summary(fs))
        assert md.exists()


class TestAnalysisInvariants:
    """Round 4: metamorphic/invariant properties that catch subtle scoring bugs."""

    def _mk(self, n, seed=0):
        import random
        r = random.Random(seed)
        sev = ["critical", "high", "medium", "low", "info"]
        types = ["exposed_git", "secret", "js_secret", "open_database", "cors_misconfig",
                 "missing_security_headers", "new_subdomain", "xss", "zone_transfer"]
        return [Finding(r.choice(types), r.choice(sev), "ex.com",
                        f"h{r.randint(0,50)}.ex.com", url=f"https://h{r.randint(0,50)}.ex.com/{i}")
                for i in range(n)]

    def test_adding_finding_never_lowers_overall(self):
        fs = self._mk(200, seed=1)
        base = A.score(fs)["overall"]
        fs.append(Finding("exposed_git", "critical", "ex.com", "z.ex.com", url="https://z.ex.com"))
        assert A.score(fs)["overall"] >= base

    def test_per_host_scores_sum_to_overall(self):
        fs = self._mk(500, seed=2)
        s = A.score(fs)
        assert sum(h["score"] for h in s["by_host"].values()) == s["overall"]

    def test_per_host_counts_sum_to_total(self):
        fs = self._mk(500, seed=3)
        s = A.score(fs)
        assert sum(h["count"] for h in s["by_host"].values()) == len(fs)

    def test_correlate_is_deterministic(self):
        fs = self._mk(300, seed=4)
        assert [i.to_dict() for i in A.correlate(fs)] == [i.to_dict() for i in A.correlate(fs)]

    def test_rank_hosts_is_sorted_desc(self):
        fs = self._mk(400, seed=5)
        ranked = A.rank_hosts(A.score(fs), limit=100)
        scores = [hb["score"] for _, hb in ranked]
        assert scores == sorted(scores, reverse=True)

    def test_risk_band_monotonic(self):
        bands = ["clean", "low", "elevated", "high", "critical"]
        vals = [A.risk_band(v) for v in (0, 10, 50, 120, 500)]
        assert [bands.index(b) for b in vals] == sorted(bands.index(b) for b in vals)
