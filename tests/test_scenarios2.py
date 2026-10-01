"""15 realistic *application* scenarios (distinct from the vector-type scenarios
in test_scenarios.py). Each models how penguin is actually used — a bug-bounty
sweep, an internal pentest, continuous monitoring, M&A due diligence, etc. —
and drives the full run_target -> findings -> analysis -> report chain, asserting
the outcome a user of that workflow would rely on.
"""
import json
from pathlib import Path

import pytest

from penguin import analysis as A
from penguin.findings import Finding, FindingStore, derive_findings

# ---- shared helpers --------------------------------------------------------

def _blocks(b1=None, b2=None, b3=None, b4=None):
    base1 = {"subdomains": [], "resolved": [], "live": [], "takeovers": [],
             "dns_issues": [], "tls_issues": []}
    base2 = {"endpoints": [], "js_secrets": [], "api": [], "web_issues": [],
             "active": [], "content_issues": []}
    base3 = {"open_db": [], "buckets": []}
    base4 = {"origin_ips": [], "exposed_git": [], "secrets": []}
    base1.update(b1 or {})
    base2.update(b2 or {})
    base3.update(b3 or {})
    base4.update(b4 or {})
    return base1, base2, base3, base4


@pytest.fixture
def harness(tmp_path, monkeypatch):
    """Returns a function run(target, b1..b4) -> (summary, report_text)."""
    import penguin.config as C
    import penguin.pipelines.master as m
    from penguin.pipelines.report import build_report
    monkeypatch.setattr(C, "ROOT", tmp_path)

    def _run(target, b1=None, b2=None, b3=None, b4=None, active=False):
        cfg = C.Config()
        cfg.proxies.enabled = False
        cfg.general.active = active
        cfg.general.output_dir = str(tmp_path / "results")
        cfg.general.wordlists_dir = str(tmp_path / "wl")
        bb = _blocks(b1, b2, b3, b4)
        monkeypatch.setattr(m, "_BLOCKS", [
            (1, "infra", lambda *a, **k: bb[0]),
            (2, "web", lambda *a, **k: bb[1]),
            (3, "cloud_db", lambda *a, **k: bb[2]),
            (4, "elite", lambda *a, **k: bb[3]),
        ])
        summary = m.run_target(cfg, target)
        md = build_report(cfg, target, summary)
        return summary, md.read_text()

    return _run


def _analyze(b1=None, b2=None, b3=None, b4=None, diff=None, target="acme.com"):
    bb = _blocks(b1, b2, b3, b4)
    fs = derive_findings({"type": "domain", "value": target}, *bb, diff or {"new": []})
    return fs, A.analyze(fs)


def _titles(a):
    return {i["title"] for i in a["insights"]}


# 1 - Bug-bounty first-pass recon of a SaaS: lots of subdomains, one real bug ---
def test_app_01_bugbounty_saas_first_pass(harness):
    summary, report = harness(
        {"type": "domain", "value": "saas.io"},
        b1={"subdomains": [f"s{i}.saas.io" for i in range(40)],
            "takeovers": ["old-blog.saas.io"]},
        b2={"web_issues": [{"url": "https://app.saas.io", "missing": ["content-security-policy"]}]},
    )
    assert summary["takeovers"] == 1
    assert "Attack surface" in report
    # the takeover should be the headline critical insight
    assert "Hijackable subdomain" in report


# 2 - Internal pentest: open databases + exposed .git on the intranet ---------
def test_app_02_internal_pentest_lateral(harness):
    summary, report = harness(
        {"type": "cidr", "value": "10.0.0.0/24"},
        b3={"open_db": ["10.0.0.5:6379", "10.0.0.6:27017"]},
        b4={"exposed_git": ["http://wiki.corp.local/.git/"], "secrets": ["/dump/wiki/creds.txt"]},
    )
    assert summary["open_db"] == 2 and summary["exposed_git"] == 1
    assert "CRITICAL" in report


# 3 - Continuous monitoring: run twice, only the delta should be "new" --------
def test_app_03_continuous_monitoring_delta(tmp_path):
    store = FindingStore.for_target(tmp_path, "watch.com")
    b = _blocks(b3={"open_db": ["1.2.3.4:9200"]})
    fs1 = derive_findings({"type": "domain", "value": "watch.com"}, *b, {"new": []})
    _, new1 = store.record(fs1, "r1")
    assert len(new1) == 1
    # next day: same DB still open + a brand-new takeover appears
    b2 = _blocks(b1={"takeovers": ["gone.watch.com"]}, b3={"open_db": ["1.2.3.4:9200"]})
    fs2 = derive_findings({"type": "domain", "value": "watch.com"}, *b2, {"new": []})
    _, new2 = FindingStore.for_target(tmp_path, "watch.com").record(fs2, "r2")
    assert {f.type for f in new2} == {"subdomain_takeover"}


# 4 - M&A due diligence: posture scoring of an acquisition target ------------
def test_app_04_ma_due_diligence_posture():
    # mixed low/medium posture issues, no criticals -> "elevated/high", not critical
    _, a = _analyze(
        b1={"dns_issues": [{"type": "missing_spf", "domain": "target.co"},
                           {"type": "missing_dmarc", "domain": "target.co"}],
            "tls_issues": [{"host": "www.target.co", "expiring_soon": True, "days_left": 7}]},
        b2={"web_issues": [{"url": "https://www.target.co", "missing": ["content-security-policy",
                            "strict-transport-security", "x-frame-options"]}]},
        target="target.co",
    )
    assert a["risk_band"] in ("elevated", "high")
    assert "Email domain spoofable" in _titles(a)


# 5 - Red team of a bank: critical breach chain must dominate ranking ---------
def test_app_05_redteam_bank_breach_chain():
    fs, a = _analyze(
        b2={"content_issues": [{"url": "https://portal.bank.com/.env", "kind": "exposed_config"}]},
        b4={"exposed_git": ["https://portal.bank.com/.git/"]},
        target="bank.com",
    )
    fs.append(Finding("js_secret", "high", "bank.com", "db_pw", url="https://portal.bank.com/a.js"))
    a = A.analyze(fs)
    assert a["risk_band"] == "critical"
    assert a["top_hosts"][0]["host"] == "portal.bank.com"
    assert {"Source exposure with leaked secrets", "Exposed config leaking credentials"} & _titles(a)


# 6 - E-commerce: public buckets with customer data + CORS on the API --------
def test_app_06_ecommerce_data_exposure():
    fs, a = _analyze(
        b2={"web_issues": [{"url": "https://api.shop.com", "cors_bad": True, "cors_credentials": True,
                            "missing": []}]},
        b3={"buckets": ["s3://shop-customer-invoices", "s3://shop-order-exports"]},
        target="shop.com",
    )
    fs.append(Finding("js_secret", "high", "shop.com", "stripe_key", url="https://api.shop.com/x.js"))
    a = A.analyze(fs)
    assert "CORS + client-side secrets = token theft" in _titles(a)
    assert len([f for f in fs if f.type == "public_bucket"]) == 2


# 7 - Healthcare posture audit: everything medium/low, strong on criticals ---
def test_app_07_healthcare_posture_audit(harness):
    summary, report = harness(
        {"type": "domain", "value": "clinic.health"},
        b1={"tls_issues": [{"host": "portal.clinic.health", "self_signed": True}],
            "dns_issues": [{"type": "dnssec_missing", "domain": "clinic.health"}]},
        b2={"content_issues": [{"url": "https://portal.clinic.health/server-status",
                                "kind": "info_disclosure"}]},
    )
    assert summary["tls_issues"] == 1 and summary["content_issues"] == 1
    assert "Attack surface" in report


# 8 - Cloud-native k8s cluster: exposed actuator/management endpoints --------
def test_app_08_cloudnative_actuator_exposure():
    fs, a = _analyze(
        b2={"content_issues": [{"url": "https://svc.k8s.io/actuator/env", "kind": "exposed_config"},
                               {"url": "https://svc.k8s.io/actuator", "kind": "info_disclosure"}]},
        b3={"open_db": ["10.1.2.3:2379"]},  # etcd exposed
        target="k8s.io",
    )
    assert len([f for f in fs if f.type == "exposed_config"]) == 1
    assert "Exposed data store" in _titles(a)


# 9 - API-first company: GraphQL + swagger surface, no criticals -------------
def test_app_09_api_first_surface(harness):
    summary, report = harness(
        {"type": "url", "value": "https://api.dev.io"},
        b2={"api": ["swagger.json", "graphql"], "endpoints": ["/v1/users", "/v1/orders"],
            "web_issues": [{"url": "https://api.dev.io", "missing": ["x-content-type-options"]}]},
    )
    assert summary["endpoints"] == 2
    assert "Attack surface" in report


# 10 - Government site: DNS zone transfer leak (classic) ---------------------
def test_app_10_gov_zone_transfer():
    fs, a = _analyze(
        b1={"dns_issues": [{"type": "zone_transfer", "domain": "agency.gov", "ns": "ns1.agency.gov"}]},
        target="agency.gov",
    )
    assert a["risk_band"] == "critical"
    assert "DNS zone transfer allowed" in _titles(a)


# 11 - Startup MVP: fast-and-loose, exposed .env with everything -------------
def test_app_11_startup_mvp_env_leak(harness):
    summary, report = harness(
        {"type": "domain", "value": "mvp.app"},
        b2={"content_issues": [{"url": "https://mvp.app/.env", "kind": "exposed_config"}],
            "js_secrets": ["sk_live_abc"]},
    )
    assert summary["content_issues"] == 1 and summary["secrets"] == 1
    assert "CRITICAL" in report  # exposed config is high; may or may not chain


# 12 - CDN-fronted app: origin IP discovery bypasses the WAF -----------------
def test_app_12_cdn_origin_bypass():
    fs, a = _analyze(
        b4={"origin_ips": ["203.0.113.10", "203.0.113.11"]},
        target="fronted.com",
    )
    assert len([f for f in fs if f.type == "origin_ip"]) == 2
    assert a["overall"] > 0


# 13 - Incident triage: given a findings.jsonl, rank what to fix first -------
def test_app_13_incident_triage_ranking(tmp_path):
    store = FindingStore.for_target(tmp_path, "inc.com")
    mixed = [
        Finding("missing_security_headers", "low", "inc.com", "https://a.inc.com", url="https://a.inc.com"),
        Finding("open_database", "high", "inc.com", "9.9.9.9:6379", url=""),
        Finding("exposed_git", "critical", "inc.com", "https://a.inc.com/.git/", url="https://a.inc.com/.git/"),
    ]
    store.record(mixed, "r1")
    reloaded = FindingStore.for_target(tmp_path, "inc.com")
    # re-derive analysis from the persisted store
    a = A.analyze(list(reloaded._by_key.values()))
    # critical host must rank first
    assert a["top_hosts"][0]["top_severity"] == "critical"


# 14 - Large enterprise: thousands of assets, ranking stays bounded/useful ---
def test_app_14_enterprise_scale(harness):
    summary, report = harness(
        {"type": "org", "value": "BigCorp"},
        b1={"subdomains": [f"h{i}.bigcorp.com" for i in range(3000)],
            "takeovers": ["legacy.bigcorp.com"]},
        b3={"open_db": [f"10.{i}.0.1:6379" for i in range(20)]},
    )
    assert summary["subdomains"] == 3000
    assert summary["open_db"] == 20
    assert "Attack surface" in report


# 15 - Clean, well-run target: scanner should NOT cry wolf ------------------
def test_app_15_clean_target_no_false_alarm(harness):
    summary, report = harness(
        {"type": "domain", "value": "secure.io"},
        b1={"subdomains": ["www.secure.io"], "resolved": ["www.secure.io"],
            "dns_issues": [], "tls_issues": []},
        b2={"endpoints": ["/"], "web_issues": []},
    )
    assert summary["secrets"] == 0 and summary["takeovers"] == 0
    # No critical/high findings -> the scanner must not cry wolf. (On a first
    # run every subdomain is "new", so an info-level new_subdomain finding is
    # expected; it must not escalate the posture.)
    crit_high = [f for f in summary["findings"] if f["severity"] in ("critical", "high")]
    assert crit_high == []
    a = A.analyze([Finding.from_dict(f) for f in summary["findings"]])
    assert a["risk_band"] in ("clean", "low")
    # manifest exists and records a clean run
    rd = Path(summary["run_dir"])
    manifest = json.loads((rd / "_manifest.json").read_text())
    assert manifest["summary"]["subdomains"] == 1
