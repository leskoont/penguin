"""15 full-weight, distinct recon scenarios exercised end-to-end through the
findings -> correlation -> scoring -> (report) chain. Each scenario models a
different real-world target profile and asserts the *intelligence* the pipeline
should produce, not merely that it doesn't crash.
"""
from penguin import analysis as A
from penguin.findings import FindingStore, derive_findings

TARGET = {"type": "domain", "value": "acme.com"}


def _b1(**kw):
    d = {"subdomains": [], "resolved": [], "live": [], "takeovers": [],
         "dns_issues": [], "tls_issues": []}
    d.update(kw)
    return d


def _b2(**kw):
    d = {"endpoints": [], "js_secrets": [], "api": [], "web_issues": [],
         "active": [], "content_issues": []}
    d.update(kw)
    return d


def _b3(**kw):
    d = {"open_db": [], "buckets": []}
    d.update(kw)
    return d


def _b4(**kw):
    d = {"origin_ips": [], "exposed_git": [], "secrets": []}
    d.update(kw)
    return d


def run(b1=None, b2=None, b3=None, b4=None, diff=None):
    fs = derive_findings(TARGET, b1 or _b1(), b2 or _b2(), b3 or _b3(), b4 or _b4(),
                         diff or {"new": []})
    return fs, A.analyze(fs)


def _titles(a):
    return {i["title"] for i in a["insights"]}


# 1 --------------------------------------------------------------------------
def test_scenario_01_clean_target():
    """Nothing found: clean risk band, no findings, no insights."""
    fs, a = run()
    assert fs == []
    assert a["overall"] == 0 and a["risk_band"] == "clean"
    assert a["insights"] == [] and a["top_hosts"] == []


# 2 --------------------------------------------------------------------------
def test_scenario_02_source_to_secret_breach_chain():
    """Exposed .git + a client-side secret on the same host = critical chain."""
    b4 = _b4(exposed_git=["http://app.acme.com/.git/"])
    b2 = _b2(js_secrets=[])  # js_secrets carry no host; use content/url-bearing secret
    from penguin.findings import Finding
    fs = derive_findings(TARGET, _b1(), b2, _b3(), b4, {"new": []})
    fs.append(Finding("js_secret", "high", "acme.com", "AKIA", url="https://app.acme.com/a.js"))
    a = A.analyze(fs)
    assert a["risk_band"] in ("high", "critical")
    assert "Source exposure with leaked secrets" in _titles(a)


# 3 --------------------------------------------------------------------------
def test_scenario_03_subdomain_takeover_farm():
    """Many dangling subdomains -> multiple critical takeover findings + insights."""
    takeovers = [f"dead{i}.acme.com" for i in range(8)]
    fs, a = run(b1=_b1(takeovers=takeovers))
    tk = [f for f in fs if f.type == "subdomain_takeover"]
    assert len(tk) == 8 and all(f.severity == "critical" for f in tk)
    assert "Hijackable subdomain" in _titles(a)
    assert a["risk_band"] == "critical"


# 4 --------------------------------------------------------------------------
def test_scenario_04_open_database_sprawl():
    """Multiple exposed datastores across hosts."""
    b3 = _b3(open_db=["10.0.0.1:6379", "10.0.0.2:27017", "10.0.0.3:9200", "10.0.0.4:5432"])
    fs, a = run(b3=b3)
    assert len([f for f in fs if f.type == "open_database"]) == 4
    assert "Exposed data store" in _titles(a)
    # 4 distinct hosts should appear in ranking
    assert len(a["top_hosts"]) >= 4


# 5 --------------------------------------------------------------------------
def test_scenario_05_email_spoofable_domain():
    """No SPF and no DMARC -> email-spoofing insight."""
    b1 = _b1(dns_issues=[{"type": "missing_spf", "domain": "acme.com"},
                         {"type": "missing_dmarc", "domain": "acme.com"},
                         {"type": "dnssec_missing", "domain": "acme.com"}])
    fs, a = run(b1=b1)
    assert "Email domain spoofable" in _titles(a)
    assert {f.type for f in fs} == {"missing_spf", "missing_dmarc", "dnssec_missing"}


# 6 --------------------------------------------------------------------------
def test_scenario_06_zone_transfer_leak():
    """AXFR allowed -> critical DNS insight."""
    b1 = _b1(dns_issues=[{"type": "zone_transfer", "domain": "acme.com", "ns": "ns1.acme.com"}])
    fs, a = run(b1=b1)
    assert any(f.type == "zone_transfer" and f.severity == "critical" for f in fs)
    assert "DNS zone transfer allowed" in _titles(a)


# 7 --------------------------------------------------------------------------
def test_scenario_07_broken_tls_estate():
    """Expired + self-signed certs across the estate."""
    b1 = _b1(tls_issues=[
        {"host": "a.acme.com", "expired": True, "days_left": -30},
        {"host": "b.acme.com", "self_signed": True},
        {"host": "c.acme.com", "expiring_soon": True, "days_left": 3},
    ])
    fs, a = run(b1=b1)
    types = {f.type for f in fs}
    assert {"tls_expired", "tls_self_signed", "tls_expiring_soon"} <= types


# 8 --------------------------------------------------------------------------
def test_scenario_08_cors_plus_client_secrets():
    """Reflect-any CORS next to client-side secrets = token-theft insight."""
    b2 = _b2(web_issues=[{"url": "https://api.acme.com", "cors_bad": True,
                          "cors_credentials": True, "missing": []}],
             js_secrets=[])
    from penguin.findings import Finding
    fs = derive_findings(TARGET, _b1(), b2, _b3(), _b4(), {"new": []})
    fs.append(Finding("js_secret", "high", "acme.com", "token", url="https://api.acme.com/app.js"))
    a = A.analyze(fs)
    assert "CORS + client-side secrets = token theft" in _titles(a)


# 9 --------------------------------------------------------------------------
def test_scenario_09_exposed_config_estate():
    """.env / actuator exposures + a secret => config-leak chain."""
    b2 = _b2(content_issues=[
        {"url": "https://app.acme.com/.env", "kind": "exposed_config"},
        {"url": "https://app.acme.com/actuator/env", "kind": "exposed_config"},
    ], js_secrets=["sk_live_xxx"])
    from penguin.findings import Finding
    fs = derive_findings(TARGET, _b1(), b2, _b3(), _b4(), {"new": []})
    fs.append(Finding("js_secret", "high", "acme.com", "sk", url="https://app.acme.com/x.js"))
    a = A.analyze(fs)
    assert "Exposed config leaking credentials" in _titles(a)
    assert len([f for f in fs if f.type == "exposed_config"]) == 2


# 10 -------------------------------------------------------------------------
def test_scenario_10_info_disclosure_and_listings():
    """Directory listings + info disclosure, no critical -> elevated/high band."""
    b2 = _b2(content_issues=[
        {"url": "https://acme.com/uploads/", "kind": "directory_listing"},
        {"url": "https://acme.com/backup/", "kind": "directory_listing"},
        {"url": "https://acme.com/server-status", "kind": "info_disclosure"},
        {"url": "https://acme.com/phpinfo.php", "kind": "info_disclosure"},
    ])
    fs, a = run(b2=b2)
    assert len(fs) == 4
    assert all(f.severity == "medium" for f in fs)
    assert a["risk_band"] in ("elevated", "high")


# 11 -------------------------------------------------------------------------
def test_scenario_11_active_xss_campaign():
    """Active-mode XSS hits become high findings."""
    b2 = _b2(active=[f"https://acme.com/s?q={i}" for i in range(5)])
    fs, a = run(b2=b2)
    xss = [f for f in fs if f.type == "xss"]
    assert len(xss) == 5 and all(f.severity == "high" for f in xss)


# 12 -------------------------------------------------------------------------
def test_scenario_12_public_bucket_exposure():
    b3 = _b3(buckets=["s3://acme-backups", "s3://acme-logs", "gs://acme-media"])
    fs, a = run(b3=b3)
    assert len([f for f in fs if f.type == "public_bucket"]) == 3
    assert a["risk_band"] in ("elevated", "high")


# 13 -------------------------------------------------------------------------
def test_scenario_13_massive_attack_surface():
    """Thousands of assets: ranking + scoring stay correct and bounded."""
    new = [f"h{i}.acme.com" for i in range(5000)]
    b3 = _b3(open_db=[f"10.0.{i//255}.{i%255}:6379" for i in range(50)])
    fs, a = run(b1=_b1(), b3=b3, diff={"new": new})
    assert len(fs) == 5050
    assert len(a["top_hosts"]) == 10  # default top cap
    # open-db hosts (high) must outrank new-subdomain hosts (info)
    assert a["top_hosts"][0]["top_severity"] == "high"


# 14 -------------------------------------------------------------------------
def test_scenario_14_degraded_partial_run(tmp_path, monkeypatch):
    """Two blocks crash; the run still yields coherent analysis over what ran."""
    import penguin.config as C
    import penguin.pipelines.master as m
    monkeypatch.setattr(C, "ROOT", tmp_path)
    cfg = C.Config()
    cfg.proxies.enabled = False
    cfg.general.output_dir = str(tmp_path / "results")
    cfg.general.wordlists_dir = str(tmp_path / "wl")

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(m, "_BLOCKS", [
        (1, "infra", lambda *a, **k: _b1(takeovers=["gone.acme.com"])),
        (2, "web", boom),
        (3, "cloud_db", lambda *a, **k: _b3(open_db=["10.0.0.9:6379"])),
        (4, "elite", boom),
    ])
    summary = m.run_target(cfg, TARGET)
    assert summary["takeovers"] == 1
    assert summary["open_db"] == 1
    # findings still derived from the blocks that ran
    types = {f["type"] for f in summary["findings"]}
    assert "subdomain_takeover" in types and "open_database" in types


# 15 -------------------------------------------------------------------------
def test_scenario_15_cross_run_delta(tmp_path):
    """Two runs: the second run flags only genuinely new findings."""
    store = FindingStore.for_target(tmp_path, "acme.com")
    # run 1
    fs1 = derive_findings(TARGET, _b1(takeovers=["a.acme.com"]),
                          _b2(js_secrets=["k1"]), _b3(), _b4(), {"new": ["x.acme.com"]})
    cur1, new1 = store.record(fs1, "run_1")
    assert len(new1) == len(fs1)
    # run 2: same takeover+secret, plus one NEW open db
    store2 = FindingStore.for_target(tmp_path, "acme.com")
    fs2 = derive_findings(TARGET, _b1(takeovers=["a.acme.com"]),
                          _b2(js_secrets=["k1"]), _b3(open_db=["10.0.0.1:6379"]), _b4(),
                          {"new": []})
    cur2, new2 = store2.record(fs2, "run_2")
    new_types = {f.type for f in new2}
    assert new_types == {"open_database"}
    # the carried-over takeover keeps its original first_seen_run
    tk = [f for f in cur2 if f.type == "subdomain_takeover"][0]
    assert tk.first_seen_run == "run_1"
