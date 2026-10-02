"""Tests for penguin.tools.secrets hit-counters.

gitleaks and trufflehog ALWAYS write a report file (empty when clean), so block4
must count actual hits, not the file's existence -- otherwise every dumped .git
repo raises a false critical "secret" finding. These lock that contract in.
"""
from penguin.tools import secrets as sc


def test_gitleaks_hits_counts_array(tmp_path):
    rep = tmp_path / "gl.json"
    rep.write_text('[{"RuleID":"aws","Secret":"AKIA..."},{"RuleID":"gh"}]', encoding="utf-8")
    assert sc.gitleaks_hits(rep) == 2


def test_gitleaks_hits_empty_is_zero(tmp_path):
    rep = tmp_path / "gl.json"
    rep.write_text("[]", encoding="utf-8")       # the clean-run output
    assert sc.gitleaks_hits(rep) == 0


def test_gitleaks_hits_missing_or_malformed(tmp_path):
    assert sc.gitleaks_hits(tmp_path / "nope.json") == 0
    bad = tmp_path / "bad.json"
    bad.write_text("not json at all", encoding="utf-8")
    assert sc.gitleaks_hits(bad) == 0
    obj = tmp_path / "obj.json"
    obj.write_text('{"not":"a list"}', encoding="utf-8")
    assert sc.gitleaks_hits(obj) == 0


def test_trufflehog_hits_counts_jsonl(tmp_path):
    rep = tmp_path / "th.json"
    rep.write_text(
        '{"DetectorName":"AWS","Verified":true}\n'
        '\n'                                           # blank line ignored
        '{"DetectorName":"GitHub","Verified":true}\n'
        'garbage-non-json\n'                           # skipped
        '[1,2,3]\n',                                   # non-dict skipped
        encoding="utf-8",
    )
    assert sc.trufflehog_hits(rep) == 2


def test_trufflehog_hits_empty_is_zero(tmp_path):
    rep = tmp_path / "th.json"
    rep.write_text("", encoding="utf-8")             # the clean-run output
    assert sc.trufflehog_hits(rep) == 0
    assert sc.trufflehog_hits(tmp_path / "nope.json") == 0
