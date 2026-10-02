"""Tests for penguin.tools.takeover - argv + JSONL parsing."""
import json

from penguin.config import Config
from penguin.runner import RunResult
from penguin.tools import takeover as tk
from penguin.tools._base import ToolContext


def test_parse_nuclei_takeovers_extracts_hosts(tmp_path):
    out = tmp_path / "takeovers.jsonl"
    out.write_text(
        json.dumps({"host": "gone.ex.com", "template-id": "github-takeover"}) + "\n"
        + json.dumps({"matched-at": "dead.ex.com", "template-id": "heroku"}) + "\n"
        + json.dumps({"host": "gone.ex.com"}) + "\n"        # duplicate -> deduped
        + "NOT JSON\n",                                      # malformed -> skipped
        encoding="utf-8",
    )
    assert tk.parse_nuclei_takeovers(out) == ["gone.ex.com", "dead.ex.com"]


def test_parse_missing_file_returns_empty(tmp_path):
    assert tk.parse_nuclei_takeovers(tmp_path / "nope.jsonl") == []


def test_nuclei_takeover_builds_correct_argv(tmp_path, monkeypatch):
    cfg = Config()
    ctx = ToolContext(cfg)
    seen = {}

    def fake_execute(tool, cmd, **kw):
        seen["tool"] = tool
        seen["cmd"] = cmd
        (tmp_path / "out.jsonl").write_text("", encoding="utf-8")
        return RunResult(cmd, 0, "", "", 1, 1.0, True)

    monkeypatch.setattr(ctx, "execute", fake_execute)
    tk.nuclei_takeover(ctx, tmp_path / "hosts.txt", tmp_path / "out.jsonl")
    assert seen["tool"] == "nuclei"
    assert "-t" in seen["cmd"]
    assert "http/takeovers/" in seen["cmd"]
    assert "-jsonl" in seen["cmd"]


def test_subzy_takeover_builds_correct_argv(tmp_path, monkeypatch):
    ctx = ToolContext(Config())
    seen = {}

    def fake_execute(tool, cmd, **kw):
        seen["tool"] = tool
        seen["cmd"] = cmd
        (tmp_path / "out.txt").write_text("", encoding="utf-8")
        return RunResult(cmd, 0, "", "", 1, 1.0, True)

    monkeypatch.setattr(ctx, "execute", fake_execute)
    tk.subzy_takeover(ctx, tmp_path / "hosts.txt", tmp_path / "out.txt")
    assert seen["tool"] == "subzy"
    assert "--targets" in seen["cmd"]


def test_parse_subzy_json_array(tmp_path):
    out = tmp_path / "subzy.json"
    out.write_text(json.dumps([
        {"Subdomain": "gone.ex.com", "Status": "VULNERABLE", "Engine": "GitHub"},
        {"Subdomain": "safe.ex.com", "Status": "NOT VULNERABLE"},   # excluded
        {"subdomain": "gone.ex.com", "status": "vulnerable"},        # dup (case-insens)
        {"subdomain": "two.ex.com", "status": "VULNERABLE"},
        "garbage-not-a-dict",
    ]), encoding="utf-8")
    assert tk.parse_subzy(out) == ["gone.ex.com", "two.ex.com"]


def test_parse_subzy_plain_text(tmp_path):
    out = tmp_path / "subzy.txt"
    out.write_text(
        "[ VULNERABLE ] https://gone.ex.com (Engine: GitHub)\n"
        "[ NOT VULNERABLE ] https://safe.ex.com\n"
        "[ VULNERABLE ] dead.ex.com\n"
        "random noise line\n",
        encoding="utf-8",
    )
    assert tk.parse_subzy(out) == ["https://gone.ex.com", "dead.ex.com"]


def test_parse_subzy_missing_and_malformed(tmp_path):
    assert tk.parse_subzy(tmp_path / "nope.json") == []
    bad = tmp_path / "bad.json"
    bad.write_text("[ this is not json", encoding="utf-8")   # looks like JSON, isn't
    assert tk.parse_subzy(bad) == []
