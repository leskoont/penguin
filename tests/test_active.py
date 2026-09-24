"""Tests for penguin.tools.active - dalfox parsing + argv + gating."""
import json

from penguin.config import Config
from penguin.runner import RunResult
from penguin.tools import active as av
from penguin.tools._base import ToolContext


def test_active_off_by_default():
    assert Config().general.active is False


def test_parse_dalfox_dedups_and_skips_nondict(tmp_path):
    out = tmp_path / "d.jsonl"
    out.write_text(
        json.dumps({"data": "https://x.com/?q=1"}) + "\n"
        + "garbage\n"
        + json.dumps([1, 2]) + "\n"                       # non-dict -> skipped
        + json.dumps({"url": "https://y.com/?a=2"}) + "\n"
        + json.dumps({"data": "https://x.com/?q=1"}) + "\n",  # dup
        encoding="utf-8",
    )
    assert av.parse_dalfox(out) == ["https://x.com/?q=1", "https://y.com/?a=2"]


def test_parse_dalfox_missing_file(tmp_path):
    assert av.parse_dalfox(tmp_path / "nope.jsonl") == []


def test_dalfox_argv(tmp_path, monkeypatch):
    ctx = ToolContext(Config())
    seen = {}

    def fake(tool, cmd, **kw):
        seen["tool"] = tool
        seen["cmd"] = cmd
        (tmp_path / "o.jsonl").write_text("", encoding="utf-8")
        return RunResult(cmd, 0, "", "", 1, 1.0, True)

    monkeypatch.setattr(ctx, "execute", fake)
    av.dalfox_file(ctx, tmp_path / "urls.txt", tmp_path / "o.jsonl")
    assert seen["tool"] == "dalfox"
    assert seen["cmd"][0] == "dalfox" and "file" in seen["cmd"]
    assert "jsonl" in seen["cmd"]


def test_nuclei_fuzz_argv(tmp_path, monkeypatch):
    ctx = ToolContext(Config())
    seen = {}

    def fake(tool, cmd, **kw):
        seen["cmd"] = cmd
        (tmp_path / "o.jsonl").write_text("", encoding="utf-8")
        return RunResult(cmd, 0, "", "", 1, 1.0, True)

    monkeypatch.setattr(ctx, "execute", fake)
    av.nuclei_fuzz(ctx, tmp_path / "hosts.txt", tmp_path / "o.jsonl")
    assert "-dast" in seen["cmd"]
