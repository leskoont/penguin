"""Security-hardening regression tests.

Each test pins one concrete vector found in the 2026-10-25 audit: CWD-relative
code execution, path traversal from remote JSON via Windows backslashes,
console-markup injection from scan output, argv leakage of URL credentials,
s3scanner path-as-finding false positives, and the dead/mismatched wrappers
(jsluice glob, cloudflair)."""
from __future__ import annotations

import pytest
from rich.console import Console

from penguin.config import Config
from penguin.runner import RunResult, run
from penguin.tools import cloud, content, probe, secrets
from penguin.ui.tables import risk_hosts_table, summary_table


class FakeCtx:
    """Captures execute() calls without running anything."""

    def __init__(self, cfg=None):
        self.cfg = cfg or Config()
        self.calls: list[tuple] = []

    def execute(self, tool, cmd, **kw):
        self.calls.append((tool, list(cmd), kw))
        return RunResult(list(cmd), 0, "ok", "", 1, 0.0, True)


# ---- deep-tier SLIRP safety ------------------------------------------------

class TestAltPortTargets:
    def test_pairs_with_port_stripping(self):
        out = probe.alt_port_targets(["https://a.ex.com", "b.ex.com:8443"], "8080,8443")
        assert out == ["a.ex.com:8080", "a.ex.com:8443",
                       "b.ex.com:8080", "b.ex.com:8443"]

    def test_total_cap_enforced(self):
        hosts = [f"h{i}.ex.com" for i in range(100)]
        out = probe.alt_port_targets(hosts, probe.ALT_WEB_PORTS, max_targets=50)
        assert len(out) == 50
        # every host gets breadth before any host gets depth: first hosts
        # walked first
        assert out[0].startswith("h0.ex.com:")
        assert out[-1].startswith("h4.ex.com:")

    def test_dedup_and_garbage_ports(self):
        out = probe.alt_port_targets(["a.ex.com", "a.ex.com"], "8080, ,abc,8443")
        assert out == ["a.ex.com:8080", "a.ex.com:8443"]

    def test_empty(self):
        assert probe.alt_port_targets([], "8080") == []
        assert probe.alt_port_targets(["a.ex.com"], "") == []


class TestHttpxPorts:
    def test_no_ports_flag_pairs_file_half_threads(self, tmp_path):
        ctx = FakeCtx()
        pairs = tmp_path / "pairs.txt"
        pairs.write_text("a.ex.com:8080\n", encoding="utf-8")
        out = tmp_path / "alt.csv"
        probe.httpx_ports(ctx, pairs, out, threads=7)
        tool, cmd, kw = ctx.calls[0]
        assert cmd[0] == "httpx"
        assert "-ports" not in cmd            # version-dependent flag never used
        assert cmd[cmd.index("-l") + 1] == str(pairs)
        assert cmd[cmd.index("-threads") + 1] == "7"

    def test_default_threads_is_half_budget(self, tmp_path):
        ctx = FakeCtx()
        ctx.cfg.general.threads = 15
        pairs = tmp_path / "pairs.txt"
        pairs.write_text("a.ex.com:8080\n", encoding="utf-8")
        probe.httpx_ports(ctx, pairs, tmp_path / "alt.csv")
        _, cmd, _ = ctx.calls[0]
        assert cmd[cmd.index("-threads") + 1] == "7"


# ---- jsluice: list signature + argv chunking --------------------------------

class TestJsluice:
    def test_takes_file_list_and_chunks(self, tmp_path, monkeypatch):
        ctx = FakeCtx()
        files = []
        for i in range(250):
            f = tmp_path / f"{i}.js"
            f.write_text("//", encoding="utf-8")
            files.append(f)
        out = tmp_path / "jsluice.txt"
        assert secrets.jsluice(ctx, files, out, chunk=100) == out
        assert len(ctx.calls) == 3                      # 250 files / 100 per call
        assert ctx.calls[0][1][:2] == ["jsluice", "urls"]
        assert len(ctx.calls[0][1]) == 102              # binary + subcmd + 100 files
        assert out.read_text(encoding="utf-8") == "ok" * 3

    def test_no_files_is_none(self, tmp_path):
        ctx = FakeCtx()
        assert secrets.jsluice(ctx, [], tmp_path / "x.txt") is None
        missing = tmp_path / "nope.js"
        assert secrets.jsluice(ctx, [missing], tmp_path / "x.txt") is None
        assert ctx.calls == []


# ---- paramspider: cwd isolation ----------------------------------------------

class TestParamspiderCwd:
    def test_runs_in_isolated_cwd_and_relocates(self, tmp_path):
        class Ctx(FakeCtx):
            def execute(self, tool, cmd, **kw):
                self.calls.append((tool, list(cmd), kw))
                cwd = kw.get("cwd")
                if cwd:  # simulate paramspider's hardcoded ./results/<domain>.txt
                    from pathlib import Path as P
                    d = P(cwd) / "results"
                    d.mkdir(parents=True, exist_ok=True)
                    (d / f"{cmd[cmd.index('-d') + 1]}.txt").write_text("x", encoding="utf-8")
                return RunResult(list(cmd), 0, "", "", 1, 0.0, True)

        ctx = Ctx()
        out = tmp_path / "run" / "paramspider_a_ex_com.txt"
        assert content.paramspider(ctx, "a.ex.com", out) == out
        _, cmd, kw = ctx.calls[0]
        assert kw.get("cwd") and kw["cwd"] != str(tmp_path)
        assert not (tmp_path / "results").exists()      # nothing scattered to CWD
        assert out.read_text(encoding="utf-8") == "x"

    def test_no_output_file_is_none(self, tmp_path):
        ctx = FakeCtx()
        out = tmp_path / "paramspider_x.txt"
        assert content.paramspider(ctx, "ex.com", out) is None


# ---- cloudflair removal -------------------------------------------------------

def test_cloudflair_wrapper_gone():
    """The wrapper ran `python3 cloudflair.py` CWD-relative -- a plant-a-file
    code-execution footgun that never worked (nothing installs the script)."""
    import penguin.pipelines.block4_elite as b4
    import penguin.tools.origin as origin
    assert not hasattr(origin, "cloudflair")
    src = open(b4.__file__, encoding="utf-8").read()
    assert "og.cloudflair" not in src          # no call site left either


# ---- s3scanner: names, not paths ----------------------------------------------

class TestParseS3scanner:
    def test_virtual_host_and_uri_forms(self):
        text = ("http://acme-assets.s3.amazonaws.com/status | exists | listed\n"
                "s3://acme-backup opened\n"
                "some prose line without buckets\n")
        assert cloud.parse_s3scanner(text) == ["acme-assets", "acme-backup"]

    def test_never_returns_paths_or_prose(self):
        text = "scan finished, report at C:\\out\\x.txt\n"
        assert cloud.parse_s3scanner(text) == []

    def test_dedup_case_insensitive(self):
        assert cloud.parse_s3scanner("A.ex.s3.amazonaws.com a.ex.s3.amazonaws.com") == ["a.ex"]


# ---- path traversal via filenames from remote data ----------------------------

class TestFilenameSanitization:
    def test_sanitize_slug_kills_windows_backslash_traversal(self):
        from penguin.findings import _sanitize_slug
        slug = _sanitize_slug("..\\..\\evil")
        # traversal requires path separators: with neither / nor \ remaining,
        # the leading dots are an inert filename prefix on every platform
        assert "\\" not in slug
        assert "/" not in slug

    def test_block4_uses_sanitize_for_registry_files(self):
        import penguin.pipelines.block4_elite as b4
        src = open(b4.__file__, encoding="utf-8").read()
        assert "trivy_{_sanitize_slug(repo)}" in src
        assert "catalog_{_sanitize_slug(registry)}" in src


# ---- console markup injection --------------------------------------------------

class TestRichEscape:
    def _render(self, table) -> str:
        c = Console(record=True, width=250, file=open("nul", "w", encoding="utf-8"))
        c.print(table)
        return c.export_text()

    def test_hostile_host_is_not_interpreted_as_markup(self):
        hostile = "evil[red]pwned[/]x"
        text = self._render(risk_hosts_table([{"host": hostile, "score": 10,
                                               "top_severity": "critical", "count": 2}]))
        assert "evil[red]pwned[/]x" in text          # literal, brackets intact

    def test_summary_title_with_markup_chars(self):
        text = self._render(summary_table("t[bold]x", {}))
        assert "t[bold]x" in text


# ---- argv/credential leakage in fatal errors -----------------------------------

class TestRunnerFatalRedaction:
    def test_fatal_message_omits_argv(self):
        with pytest.raises(RuntimeError) as ei:
            run([pytest.importorskip("sys").executable,
                 "-c", "SECRET=token123; import sys; sys.exit(1)"],
                retries=1, fatal=True)
        assert "token123" not in str(ei.value)
        assert "python" in str(ei.value).lower() or "executable" in str(ei.value).lower()


# ---- URL building from operator input -------------------------------------------

class TestUrlEncoding:
    def test_osint_urls_quote_domain(self):
        import inspect

        from penguin.tools import osint
        src = inspect.getsource(osint)
        assert "quote(domain, safe='')" in src
        # no f-string interpolates the raw domain into a URL anymore
        assert "domain}/passive_dns" not in src
        assert "domain:*" not in src and "domain}/*" not in src

    def test_crtsh_quotes_domain(self):
        import inspect

        from penguin.tools import subdomain
        assert "quote(domain, safe='')" in inspect.getsource(subdomain.crtsh)
