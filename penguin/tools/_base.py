"""penguin.tools - shared base for third-party CLI wrappers.

Each wrapper shells out to a recon binary via ``runner.run`` and returns the
output path / parsed data. Proxies are injected automatically when the tool
supports them (per ``config.tools.<name>.proxy``). Missing binaries are
skipped non-fatally.

Tool timeout defaults and flags follow predictable patterns:

- Timeout: Most wrappers accept a timeout kwarg passed to ToolContext.execute().
  If unspecified, config.general.timeout is used. Passive sources (amass, subfinder,
  crt.sh) often have higher timeouts (e.g. 60-120s) due to slow OSINT aggregators.
  Active probes (httpx, masscan, nmap) use shorter timeouts (e.g. 30s) except where
  the probe itself dictates a longer timeout (e.g. masscan scanning 65k ports).

- Proxy support: Tools are listed in ToolContext.proxy_flag() if they support CLI
  proxy flags. Tools NOT listed (amass v4, puredns) dropped proxy support from their
  CLI entirely. Calling .execute() with proxy=True still picks a proxy and passes it
  in the list for matching tools; for unsupported tools, the proxy arg is ignored.

- Retries and backoff: Proxy-routed tools use the config-specified retry_attempts
  (default 3) with exponential backoff (config.retry_backoff, default 2.0). Each
  attempt re-picks a fresh proxy (round-robin) so failed proxies are skipped without
  waiting. Un-proxied tools (direct public APIs) use retries=1 by default unless
  explicitly overridden (e.g. crt.sh uses retries=3 as a transient aggregator).

- Binary-missing handling: All wrappers use ok_path() to distinguish a stale output
  file from a fresh run result. A missing binary is detected in runner.run() and
  reported via RunResult.ok=False with no output; the wrapper returns None and the
  caller skips the result non-fatally.
"""
from __future__ import annotations

import logging
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

from ..config import Config
from ..runner import RunResult, run, is_permanent
from ..proxies import get_pool

logger = logging.getLogger("penguin.tools")


def ok_path(r: RunResult, out: Path) -> Optional[Path]:
    """``out.exists()`` alone can't tell a fresh result from a stale file left
    on disk by a *prior* run of the same wrapper -- a binary that's missing,
    times out, or hits a permanent CLI error still reports ``r.ok is False``
    while an old ``out`` from an earlier invocation sits there untouched.
    Require both: the current invocation must have exited cleanly *and*
    produced the file.
    """
    return out if r.ok and out.exists() else None


class ToolContext:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def proxy_applies(self, tool: str) -> bool:
        return self.cfg.proxies.enabled and bool(self.cfg.tool_setting(tool, "proxy", True))

    def proxy_for(self, tool: str) -> Optional[str]:
        if not self.proxy_applies(tool):
            return None
        pool = get_pool(self.cfg)
        return pool.pick()

    def proxy_flag(self, tool: str, proxy: Optional[str]) -> list[str]:
        """Return the correct proxy flag for a given tool."""
        if not proxy:
            return []
        # amass v4 and puredns dropped proxy support from their CLI entirely --
        # passing -proxy makes them fail with "flag provided but not defined"
        # (amass) / print the usage screen and exit nonzero (puredns), so
        # neither is listed here even though they're in config.tools.
        mapping = {
            "httpx": ["-proxy", proxy],
            "nuclei": ["-proxy", proxy],
            "subfinder": ["-proxy", proxy],
            "dnsx": ["-proxy", proxy],
            "katana": ["-proxy", proxy],
            "gau": ["-proxy", proxy],
            "ffuf": ["-x", proxy],
            "curl": ["-x", proxy],
        }
        return mapping.get(tool, [])

    def execute(self, tool: str, cmd: list, *, timeout: Optional[float] = None, log_stdout: bool = False,
                extra_env: Optional[dict] = None, retries: Optional[int] = None, input: Optional[str] = None,
                proxy: Optional[bool] = None):
        to = timeout or self.cfg.general.timeout
        env = {**os.environ, **extra_env} if extra_env else None
        backoff = self.cfg.general.retry_backoff

        # ``proxy`` lets a caller force-disable proxying for a specific call even
        # though the tool is proxy-eligible in config -- used by passive OSINT
        # lookups (e.g. crt.sh) that hit a public aggregator, not the target,
        # and simply don't survive the free SOCKS pool.
        use_proxy = self.proxy_applies(tool) if proxy is None else (proxy and self.cfg.proxies.enabled)
        if not use_proxy:
            # Retries in this codebase exist for exactly one reason: to re-pick a
            # fresh proxy between attempts (the loop below). An un-proxied tool
            # gets no benefit from that -- a *hard* failure already fail-fasts in
            # run() (permanent-error detection), and the only thing left to retry
            # is a *timeout*, which just gets replayed at full length. So the
            # default 3 attempts turn a tool with timeout=1800 into 90 min of dead
            # wall-clock for a result that was final on attempt 1 -- the retry
            # storms observed live across gotator/trufflehog/masscan/feroxbuster/
            # kr/etc. Un-proxied tools therefore run *once* unless a caller
            # explicitly asks for more (e.g. crt.sh, a flaky public aggregator
            # where a genuine transient can clear on a second direct request).
            n = max(1, retries) if retries is not None else 1
            return run(cmd, retries=n, backoff=backoff, timeout=to, log_stdout=log_stdout, env=env, input=input)

        n = max(1, retries if retries is not None else self.cfg.general.retry_attempts)
        # Proxy-routed tools: a dead/broken proxy (e.g. curl exit=97
        # CURLE_PROXY) fails identically every time, so retrying the *same*
        # picked proxy n times just burns the backoff delay on a guaranteed
        # repeat failure. Re-pick a fresh proxy (roundrobin -> next in pool)
        # before each attempt instead of baking one proxy into the whole
        # retry loop.
        result = None
        for attempt in range(n):
            proxy = self.proxy_for(tool)
            full_cmd = list(cmd) + self.proxy_flag(tool, proxy) if proxy else list(cmd)
            result = run(full_cmd, retries=1, backoff=backoff, timeout=to, log_stdout=log_stdout, env=env,
                         input=input, log_attempt=(attempt + 1, n))
            if result.ok or is_permanent(cmd[0], result.returncode, result.stderr):
                return result
            if attempt < n - 1:
                time.sleep(backoff * (2 ** attempt))
        return result

    def curl_with_secret(self, curl_args: list[str], directives: list[str], *, timeout: Optional[float] = None):
        """Run curl with credentials passed via a temp ``-K`` config file instead of
        argv, so API keys don't show up in ``ps``/``/proc/<pid>/cmdline`` for other
        local users. ``directives`` are curl config-file lines, e.g.
        ``['header = "apikey: xxx"']`` or ``['user = "id:secret"']``.
        """
        fd, cfg_path = tempfile.mkstemp(suffix=".curlcfg", text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(directives) + "\n")
            # #90: chmod 0o600 no-op on Windows, only call on POSIX systems
            if not sys.platform.startswith('win'):
                os.chmod(cfg_path, 0o600)
            cmd = ["curl", "-s", "-K", cfg_path] + curl_args
            return self.execute("curl", cmd, timeout=timeout)
        finally:
            try:
                os.unlink(cfg_path)
            except OSError:
                pass

    def threads_flag(self, tool: str, default: int) -> list[str]:
        t = self.cfg.tool_setting(tool, "threads", self.cfg.general.threads)
        mapping = {
            "httpx": ["-threads", str(t)],
            "subfinder": ["-t", str(t)],
            "ffuf": ["-t", str(t)],
            "katana": ["-jc", "-d", "3"],
            "dnsx": ["-t", str(t)],
        }
        return mapping.get(tool, [])
