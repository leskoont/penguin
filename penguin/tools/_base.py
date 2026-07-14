"""penguin.tools - shared base for third-party CLI wrappers.

Each wrapper shells out to a recon binary via ``runner.run`` and returns the
output path / parsed data. Proxies are injected automatically when the tool
supports them (per ``config.tools.<name>.proxy``). Missing binaries are
skipped non-fatally.
"""
from __future__ import annotations

import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Optional

from ..config import Config
from ..runner import run, is_permanent
from ..proxies import get_pool

logger = logging.getLogger("penguin.tools")


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
                extra_env: Optional[dict] = None, retries: Optional[int] = None, input: Optional[str] = None):
        to = timeout or self.cfg.general.timeout
        env = {**os.environ, **extra_env} if extra_env else None
        n = max(1, retries if retries is not None else self.cfg.general.retry_attempts)
        backoff = self.cfg.general.retry_backoff

        if not self.proxy_applies(tool):
            return run(cmd, retries=n, backoff=backoff, timeout=to, log_stdout=log_stdout, env=env, input=input)

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
