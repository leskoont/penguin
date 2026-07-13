"""penguin.tools - shared base for third-party CLI wrappers.

Each wrapper shells out to a recon binary via ``runner.run`` and returns the
output path / parsed data. Proxies are injected automatically when the tool
supports them (per ``config.tools.<name>.proxy``). Missing binaries are
skipped non-fatally.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from ..config import Config
from ..runner import run
from ..proxies import get_pool

logger = logging.getLogger("penguin.tools")


class ToolContext:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def proxy_for(self, tool: str) -> Optional[str]:
        if not self.cfg.proxies.enabled:
            return None
        if not self.cfg.tool_setting(tool, "proxy", True):
            return None
        pool = get_pool(self.cfg)
        return pool.pick()

    def proxy_flag(self, tool: str, proxy: Optional[str]) -> list[str]:
        """Return the correct proxy flag for a given tool."""
        if not proxy:
            return []
        mapping = {
            "httpx": ["-proxy", proxy],
            "nuclei": ["-proxy", proxy],
            "puredns": ["-proxy", proxy],
            "subfinder": ["-proxy", proxy],
            "amass": ["-proxy", proxy],
            "dnsx": ["-proxy", proxy],
            "katana": ["-proxy", proxy],
            "gau": ["-proxy", proxy],
            "ffuf": ["-x", proxy],
            "curl": ["-x", proxy],
        }
        return mapping.get(tool, [])

    def execute(self, tool: str, cmd: list, *, timeout: Optional[float] = None, log_stdout: bool = False):
        proxy = self.proxy_for(tool)
        if proxy:
            cmd += self.proxy_flag(tool, proxy)
        to = timeout or self.cfg.general.timeout
        return run(cmd, retries=self.cfg.general.retry_attempts, backoff=self.cfg.general.retry_backoff, timeout=to, log_stdout=log_stdout)

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
