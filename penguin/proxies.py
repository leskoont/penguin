"""penguin - proxy acquisition, validation and rotation.

On every invocation (and via ``penguin proxies refresh``) we pull the two
free proxy lists requested by the operator, dedup them, validate the working
ones against a benign endpoint, persist the pool and expose a ``pick()`` used
by every proxy-capable tool wrapper.

Sources (raw github, the blob URLs render HTML):
  - proxifly : https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt
  - iplocate : https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

from .config import Config, ProxyConfig

logger = logging.getLogger("penguin.proxies")


@dataclass
class Proxy:
    host: str
    port: int
    protocol: str  # http | https | socks5
    latency: float = 0.0

    @property
    def url(self) -> str:
        return f"{self.protocol}://{self.host}:{self.port}"


class ProxyPool:
    def __init__(self, cfg: Config):
        self.cfg = cfg.proxies  # type: ProxyConfig
        self._lock = threading.Lock()
        self._pool: list[Proxy] = []
        self._idx = 0
        self.raw_file = cfg.path(self.cfg.pool_file).with_name("proxies_raw.txt")
        self.valid_file = cfg.path(self.cfg.pool_file)
        self.valid_json = cfg.path(self.cfg.pool_file).with_suffix(".json")

    # ---------- acquisition ----------
    def _fetch(self, url: str) -> list[str]:
        try:
            req = Request(url, headers={"User-Agent": "penguin-recon"})
            with urlopen(req, timeout=20) as resp:
                text = resp.read().decode("utf-8", "ignore")
            return [ln.strip() for ln in text.splitlines() if ln.strip()]
        except (URLError, OSError, ValueError) as exc:
            logger.warning("[proxies] fetch failed %s: %s", url, exc)
            return []

    def _parse(self, lines: list[str], default_proto: str) -> list[Proxy]:
        out: list[Proxy] = []
        for ln in lines:
            if ln.startswith("#") or ln.lower().startswith("ip") or ":" not in ln:
                continue
            # proxifly data.txt format: ip:port:protocol  (or ip:port)
            parts = ln.split(":")
            if len(parts) < 2:
                continue
            host = parts[0].strip()
            try:
                port = int(parts[1].strip())
            except ValueError:
                continue
            proto = parts[2].strip().lower() if len(parts) >= 3 else default_proto
            if proto not in ("http", "https", "socks5", "socks4"):
                proto = default_proto
            out.append(Proxy(host, port, proto))
        return out

    def acquire(self) -> list[Proxy]:
        """Fetch both sources, dedup, persist raw list. Returns merged pool (unvalidated)."""
        merged: dict[tuple, Proxy] = {}
        if self.cfg.proxifly:
            for p in self._parse(self._fetch(self.cfg.proxifly), "http"):
                merged[(p.host, p.port)] = p
        if self.cfg.iplocate:
            for p in self._parse(self._fetch(self.cfg.iplocate), "socks5"):
                # keep socks5 when both list the same host:port but only upgrade if not present
                key = (p.host, p.port)
                if key not in merged:
                    merged[key] = p
                else:
                    if merged[key].protocol is None:
                        merged[key].protocol = "socks5"
        proxies = list(merged.values())
        self.raw_file.parent.mkdir(parents=True, exist_ok=True)
        self.raw_file.write_text(
            "\n".join(f"{p.host}:{p.port}:{p.protocol}" for p in proxies) + "\n", encoding="utf-8"
        )
        logger.info("[proxies] acquired %d unique candidates (proxifly+iplocate)", len(proxies))
        return proxies

    # ---------- validation ----------
    def _validate_one(self, proxy: Proxy, test_url: str, timeout: int) -> Optional[Proxy]:
        import requests

        # requests maps its `proxies` dict by the *target* URL scheme, not the
        # proxy's own scheme -- the same http(s):// proxy handles both, and
        # socks5 needs PySocks (requests[socks]) which is a declared dep.
        proxy_map = {"http": proxy.url, "https": proxy.url}
        try:
            t0 = time.time()
            resp = requests.get(test_url, proxies=proxy_map, timeout=timeout)
            if resp.status_code == 200:
                proxy.latency = round(time.time() - t0, 3)
                return proxy
        except Exception:  # noqa
            return None
        return None

    def validate(self, proxies: list[Proxy], progress_cb=None) -> list[Proxy]:
        import concurrent.futures

        valid: list[Proxy] = []
        test_url = self.cfg.test_url
        timeout = self.cfg.timeout
        total = len(proxies)
        done = 0
        # Validation is pure I/O wait (each candidate blocks up to `timeout`
        # seconds on a network round-trip), so worker count -- not CPU --
        # is what bounds wall-clock time here. 50 workers against ~4000
        # candidates at a 5s timeout took ~7 minutes (3942/50*5s =~ 394s);
        # a bigger pool cuts that roughly linearly.
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=self.cfg.validate_workers)
        try:
            futs = {ex.submit(self._validate_one, p, test_url, timeout): p for p in proxies}
            pending = set(futs)
            while pending:
                # Poll with a short timeout instead of an unbounded
                # as_completed()/wait(): on Windows, Ctrl+C only gets
                # processed when control returns to the interpreter loop, and
                # a blocking wait with no timeout never returns it, so
                # SIGINT is swallowed until every proxy finishes validating.
                finished, pending = concurrent.futures.wait(
                    pending, timeout=0.5, return_when=concurrent.futures.FIRST_COMPLETED
                )
                for fut in finished:
                    res = fut.result()
                    if res:
                        valid.append(res)
                    done += 1
                    if progress_cb:
                        # Runs on the main thread (this loop), so it keeps
                        # redrawing even when the 50 validation workers are
                        # busy enough to starve a background refresh thread.
                        try:
                            progress_cb(done, total)
                        except Exception:  # noqa
                            pass
        except BaseException:
            # Drop not-yet-started work immediately so shutdown doesn't wait
            # for all ~4500 candidates; already-running requests still get
            # up to `timeout` seconds to unwind cleanly below.
            for fut in futs:
                fut.cancel()
            raise
        finally:
            ex.shutdown(wait=True)
        valid.sort(key=lambda p: p.latency)
        return valid

    # ---------- refresh ----------
    def refresh(self, force: bool = False, progress_cb=None) -> list[Proxy]:
        if self._pool and not force:
            return self._pool
        candidates = self.acquire()
        if self.cfg.validate:
            valid = self.validate(candidates, progress_cb=progress_cb)
        else:
            valid = candidates
        with self._lock:
            self._pool = valid
            self._idx = 0
        self.valid_file.parent.mkdir(parents=True, exist_ok=True)
        self.valid_file.write_text("\n".join(p.url for p in valid) + "\n", encoding="utf-8")
        self.valid_json.write_text(json_dumps([asdict(p) for p in valid]), encoding="utf-8")
        logger.info("[proxies] pool ready: %d valid proxies", len(valid))
        return valid

    # ---------- pick ----------
    def pick(self) -> Optional[str]:
        with self._lock:
            if not self._pool:
                return None
            pref = self.cfg.protocol_preference
            if pref != "any":
                pref_list = [p for p in self._pool if p.protocol == pref]
                pool = pref_list or self._pool
            else:
                pool = self._pool
            if self.cfg.rotate == "fastest":
                proxy = pool[0]
            elif self.cfg.rotate == "random":
                import random

                proxy = random.choice(pool)
            else:  # roundrobin
                proxy = pool[self._idx % len(pool)]
                self._idx += 1
            return proxy.url

    def __len__(self) -> int:
        return len(self._pool)


def json_dumps(obj) -> str:
    import json

    return json.dumps(obj, indent=2)


# module-level cache keyed on pool_file path (lazily refreshed by CLI / pipelines)
_pool_cache: dict[str, ProxyPool] = {}


def get_pool(cfg: Config) -> ProxyPool:
    global _pool_cache
    pool_file = str(cfg.path(cfg.proxies.pool_file))
    if pool_file not in _pool_cache:
        _pool_cache[pool_file] = ProxyPool(cfg)
        # No eager refresh here: every CLI call site refreshes explicitly
        # right after get_pool() (behind a visible progress bar via
        # ui.progress.refresh_proxy_pool). An eager refresh here used to
        # run first, silently, with no progress feedback at all -- so the
        # first several minutes of every run showed nothing, and by the
        # time the visible progress bar appeared it was already
        # revalidating the same pool a second time.
    return _pool_cache[pool_file]
