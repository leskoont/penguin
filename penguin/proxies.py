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
        import random

        valid: list[Proxy] = []
        test_url = self.cfg.test_url
        timeout = self.cfg.timeout
        # Cap total attempts (see ProxyConfig.max_candidates): each candidate we
        # test opens a conntrack flow to the proxy IP that lingers ~120s on the
        # router even after we time out, so validating thousands overflows the
        # NAT table and drops the WAN link right after validation. A random
        # sample keeps the pool representative of the full list.
        max_cand = getattr(self.cfg, "max_candidates", 0)
        if max_cand and len(proxies) > max_cand:
            proxies = random.sample(proxies, max_cand)
        target_valid = getattr(self.cfg, "target_valid", 0)
        total = len(proxies)
        done = 0
        # Validation is pure I/O wait (each candidate blocks up to `timeout`
        # seconds on a network round-trip), so worker count -- not CPU --
        # is what bounds wall-clock time here. 50 workers against ~4000
        # candidates at a 5s timeout took ~7 minutes (3942/50*5s =~ 394s);
        # a bigger pool cuts that roughly linearly.
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=self.cfg.validate_workers)
        futs = {}
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
                # Stop firing new connections once the pool is big enough: every
                # further attempt only adds conntrack pressure on the router for
                # proxies we don't need. Cancel the not-yet-started futures so
                # they never open their sockets.
                if target_valid and len(valid) >= target_valid:
                    for fut in pending:
                        fut.cancel()
                    break
        except BaseException:
            # Drop not-yet-started work immediately so shutdown doesn't wait
            # for all ~4500 candidates; already-running requests still get
            # up to `timeout` seconds to unwind cleanly below.
            for fut in futs:
                fut.cancel()
            raise
        finally:
            # cancel_futures drops anything still queued (early-stop leftovers)
            # so we don't open sockets we no longer need; running requests still
            # unwind within `timeout`.
            ex.shutdown(wait=True, cancel_futures=True)
        valid.sort(key=lambda p: p.latency)
        return valid

    # ---------- refresh ----------
    def _cache_fresh(self) -> bool:
        """True if the persisted validated pool is still within its TTL."""
        ttl = self.cfg.cache_ttl_minutes
        if ttl <= 0 or not self.valid_json.exists():
            return False
        age = time.time() - self.valid_json.stat().st_mtime
        return age < ttl * 60

    def _load_cache(self) -> list[Proxy]:
        import json

        try:
            data = json.loads(self.valid_json.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            logger.warning("[proxies] cache read failed; revalidating", exc_info=True)
            return []
        try:
            return [Proxy(**p) for p in data]
        except Exception:  # noqa: BLE001
            logger.warning("[proxies] cache parse failed; revalidating", exc_info=True)
            return []

    def refresh(self, force: bool = False, progress_cb=None) -> list[Proxy]:
        # Reuse an in-memory pool (same process) without revalidating unless forced.
        with self._lock:
            if self._pool and not force:
                return self._pool
        # Across runs (fresh process) reuse a recent validated pool within TTL
        # instead of re-validating ~4000 candidates every time (issue #3).
        if not force and self._cache_fresh():
            cached = self._load_cache()
            if cached:
                with self._lock:
                    self._pool = cached
                    self._idx = 0
                # Extend the cache window from last *use*, not just creation,
                # so repeated runs within TTL keep reusing instead of letting
                # the original validation timestamp expire the pool early.
                try:
                    self.valid_json.touch()
                except OSError:
                    pass
                logger.info("[proxies] reused cached pool: %d valid proxies (age < TTL)", len(cached))
                return cached
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

    def mark_dead(self, proxy_url: str) -> None:
        """Mark a proxy as dead after repeated failures and remove from rotation.

        Called by tool wrappers when a proxy connection fails (e.g. CURLE_PROXY).
        After repeated failures, the proxy is removed from the pool so subsequent
        picks don't try the same broken proxy again.
        """
        with self._lock:
            # Keep only proxies that don't match the dead proxy URL
            self._pool = [p for p in self._pool if p.url != proxy_url]
            if self._idx >= len(self._pool):
                self._idx = 0

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
