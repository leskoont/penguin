"""Bounded, fault-isolated fan-out for independent tool calls.

Blocks 1-4 spend most of their wall-clock waiting on subprocesses (subfinder,
amass, curl-to-crt.sh, OSINT lookups) that are network-bound, not CPU-bound.
Where several of those calls are genuinely independent -- each writes its own
distinct output file and none hammers the same target host or the same DNS
resolver set -- running them one after another just adds their timeouts
together. This helper runs such a batch concurrently instead.

Deliberately *not* a general "parallelize the whole pipeline" primitive:
callers must only hand it tasks that are safe to overlap. Concurrent puredns
resolves (resolver rate-limit -> dropped valid names), ffuf+feroxbuster on one
host (WAF/throttle), masscan+nmap on the same IPs (double load / IDS), and any
loop whose tools append to a *shared* output file all lose results or corrupt
output under concurrency, so those stay sequential at the call sites.
"""
from __future__ import annotations

import concurrent.futures
import logging
from typing import Callable, List, Optional, TypeVar

logger = logging.getLogger("penguin.parallel")

T = TypeVar("T")


def run_parallel(tasks: List[Callable[[], T]], *, max_workers: int,
                 label: str = "tasks") -> List[Optional[T]]:
    """Run zero-arg callables concurrently; return their results in input order.

    Exceptions raised by a task are logged and become ``None`` in that slot so a
    single failing tool never aborts its siblings -- this mirrors the runner's
    non-fatal philosophy (one dead tool must not sink the whole block). With a
    single task, or ``max_workers==1``, execution stays inline so operators can
    pin concurrency to 1 to reproduce the old sequential behaviour exactly.
    """
    tasks = list(tasks)
    if not tasks:
        return []
    workers = max(1, min(max_workers, len(tasks)))
    if workers == 1:
        return [_safe_call(fn, label) for fn in tasks]

    results: List[Optional[T]] = [None] * len(tasks)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    futs = {}
    try:
        futs = {ex.submit(_safe_call, fn, label): i for i, fn in enumerate(tasks)}
        pending = set(futs)
        while pending:
            # Poll with a short timeout rather than a blocking wait: on Windows
            # Ctrl+C is only delivered when control returns to the interpreter,
            # so an unbounded wait swallows SIGINT until every task finishes.
            # (Same reasoning as ProxyPool.validate.)
            finished, pending = concurrent.futures.wait(
                pending, timeout=0.5, return_when=concurrent.futures.FIRST_COMPLETED
            )
            for fut in finished:
                results[futs[fut]] = fut.result()
    except BaseException:
        for fut in futs:
            fut.cancel()
        raise
    finally:
        # in-flight tool subprocesses are timeout-bounded, so this is finite
        ex.shutdown(wait=True)
    return results


def _safe_call(fn: Callable[[], T], label: str) -> Optional[T]:
    try:
        return fn()
    except Exception:  # noqa: BLE001 - one task's failure must not sink siblings
        logger.warning("[parallel] %s task raised; continuing", label, exc_info=True)
        return None
