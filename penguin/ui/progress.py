"""Per-block Rich progress spinner for `penguin run`/`penguin tui`."""
from __future__ import annotations

import time

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

BLOCK_LABELS = {
    1: "Block 1: infra recon",
    2: "Block 2: web",
    3: "Block 3: cloud & db",
    4: "Block 4: elite/git",
}


class RichBlockProgress:
    def __init__(self, console: Console):
        # spinner_name="line" (pure ASCII -\|/) avoids UnicodeEncodeError on
        # Windows consoles running a legacy (non-UTF-8) codepage, where the
        # default "dots" spinner's Braille characters can't be encoded.
        self._progress = Progress(SpinnerColumn(spinner_name="line"), TextColumn("{task.description}"),
                                   TimeElapsedColumn(), console=console)
        self._task_id = None
        self._started = False
        self._stopped = False

    def __enter__(self) -> "RichBlockProgress":
        self._progress.start()
        self._task_id = self._progress.add_task("starting...", total=None)
        self._started = True
        return self

    def __exit__(self, *exc) -> None:
        self._stopped = True
        self._progress.stop()

    def callback(self, block_num: int, name: str, phase: str) -> None:
        # Guard against callback invocation outside context manager scope or after __exit__.
        # This can happen if a background task queues callbacks that fire after the
        # context manager has already exited.
        if not self._started or self._stopped:
            return
        label = BLOCK_LABELS.get(block_num, name)
        style = "bold cyan" if phase == "start" else "green"
        suffix = "..." if phase == "start" else " done"
        self._progress.update(self._task_id, description=f"[{style}]{label}{suffix}[/]")


def refresh_proxy_pool(pool, console: Console, force: bool = True):
    """Refresh the proxy pool behind a live N/total progress bar. Validating
    hundreds of free-proxy candidates against a live endpoint can take
    minutes with no other output in between, which otherwise looks like a
    hang.

    Updates are driven with an explicit refresh=True on the calling
    (main) thread rather than relying on Progress's own background
    auto-refresh thread: with 50 concurrent validation worker threads
    hammering the GIL, that background thread can get starved badly enough
    on some setups that the spinner never visibly moves.
    """
    progress = Progress(SpinnerColumn(spinner_name="line"), TextColumn("{task.description}"),
                         BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(), console=console)
    last_refresh = 0.0
    with progress:
        task_id = progress.add_task("[cyan]acquiring proxy candidates...[/]", total=None)

        def _cb(done: int, total: int) -> None:
            nonlocal last_refresh
            now = time.monotonic()
            force_refresh = now - last_refresh > 0.1 or done == total
            if force_refresh:
                last_refresh = now
            progress.update(task_id, description="[cyan]validating proxies...[/]",
                             completed=done, total=total, refresh=force_refresh)

        return pool.refresh(force=force, progress_cb=_cb)
