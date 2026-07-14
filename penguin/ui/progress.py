"""Per-block Rich progress spinner for `penguin run`/`penguin tui`."""
from __future__ import annotations

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

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

    def __enter__(self) -> "RichBlockProgress":
        self._progress.start()
        self._task_id = self._progress.add_task("starting...", total=None)
        return self

    def __exit__(self, *exc) -> None:
        self._progress.stop()

    def callback(self, block_num: int, name: str, phase: str) -> None:
        label = BLOCK_LABELS.get(block_num, name)
        style = "bold cyan" if phase == "start" else "green"
        suffix = "..." if phase == "start" else " done"
        self._progress.update(self._task_id, description=f"[{style}]{label}{suffix}[/]")
