"""Shared Rich console + logging setup for the penguin CLI."""
from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler

console = Console()


def setup_logging(verbose: bool) -> None:
    logger = logging.getLogger("penguin")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    # Remove all existing handlers (not just RichHandler) to prevent leaking
    # TUI handlers or other non-Rich handlers from previous setup() calls.
    # This ensures a clean logging state when setup_logging() is called multiple times.
    for h in list(logger.handlers):
        logger.removeHandler(h)
    handler = RichHandler(console=console, show_time=True, show_path=False,
                           markup=False, rich_tracebacks=True)
    handler.setFormatter(logging.Formatter("%(name)s: %(message)s", datefmt="%H:%M:%S"))
    logger.addHandler(handler)
    logger.propagate = False
