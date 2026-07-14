"""Minimal single-target Textual dashboard for `penguin tui`."""
from __future__ import annotations

import logging
import threading
import traceback

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Footer, Header, Log, Static

from ..config import Config
from ..pipelines.master import run_target
from ..pipelines.report import build_report
from .progress import BLOCK_LABELS
from .tables import summary_table


class _LogWidgetHandler(logging.Handler):
    """Routes penguin logger records into the TUI's Log widget instead of
    Rich's normal stdout handler, which would corrupt the Textual screen."""

    def __init__(self, app: "PenguinTUI"):
        super().__init__()
        self._app = app

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self._app.call_from_thread(self._app.write_log, msg)
        except Exception:
            pass


class PenguinTUI(App):
    CSS = """
    #progress { height: 3; content-align: center middle; }
    #feed { height: 1fr; border: solid $accent; }
    #summary { height: auto; border: solid $accent; }
    """
    BINDINGS = [("q", "quit", "Quit")]

    def __init__(self, cfg: Config, target: dict):
        super().__init__()
        self.cfg = cfg
        self.target = target
        self._summary: dict | None = None
        # Set on quit (action_quit below) and checked between blocks inside
        # run_target -- a plain background thread can't be forcibly killed
        # or interrupted mid-synchronous-call, so this is the only way to
        # get the worker to stop launching further blocks once the user
        # has asked to quit.
        self._cancel_event = threading.Event()

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("starting...", id="progress")
            yield Log(id="feed")
            yield Static("", id="summary")
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"penguin tui - {self.target['value']}"
        self.run_recon()

    def write_log(self, msg: str) -> None:
        self.query_one("#feed", Log).write_line(msg)

    def update_progress(self, block_num: int, name: str, phase: str) -> None:
        label = BLOCK_LABELS.get(block_num, name)
        suffix = "..." if phase == "start" else " done"
        self.query_one("#progress", Static).update(f"{label}{suffix}")

    def _progress_cb(self, block_num: int, name: str, phase: str) -> None:
        self.call_from_thread(self.update_progress, block_num, name, phase)

    async def action_quit(self) -> None:
        """Signal the background recon worker to stop before exiting.

        Textual's default action_quit just tears down the event loop -- it
        has no way to interrupt a synchronous @work(thread=True) call chain.
        Setting the cancel event lets run_target notice between blocks and
        stop launching further ones instead of continuing to run orphaned
        after the UI is gone.
        """
        self._cancel_event.set()
        self.exit()

    @work(thread=True)
    def run_recon(self) -> None:
        logger = logging.getLogger("penguin")
        handler = _LogWidgetHandler(self)
        handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
        prev_handlers = list(logger.handlers)
        for h in prev_handlers:
            logger.removeHandler(h)
        logger.addHandler(handler)
        try:
            summary = run_target(self.cfg, self.target, progress_cb=self._progress_cb,
                                  cancel_event=self._cancel_event)
            self._summary = summary
            build_report(self.cfg, self.target, summary)
            self.call_from_thread(self._show_summary, summary)
        except Exception:
            # Otherwise a raise here is a silent Textual worker failure:
            # #progress stays frozen on the last block label and #summary
            # stays empty with no indication anything went wrong.
            self.call_from_thread(self.write_log, traceback.format_exc())
        finally:
            logger.removeHandler(handler)
            for h in prev_handlers:
                logger.addHandler(h)

    def _show_summary(self, summary: dict) -> None:
        table = summary_table(self.target["value"], summary)
        self.query_one("#summary", Static).update(table)
        self.query_one("#progress", Static).update("[bold green]done[/]")
