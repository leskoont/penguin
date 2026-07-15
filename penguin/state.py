"""penguin - run state store, dedup (anew) and diff engine.

Every artifact is stored as a normalized file under
``results/<target>/<run_id>/`` and accumulated into per-target history files
so each run can be diffed against the previous one.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional

from .config import Config


def _now() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")


class Artifacts:
    """Central registry of the well-known filenames blocks pass between each
    other through :class:`RunState`, instead of typed return values.

    Blocks 1-4 and the master pipeline currently hand data forward via *both*
    an in-memory return dict *and* these on-disk paths (re-read by later
    blocks/master via ``state.path()`` / ``state.read_lines()``). The
    filenames used to be duplicated as string literals across
    ``block1_infra.py``/``block2_web.py``/``block3_cloud_db.py``/
    ``block4_elite.py``/``master.py``, so a rename in one place could
    silently break a reader elsewhere. Import and use these constants
    instead of re-typing the literal.

    All paths are relative to the *run* directory (``RunState.run_dir`` /
    ``state.path(...)``) unless noted otherwise -- they are per-run
    artifacts, not accumulators. The one accumulator here (``ALL_*``) lives
    at the per-target base directory instead (``state.add_lines(...,
    accumulate=True)``) and must use a filename distinct from any per-run
    artifact above, so a cross-run history file never shares a name with
    -- and gets confused for -- a same-run artifact.
    """

    # block1 -> block3 (hostnames resolved this run, one per line)
    RESOLVED = "resolved.txt"
    # block1 -> block2/3 (raw httpx `-csv` output: "url,input,title,...")
    LIVE_HTTPX_CSV = "live/httpx.csv"
    # block2 -> block4 (clean http(s)://host URL-per-line, this run only)
    LIVE_HOSTS = "live_hosts.txt"

    # ---- cross-run accumulators (base dir, not run dir; see add_lines) ----
    ALL_SUBDOMAINS = "all_subdomains.txt"
    ALL_URLS = "all_urls.txt"
    # Deliberately NOT named "live_hosts.txt" -- that name is already the
    # per-run artifact block2/4 write above; reusing it here for the
    # cross-run accumulator was the dual-purpose footgun this registry
    # exists to prevent (see issue: "Implicit file-based contract between
    # blocks").
    ALL_LIVE_HOSTS = "all_live_hosts.txt"


ARTIFACTS = Artifacts()


class RunState:
    def __init__(self, cfg: Config, target: str):
        self.cfg = cfg
        self.target = target
        base_ts = _now()
        self.run_id = base_ts
        self.base = cfg.path(cfg.general.output_dir, target)
        self.run_dir = self.base / self.run_id

        # Collision guard: if run_dir already exists, append a counter
        counter = 0
        while self.run_dir.exists():
            counter += 1
            self.run_id = f"{base_ts}_{counter}"
            self.run_dir = self.base / self.run_id

        self.history_dir = self.base / "history"
        for d in (self.run_dir, self.history_dir):
            d.mkdir(parents=True, exist_ok=True)

    # ---- paths ----
    def path(self, *parts: str, run: bool = True) -> Path:
        root = self.run_dir if run else self.base
        p = root / Path(*parts)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def sub(self, name: str) -> Path:
        p = self.run_dir / name
        p.mkdir(parents=True, exist_ok=True)
        return p

    # ---- dedup (anew) ----
    def add_lines(self, filename: str, lines, *, accumulate: bool = True) -> int:
        """Append ``lines`` to a run file, deduped against the accumulator.

        Returns the number of *new* lines added. Honors the guide's anew pattern.
        When accumulate=True, returns count of lines new to the accumulator (system-wide);
        when accumulate=False, returns count of lines new to this run.
        """
        lines = {self._norm(l) for l in lines if l and str(l).strip()}
        new_to_accumulator = lines  # default if accumulate=False
        if accumulate:
            acc = self.base / filename
            existing = self._read_set(acc)
            new_to_accumulator = lines - existing
            if new_to_accumulator:
                # Atomic write: read-dedupe-temp-rename to avoid RMW race
                all_lines = existing | new_to_accumulator
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    dir=acc.parent,
                    encoding="utf-8",
                    delete=False,
                    suffix=".tmp"
                ) as tmp:
                    tmp.write("\n".join(sorted(all_lines)) + "\n")
                    tmp_path = Path(tmp.name)
                # Atomic rename on Windows and POSIX
                tmp_path.replace(acc)
        run_file = self.run_dir / filename
        run_set = self._read_set(run_file)
        added = lines - run_set
        if added:
            # Atomic write: read-dedupe-temp-rename to avoid RMW race
            all_run_lines = run_set | added
            with tempfile.NamedTemporaryFile(
                mode="w",
                dir=run_file.parent,
                encoding="utf-8",
                delete=False,
                suffix=".tmp"
            ) as tmp:
                tmp.write("\n".join(sorted(all_run_lines)) + "\n")
                tmp_path = Path(tmp.name)
            # Atomic rename on Windows and POSIX
            tmp_path.replace(run_file)
        return len(new_to_accumulator) if accumulate else len(added)

    def read_lines(self, filename: str, *, accumulate: bool = False) -> list[str]:
        p = (self.base / filename) if accumulate else (self.run_dir / filename)
        return self._read_list(p)

    @staticmethod
    def _norm(line: str) -> str:
        return line.strip().rstrip("/")

    @staticmethod
    def _read_set(p: Path) -> set:
        if not p.exists():
            return set()
        return {x.strip() for x in p.read_text(encoding="utf-8").splitlines() if x.strip()}

    @staticmethod
    def _read_list(p: Path) -> list:
        if not p.exists():
            return []
        return [x.strip() for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]

    # ---- JSON artifact ----
    def save_json(self, name: str, data) -> Path:
        p = self.run_dir / name
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        return p

    def save_text(self, name: str, text: str) -> Path:
        p = self.run_dir / name
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p

    # ---- diff (comm -13 style) ----
    def diff_against_previous(self, filename: str) -> dict:
        """Compare today's accumulated file vs the previous run's file."""
        cur = self.run_dir / filename
        prev_runs = sorted([d for d in self.history_dir.iterdir() if d.is_dir() and d.name != self.run_id])
        prev_file = None
        for d in reversed(prev_runs):
            cand = d / filename
            if cand.exists():
                prev_file = cand
                break
        cur_set = self._read_set(cur)
        prev_set = self._read_set(prev_file) if prev_file else set()
        new = sorted(cur_set - prev_set)
        removed = sorted(prev_set - cur_set)
        return {
            "current_count": len(cur_set),
            "previous_count": len(prev_set),
            "new": new,
            "removed": removed,
            "new_file": str(self.run_dir / f"new_{filename}"),
            "removed_file": str(self.run_dir / f"removed_{filename}"),
        }

    def write_diff_files(self, filename: str) -> dict:
        res = self.diff_against_previous(filename)
        if res["new"]:
            (self.run_dir / f"new_{filename}").write_text("\n".join(res["new"]) + "\n", encoding="utf-8")
        if res["removed"]:
            (self.run_dir / f"removed_{filename}").write_text("\n".join(res["removed"]) + "\n", encoding="utf-8")
        return res

    def archive(self) -> None:
        """Copy this run into history/ for future diffs."""
        dest = self.history_dir / self.run_id
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(self.run_dir, dest)
