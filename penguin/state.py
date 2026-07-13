"""penguin - run state store, dedup (anew) and diff engine.

Every artifact is stored as a normalized file under
``results/<target>/<run_id>/`` and accumulated into per-target history files
so each run can be diffed against the previous one.
"""
from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

from .config import Config


def _now() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


class RunState:
    def __init__(self, cfg: Config, target: str):
        self.cfg = cfg
        self.target = target
        self.run_id = _now()
        self.base = cfg.path(cfg.general.output_dir, target)
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
        """
        lines = {self._norm(l) for l in lines if l and str(l).strip()}
        if accumulate:
            acc = self.base / filename
            existing = self._read_set(acc)
            new = lines - existing
            if new:
                with open(acc, "a", encoding="utf-8") as fh:
                    fh.write("\n".join(sorted(new)) + "\n")
        run_file = self.run_dir / filename
        run_set = self._read_set(run_file)
        added = lines - run_set
        with open(run_file, "a", encoding="utf-8") as fh:
            if added:
                fh.write("\n".join(sorted(added)) + "\n")
        return len(added)

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
