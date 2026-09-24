"""Target resolution shared by `run` and `tui`, with an interactive
questionary fallback when nothing resolves and stdin is a real TTY."""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

from ..config import Config, load_targets, parse_target_token

logger = logging.getLogger("penguin")


def _expand_target_opt(target_opt: str) -> list[dict]:
    """Expand --target into one or more targets:
      * "-"                  -> read tokens from stdin
      * an existing file     -> read tokens from that file
      * "a.com,b.com"        -> comma-separated list
      * a single value       -> one target
    Each token goes through parse_target_token so type prefixes / URLs work."""
    tokens: list[str]
    if target_opt.strip() == "-":
        tokens = sys.stdin.read().splitlines()
    else:
        p = Path(target_opt)
        try:
            is_file = p.is_file()
        except OSError:
            is_file = False
        if is_file:
            tokens = p.read_text(encoding="utf-8").splitlines()
        else:
            tokens = target_opt.split(",")
    out: list[dict] = []
    seen: set[str] = set()
    for tok in tokens:
        t = parse_target_token(tok)
        if t and t["value"] and t["value"] not in seen:
            seen.add(t["value"])
            out.append(t)
    return out


def resolve_targets(
    cfg: Config,
    targets_path: Optional[str],
    target_opt: Optional[str],
    allow_wizard: bool = True,
) -> list[dict]:
    if target_opt:
        return _expand_target_opt(target_opt)

    resolved = load_targets(targets_path)
    if resolved:
        return resolved

    stdin = sys.stdin
    if allow_wizard and stdin is not None and stdin.isatty():
        from .wizard import wizard_target

        try:
            t = wizard_target(cfg)
        except Exception:
            # Some terminals report isatty()==True but aren't actually
            # usable by prompt_toolkit (e.g. certain Windows/MSYS shells),
            # which raises instead of returning None. Degrade to the
            # ordinary "no targets" error path rather than crashing.
            logger.debug("wizard failed, falling back to no-targets error", exc_info=True)
            return []
        if t:
            # #82: apply selected stages from wizard result to cfg
            if "stages" in t:
                cfg.stages.update(t.pop("stages"))
            return [t]
        return []

    return []
