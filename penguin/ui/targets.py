"""Target resolution shared by `run` and `tui`, with an interactive
questionary fallback when nothing resolves and stdin is a real TTY."""
from __future__ import annotations

import logging
import sys
from typing import Optional

from ..config import Config, load_targets

logger = logging.getLogger("penguin")


def resolve_targets(
    cfg: Config,
    targets_path: Optional[str],
    target_opt: Optional[str],
    allow_wizard: bool = True,
) -> list[dict]:
    if target_opt:
        return [{"type": "domain", "value": target_opt}]

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
        return [t] if t else []

    return []
