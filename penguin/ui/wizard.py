"""Interactive questionary wizard, used only as a fallback when no target
resolves from --target/targets.txt and stdin is a real TTY."""
from __future__ import annotations

from typing import Optional

import questionary

from ..config import Config

_STAGE_LABELS = {
    "infra": "Block 1: infra recon",
    "web": "Block 2: web",
    "cloud_db": "Block 3: cloud & db",
    "elite": "Block 4: elite/git",
}


def wizard_target(cfg: Config) -> Optional[dict]:
    target_type = questionary.select(
        "Target type:",
        choices=["domain", "asn", "cidr", "org", "url"],
    ).ask()
    if target_type is None:
        return None

    value = (questionary.text(f"Target {target_type}:").ask() or "").strip()
    if not value:
        return None

    choices = [
        questionary.Choice(label, value=name, checked=cfg.stage_enabled(name))
        for name, label in _STAGE_LABELS.items()
    ]
    selected = questionary.checkbox("Stages to run:", choices=choices).ask()
    if selected is None:
        return None
    # #81: empty selection returns empty list, not None -- warn and re-prompt
    if not selected:
        import logging
        logger = logging.getLogger("penguin.wizard")
        logger.warning("no stages selected; please select at least one stage")
        return wizard_target(cfg)  # re-prompt recursively

    # #82: return stages in result dict instead of mutating global cfg
    return {
        "type": target_type,
        "value": value,
        "stages": {name: (name in selected) for name in _STAGE_LABELS}
    }
