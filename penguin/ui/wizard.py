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

    value = questionary.text(f"Target {target_type}:").ask()
    if not value:
        return None

    choices = [
        questionary.Choice(label, value=name, checked=cfg.stage_enabled(name))
        for name, label in _STAGE_LABELS.items()
    ]
    selected = questionary.checkbox("Stages to run:", choices=choices).ask()
    if selected is None:
        return None
    for name in _STAGE_LABELS:
        cfg.stages[name] = name in selected

    return {"type": target_type, "value": value.strip()}
