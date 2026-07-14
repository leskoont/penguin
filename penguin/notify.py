"""penguin - optional notifications (Slack / Discord / Telegram).

Disabled by default. Sends a webhook POST only when notify.enabled and the
webhook env var is present. Used by continuous mode to alert on new assets
or critical findings.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

import requests

from .config import Config

logger = logging.getLogger("penguin.notify")


def notify(cfg: Config, message: str, *, level: str = "info", event: str = "") -> bool:
    if not cfg.notify.enabled:
        logger.debug("[notify] disabled, skipping")
        return False
    webhook = os.environ.get(cfg.notify.webhook_env)
    if not webhook:
        logger.debug("[notify] no webhook env %s, skipping", cfg.notify.webhook_env)
        return False
    if event and event not in cfg.notify.notify_on:
        logger.debug("[notify] event %s not in notify_on, skipping", event)
        return False

    provider = cfg.notify.provider.lower()
    try:
        if provider == "slack":
            payload = {"text": f"[{level.upper()}] {message}"}
            resp = requests.post(webhook, json=payload, timeout=10)
        elif provider == "discord":
            payload = {"content": f"[{level.upper()}] {message}"}
            resp = requests.post(webhook, json=payload, timeout=10)
        elif provider == "telegram":
            # webhook env expected as https://api.telegram.org/bot<token>/sendMessage?chat_id=<id>
            payload = {"text": f"[{level.upper()}] {message}"}
            resp = requests.post(webhook, json=payload, timeout=10)
        else:
            logger.warning("[notify] unknown provider %s", provider)
            return False
        ok = resp.status_code < 300
        if not ok:
            logger.warning("[notify] post failed %s: %s", resp.status_code, resp.text[:200])
        return ok
    except Exception as exc:  # noqa
        logger.warning("[notify] error: %s", exc)
        return False
