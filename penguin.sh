#!/usr/bin/env bash
# penguin launcher - cd to project root, then run (auto-bootstraps .venv)
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
exec python3 -m penguin "$@"
