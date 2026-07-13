#!/usr/bin/env bash
# penguin launcher (auto-bootstraps .venv + deps, then runs inside it)
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
exec python3 -m penguin "$@"
