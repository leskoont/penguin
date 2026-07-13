import os
import sys

# Handle venv control flags before any heavy import / re-exec.
if "--no-venv" in sys.argv:
    os.environ["PENGUIN_NO_VENV"] = "1"
if "--reinstall-venv" in sys.argv:
    # remove marker so ensure_venv reinstalls deps
    from pathlib import Path

    _marker = Path(__file__).resolve().parent.parent / ".venv" / ".penguin_bootstrapped"
    if _marker.exists():
        _marker.unlink()

from .venv import ensure_venv

ensure_venv()

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
