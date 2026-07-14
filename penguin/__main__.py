import os
import sys

# Handle venv control flags before any heavy import / re-exec.
if "--no-venv" in sys.argv:
    os.environ["PENGUIN_NO_VENV"] = "1"
if "--reinstall-venv" in sys.argv:
    # remove markers so ensure_venv reinstalls deps + reruns the toolchain installer
    from pathlib import Path

    _venv_dir = Path(__file__).resolve().parent.parent / ".venv"
    for _marker_name in (".penguin_bootstrapped", ".penguin_tools_bootstrapped"):
        _marker = _venv_dir / _marker_name
        if _marker.exists():
            _marker.unlink()

from .venv import ensure_venv

ensure_venv()

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
