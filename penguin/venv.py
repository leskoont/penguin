"""penguin - automatic virtualenv bootstrap.

On the first run (and every subsequent run) penguin ensures a local ``.venv``
exists, installs ``requirements.txt`` into it, and re-executes itself inside
that venv. Subsequent runs skip the (re)install unless the marker is missing.

Disable with ``PENGUIN_NO_VENV=1`` or ``penguin run --no-venv``.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENV = ROOT / ".venv"
REQ = ROOT / "requirements.txt"
MARKER = VENV / ".penguin_bootstrapped"


def venv_python() -> Path:
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def in_venv() -> bool:
    return os.path.abspath(sys.prefix) == os.path.abspath(str(VENV))


def _create_venv() -> None:
    VENV.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True)
    py = str(venv_python())
    subprocess.run([py, "-m", "pip", "install", "--upgrade", "pip"], check=False)


def _install_deps() -> bool:
    py = str(venv_python())
    ok = True
    if REQ.exists():
        rc = subprocess.run([py, "-m", "pip", "install", "-r", str(REQ)], check=False).returncode
        ok = rc == 0
    if ok:
        MARKER.write_text("ok", encoding="utf-8")
    else:
        sys.stderr.write("[penguin] dependency install failed (offline?); venv created without deps\n")
    return ok


def ensure_venv(argv=None) -> None:
    if os.environ.get("PENGUIN_NO_VENV"):
        return
    if in_venv():
        return

    if not VENV.exists():
        try:
            _create_venv()
        except Exception as exc:  # noqa
            sys.stderr.write(f"[penguin] venv create failed: {exc}; using current interpreter\n")
            return

    if not MARKER.exists():
        _install_deps()

    py = venv_python()
    if not py.exists():
        return

    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    # Re-exec the CLI inside the venv; cwd pinned to project root.
    rc = subprocess.run([str(py), "-m", "penguin"] + list(argv or sys.argv[1:]),
                        cwd=str(ROOT), env=env, check=False).returncode
    sys.exit(rc)
