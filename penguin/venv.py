"""penguin - automatic virtualenv bootstrap.

On the first run (and every subsequent run) penguin ensures a local ``.venv``
exists, installs ``requirements.txt`` into it, and re-executes itself inside
that venv. Subsequent runs skip the (re)install unless the marker is missing.

The first run also invokes the OS-appropriate installer
(``scripts/install.ps1`` on Windows, ``scripts/install.sh`` elsewhere) to
pull in the recon toolchain (Go binaries, wordlists), gated by its own
marker so it likewise only runs once.

Disable with ``PENGUIN_NO_VENV=1`` or ``penguin run --no-venv``. Force
either step to run again with ``penguin run --reinstall-venv``.
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
TOOLS_MARKER = VENV / ".penguin_tools_bootstrapped"


def _augment_tool_path() -> None:
    """scripts/install.sh installs recon tools into ~/go/bin, ~/.local/bin
    and ~/.cargo/bin, and persists those onto PATH via ~/.bashrc -- but a
    shell that hasn't been reopened/sourced since (e.g. right after this
    same run just installed Go for the first time) won't see them yet.
    Prepend them to this process's PATH so install-check and tool execution
    (runner.py, via inherited PATH) work immediately either way.
    """
    if os.name == "nt":
        return
    home = Path.home()
    extra = [home / "go" / "bin", home / ".local" / "bin", home / ".cargo" / "bin"]
    parts = os.environ.get("PATH", "").split(os.pathsep)
    for d in extra:
        d = str(d)
        if d not in parts:
            parts.insert(0, d)
    os.environ["PATH"] = os.pathsep.join(parts)


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


def _install_tools() -> bool:
    script = ROOT / "scripts" / ("install.ps1" if os.name == "nt" else "install.sh")
    if not script.exists():
        TOOLS_MARKER.write_text("skip", encoding="utf-8")
        return True
    sys.stderr.write(
        f"[penguin] first run: installing recon toolchain via scripts/{script.name} "
        "(network access + tool builds, may take several minutes)...\n"
    )
    if os.name == "nt":
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)]
    else:
        cmd = ["bash", str(script)]
    rc = subprocess.run(cmd, cwd=str(ROOT), check=False).returncode
    ok = rc == 0
    if ok:
        TOOLS_MARKER.write_text("ok", encoding="utf-8")
    else:
        sys.stderr.write(
            f"[penguin] toolchain install exited {rc}; some tools may be missing "
            "(see `penguin install-check`). Re-run anytime with: python -m penguin --reinstall-venv\n"
        )
    return ok


def ensure_venv(argv=None) -> None:
    _augment_tool_path()
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

    if not TOOLS_MARKER.exists():
        _install_tools()

    py = venv_python()
    if not py.exists():
        return

    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    # Re-exec the CLI inside the venv; cwd pinned to project root.
    rc = subprocess.run([str(py), "-m", "penguin"] + list(argv or sys.argv[1:]),
                        cwd=str(ROOT), env=env, check=False).returncode
    sys.exit(rc)
