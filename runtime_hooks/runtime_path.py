"""
Project AEGIS — PyInstaller Runtime Hook
Ensures sys.path includes the _MEIPASS extraction directory so all bundled
modules can find each other via relative imports. Configures the Windows
console for UTF-8 output to prevent UnicodeEncodeError crashes.

Persistent data directories (logs, config, evidence) are created by config.py
using %PROGRAMDATA%/AEGIS — not in _MEIPASS.

This hook is loaded automatically by PyInstaller at application startup.
"""

import sys
import os
from pathlib import Path


def _setup_console_encoding() -> None:
    """Configure the Windows console to support UTF-8 output.

    On Windows, the default console code page (CP437/CP850) does not support
    the Unicode box-drawing and emoji characters used by AEGIS. This function:
    1. Sets PYTHONIOENCODING for subprocesses
    2. Reconfigures sys.stdout/sys.stderr to use UTF-8 encoding with
       error replacement (so unsupported chars display as '?' instead of
       raising UnicodeEncodeError)
    """
    try:
        os.environ["PYTHONIOENCODING"] = "utf-8"

        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")

        # Best-effort: set Windows console code page to UTF-8
        if sys.platform == "win32":
            try:
                import subprocess
                subprocess.run(
                    ["chcp", "65001"],
                    capture_output=True,
                    timeout=2,
                    shell=True,
                )
            except Exception:
                pass  # Non-fatal
    except Exception:
        pass  # Non-fatal


def _setup_path() -> None:
    """Ensure _MEIPASS is at the front of sys.path.

    When running as a PyInstaller bundle, sys._MEIPASS is the extraction
    directory containing all bundled Python modules and data files.
    """
    meipass = getattr(sys, "_MEIPASS", None)

    if meipass:
        meipass_str = str(meipass)
        if meipass_str in sys.path:
            sys.path.remove(meipass_str)
        sys.path.insert(0, meipass_str)

        # Also add the parent directory as fallback
        parent = str(Path(meipass).resolve().parent)
        if parent in sys.path:
            sys.path.remove(parent)
        sys.path.insert(1, parent)

    # When running in development mode (unfrozen), this hook is a no-op


_setup_console_encoding()
_setup_path()
