# -*- mode: python ; coding: utf-8 -*-
"""
Project AEGIS — PyInstaller Build Specification
Lead Architect: ETCHERO / Abdul-Hameed
Version: 1.3.0 | Classification: AEGIS-BUILD

Produces a standalone AEGIS.exe for Windows that requires no Python runtime.

Usage:
    pyinstaller AEGIS.spec

Build requirements:
    pip install pyinstaller psutil scapy websockets

Assets bundled:
    - config/file_baseline.json  — baseline hashes for File Integrity Monitor
    - image.ico                  — application icon
    - AEGIS_Documentation.html   — full system documentation
    - investor_one_pager.html    — investor pitch one-pager
    - validation/reports/*.html  — phase validation reports
    - README.md                  — project readme

Runtime behaviour:
    - All Python modules are extracted to sys._MEIPASS at startup
    - config.py creates LOG_DIR and CONFIG_DIR under _MEIPASS at import time
    - Logs and evidence persist inside the temp directory for the session,
      then are cleaned up by the OS when the process exits
    - Use --persist to write blocked IPs to disk (within _MEIPASS/config/)
"""

import os
import glob
from pathlib import Path

block_cipher = None

# ─── DATA FILES (assets bundled alongside the executable) ──────────────────

# Collect all validation report HTML files
report_files = []
reports_glob = sorted(glob.glob("validation/reports/*.html"))
for fp in reports_glob:
    report_files.append((fp, "validation/reports"))

# Core configuration
datas = [
    ("config/file_baseline.json", "config"),
    ("image.ico", "."),
    ("AEGIS_Documentation.html", "."),
    ("investor_one_pager.html", "."),
    ("README.md", "."),
    ("LICENSE", "."),
]

# Add validation reports
datas.extend(report_files)

# ─── HIDDEN IMPORTS (dynamically/lazily loaded modules) ────────────────────
#
# These are modules that PyInstaller may not discover automatically because:
# - They are imported lazily (inside functions, behind try/except)
# - They are used via dynamic string lookups
# - They are built-in C extensions referenced by other modules

hiddenimports = [
    # === Core Python ===
    "ctypes",
    "ipaddress",
    "uuid",
    "hashlib",
    "argparse",
    "json",
    "threading",
    "datetime",
    "logging",
    "logging.handlers",
    "pathlib",
    "typing",
    "time",
    "traceback",
    "urllib.request",
    "re",
    "collections",
    "dataclasses",
    "abc",
    "tempfile",
    "subprocess",
    "asyncio",
    "platform",
    "shutil",
    "socket",
    "inspect",
    "textwrap",
    "math",
    "enum",

    # === Third-party dependencies ===
    "psutil",
    "scapy",
    "scapy.all",
    "websockets",

    # === Project modules ===
    "config",
    "core",
    "core.heartbeat",
    "modules",
    "modules.firewall",
    "modules.firewall_backends",
    "modules.evidence_engine",
    "modules.incident_manager",
    "modules.dashboard_server",
    "modules.ai_analyst",
    "modules.dns_monitor",
    "modules.file_monitor",
    "modules.login_monitor",
    "modules.memory_monitor",
    "modules.net_sentinel",
    "modules.process_monitor",
]

# ─── EXCLUDES (not needed for AEGIS) ───────────────────────────────────────
excludes = [
    "tkinter",
    "matplotlib",
    "numpy",
    "pandas",
    "scipy",
    "PIL",
    "PyQt5",
    "PyQt6",
    "PySide2",
    "PySide6",
    "wx",
    "notebook",
    "jupyter",
    "ipython",
    "cv2",
    "tensorflow",
    "torch",
    "keras",
    "transformers",
    "nltk",
    "sphinx",
    "flask",
    "django",
    "sanic",
    "fastapi",
    "bottle",
    "tornado",
    "celery",
    "redis",
    "sqlalchemy",
    "alembic",
    "mypy",
    "black",
    "pylint",
    "coverage",
    "pytest",
    "pytest_mock",
    "pytest_asyncio",
    "pytest_cov",
]

# ─── ANALYSIS ───────────────────────────────────────────────────────────────
a = Analysis(
    ["aegis.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=["runtime_hooks"],
    hooksconfig={},
    runtime_hooks=["runtime_hooks/runtime_path.py"],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# ─── PYZ (compressed Python bytecode archive) ──────────────────────────────
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# ─── EXECUTABLE ─────────────────────────────────────────────────────────────
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="AEGIS",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,               # Security tool — shows console output
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="image.ico",
)

# ─── COLLECT (for one-folder mode — uncomment to use) ──────────────────────
# coll = COLLECT(
#     exe,
#     a.binaries,
#     a.zipfiles,
#     a.datas,
#     strip=False,
#     upx=True,
#     upx_exclude=[],
#     name="AEGIS",
# )
