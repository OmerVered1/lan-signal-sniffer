# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the probe tool, built as a single console executable.

Separate from the app on purpose. This is the one thing here that transmits, so
it is not a button in a window that can be reached by accident — it is a command
you have to open a terminal and type, on a machine where you have deliberately
closed the instrument's own software.

One file rather than a folder, because it gets carried to whichever machine is
wired to the analyser. The request lists are bundled inside it, so nothing has
to travel alongside it.
"""

import os

block_cipher = None

a = Analysis(
    ["tools/probe_analyser.py"],
    pathex=["."],
    binaries=[],
    datas=[("probe_lists", "probe_lists")],
    hiddenimports=[
        "lan_sniffer",
        "lan_sniffer.readers.probe",
        "lan_sniffer.protocol.framer",
        "lan_sniffer.protocol.fields",
        "lan_sniffer.capture.reassembly",
        "lan_sniffer.writers.raw_writer",
        "numpy",
    ],
    hookspath=[],
    runtime_hooks=[],
    # No GUI, no capture driver: this speaks TCP and nothing else.
    excludes=["PyQt5", "PyQt6", "PySide2", "PySide6", "pyqtgraph", "matplotlib",
              "tkinter", "scapy"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="probe-analyser",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="assets/app_icon.ico" if os.path.exists("assets/app_icon.ico") else None,
)
