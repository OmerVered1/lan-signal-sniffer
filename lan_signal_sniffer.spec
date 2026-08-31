# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for LAN Signal Sniffer.

Produces a folder-based distribution on Windows and Linux, and a .app bundle on
macOS. The BUNDLE step is skipped off darwin, where it raises NotImplementedError.

Note there is no bundled capture driver, and there cannot be: Npcap is a kernel
driver with its own installer and licence. The Windows installer checks for it
and the app reports its absence at startup.
"""

import os
import sys

block_cipher = None

if sys.platform == "darwin" and os.path.exists("assets/app_icon.icns"):
    icon_path = "assets/app_icon.icns"
elif sys.platform == "win32" and os.path.exists("assets/app_icon.ico"):
    icon_path = "assets/app_icon.ico"
else:
    icon_path = None

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    # Profiles ship alongside the executable so a fresh install can record from
    # a known instrument without going through identification first.
    datas=[("profiles", "profiles"), ("assets", "assets")],
    hiddenimports=[
        "lan_sniffer",
        "lan_sniffer._version",
        "lan_sniffer.monitor",
        "lan_sniffer.analysis.reconstruct",
        "lan_sniffer.analysis.vendor",
        "lan_sniffer.analysis",
        "lan_sniffer.ui.modbus_setup",
        "lan_sniffer.ui.device_form",
        "lan_sniffer.readers.modbus",
        "lan_sniffer.readers.probe",
        "lan_sniffer.readers.questor",
        "lan_sniffer.ui.questor_setup",
        "lan_sniffer.updater",
        "lan_sniffer.capture.capture",
        "lan_sniffer.capture.neighbors",
        "lan_sniffer.capture.reassembly",
        "lan_sniffer.protocol.fields",
        "lan_sniffer.protocol.framer",
        "lan_sniffer.protocol.profile",
        "lan_sniffer.protocol.session",
        "lan_sniffer.ui.calibrate",
        "lan_sniffer.ui.identify",
        "lan_sniffer.ui.live_view",
        "lan_sniffer.ui.main_window",
        "lan_sniffer.writers.csv_writer",
        "lan_sniffer.writers.raw_writer",
        "lan_sniffer.writers.survey",
        "lan_sniffer.writers.merge",
        "PyQt5",
        "PyQt5.QtCore",
        "PyQt5.QtGui",
        "PyQt5.QtWidgets",
        "pyqtgraph",
        "numpy",
        # scapy resolves several of these at run time, so PyInstaller's static
        # analysis does not see them.
        "scapy",
        "scapy.all",
        "scapy.arch",
        "scapy.arch.common",
        "scapy.layers.inet",
        "scapy.sendrecv",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=["matplotlib", "tkinter", "PyQt6", "PySide2", "PySide6"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="LAN Signal Sniffer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="LAN Signal Sniffer",
)

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="LAN Signal Sniffer.app",
        icon=icon_path,
        bundle_identifier="il.ac.bgu.omervered.lansignalsniffer",
        info_plist={
            "CFBundleShortVersionString": "0.15.0",
            "NSHighResolutionCapable": True,
        },
    )
