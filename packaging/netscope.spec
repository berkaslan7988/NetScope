# -*- mode: python ; coding: utf-8 -*-
# Build from the project root (the folder containing gui.py):
#     pyinstaller --noconfirm packaging/netscope.spec
import os

ROOT = os.getcwd()  # build_windows.bat cd's to the project root first

a = Analysis(
    [os.path.join(ROOT, 'gui.py')],
    pathex=[ROOT],
    binaries=[],
    datas=[
        # bundle the IEEE OUI database next to the package
        (os.path.join(ROOT, 'netscope', 'data', 'oui.tsv.gz'), os.path.join('netscope', 'data')),
    ],
    hiddenimports=[
        # modules imported lazily inside functions (helps the analyzer)
        'netscope.ui.settings_dialog',
        'netscope.lan.active',
        'netscope.lan.traffic',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'PySide6.QtWebEngineCore'],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='NetScope',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,                       # GUI app, no console window
    disable_windowed_traceback=False,
    icon=os.path.join(ROOT, 'packaging', 'icon.ico'),
    version=os.path.join(ROOT, 'packaging', 'version_info.txt'),
)
