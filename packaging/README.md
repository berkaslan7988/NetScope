# Packaging NetScope for Windows

These files build a standalone Windows executable and an installer.

## What's here
- `netscope.spec` — PyInstaller build recipe (single-file, windowed, bundles the
  IEEE OUI database and the app icon).
- `version_info.txt` — Windows file/product version metadata embedded in the exe.
- `icon.ico` / `icon.png` — application icon.
- `build_windows.bat` — one-click build: venv → deps → PyInstaller → (optional) installer.
- `netscope_installer.iss` — Inno Setup script for `NetScope-Setup.exe`.

## Build (on Windows)
1. Install Python 3.10+ (with the `py` launcher) and, optionally,
   [Inno Setup 6](https://jrsoftware.org/isdl.php) for the installer.
2. From the project root (the folder with `gui.py`):
   ```bat
   packaging\build_windows.bat
   ```
3. Outputs:
   - `dist\NetScope.exe` — the standalone app (no Python needed to run).
   - `dist\NetScope-Setup.exe` — the installer (only if Inno Setup is present).

## Manual build (equivalent)
```bat
pip install -r requirements.txt pyinstaller
pyinstaller --noconfirm --clean packaging\netscope.spec
```

## Notes
- The app reads/writes its database and settings under `%USERPROFILE%\.netscope\`,
  so the install location stays read-only and no admin rights are required.
- UPX is enabled in the spec to shrink the exe; if UPX isn't installed PyInstaller
  simply skips it (harmless).
- Antivirus tools occasionally flag fresh PyInstaller exes (false positive). Code-signing
  the exe avoids this for distribution.
