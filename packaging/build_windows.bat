@echo off
REM ============================================================
REM  NetScope - Windows build script
REM  Produces a single-file dist\NetScope.exe via PyInstaller,
REM  then (optionally) an installer via Inno Setup.
REM  Run from anywhere; it cd's to the project root itself.
REM ============================================================
setlocal
cd /d "%~dp0\.."

echo [1/4] Creating / using a virtual environment...
if not exist .venv (
    py -3 -m venv .venv
)
call .venv\Scripts\activate.bat

echo [2/4] Installing dependencies...
python -m pip install --upgrade pip >nul
pip install -r requirements.txt
pip install pyinstaller

echo [3/4] Building NetScope.exe (this can take a few minutes)...
pyinstaller --noconfirm --clean packaging\netscope.spec
if errorlevel 1 (
    echo BUILD FAILED.
    exit /b 1
)
if not exist "dist\NetScope.exe" (
    echo BUILD FAILED: dist\NetScope.exe was not produced.
    exit /b 1
)
echo Built: dist\NetScope.exe
for %%I in ("dist\NetScope.exe") do echo Size: %%~zI bytes

echo [4/4] Building installer (optional, needs Inno Setup 6)...
where iscc >nul 2>nul
if %errorlevel%==0 (
    iscc packaging\netscope_installer.iss
    echo Installer built in dist\
) else (
    echo Inno Setup ^(iscc^) not found on PATH - skipping installer.
    echo Get it from https://jrsoftware.org/isdl.php to build the setup .exe.
)

echo.
echo All done. Run dist\NetScope.exe
endlocal
