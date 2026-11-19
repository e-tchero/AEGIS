@echo off
REM
REM Project AEGIS — Windows Release Build Script
REM Lead Architect: ETCHERO / Abdul-Hameed
REM
REM Builds AEGIS.exe using PyInstaller and prepares the release directory.
REM
REM Usage:
REM   build.bat                    — full release build
REM   build.bat --quick            — skip Inno Setup installer generation
REM   build.bat --installer-only   — skip PyInstaller, rebuild installer only
REM

setlocal enabledelayedexpansion
set VERSION=1.0.0
set RELEASE_DIR=release\AEGIS-v%VERSION%
set DIST_DIR=dist\AEGIS

echo.
echo ╔══════════════════════════════════════════════════════╗
echo ║     PROJECT AEGIS — WINDOWS RELEASE BUILDER         ║
echo ║     Version %VERSION%                               ║
echo ╚══════════════════════════════════════════════════════╝
echo.

REM ─── Parse arguments ────────────────────────────────────────────────────
set QUICK=0
set INSTALLER_ONLY=0

if "%1"=="--quick" set QUICK=1
if "%1"=="--installer-only" set INSTALLER_ONLY=1

if "%INSTALLER_ONLY%"=="1" goto :installer

REM ─── Step 1: Verify dependencies ─────────────────────────────────────────────────
echo [BUILD] Step 1/6 — Verifying dependencies...
echo.

python -c "import PyInstaller; print('  PyInstaller', PyInstaller.__version__)" 2>nul
if errorlevel 1 (
    echo [ERROR] PyInstaller is not installed.
    echo   Install it with: pip install pyinstaller
    exit /b 1
)

python -c "import psutil; print('  psutil', psutil.__version__)" 2>nul
if errorlevel 1 (
    echo [WARNING] psutil not found — some modules may not work.
)

python -c "import scapy; print('  scapy', scapy.__version__)" 2>nul
if errorlevel 1 (
    echo [WARNING] scapy not found — network sentinel will use simulation mode.
)

python -c "import websockets; print('  websockets', websockets.__version__)" 2>nul
if errorlevel 1 (
    echo [WARNING] websockets not found — dashboard server will not work.
)

echo.

REM ─── Step 2: Verify icon exists ────────────────────────────────────────────────
echo [BUILD] Step 2/6 — Checking assets...
if not exist "image.ico" (
    echo [WARNING] image.ico not found. Building without icon.
    set ICON_FLAG=
) else (
    echo  [32m✓[0m image.ico found
    set ICON_FLAG=--icon=image.ico
)

if exist "config\file_baseline.json" (
    echo  [32m✓[0m config\file_baseline.json found
) else (
    echo  [33m⚠[0m config\file_baseline.json not found — FIM may not work
)

echo.

REM ─── Step 3: Clean previous builds ─────────────────────────────────────────────
echo [BUILD] Step 3/6 — Cleaning previous builds...
if exist "dist\AEGIS"     rmdir /s /q "dist\AEGIS"     2>nul
if exist "dist\AEGIS.exe" del "dist\AEGIS.exe"         2>nul
if exist "%RELEASE_DIR%"  rmdir /s /q "%RELEASE_DIR%"  2>nul
echo  [32m✓[0m Cleaned
echo.

REM ─── Step 4: Build with PyInstaller ────────────────────────────────────────────
echo [BUILD] Step 4/6 — Building AEGIS.exe with PyInstaller...
echo.
echo  This may take several minutes. Please wait...
echo.

pyinstaller --clean AEGIS.spec

if errorlevel 1 (
    echo.
    echo [ERROR] PyInstaller build failed. Check the output above for details.
    exit /b 1
)

echo  [32m✓[0m PyInstaller build complete
echo.

REM ─── Verify the executable exists ──────────────────────────────────────────────
if not exist "dist\AEGIS\AEGIS.exe" (
    if exist "dist\AEGIS.exe" (
        echo  [32m✓[0m AEGIS.exe found in dist\
    ) else (
        echo [ERROR] AEGIS.exe was not created. Build may have failed silently.
        dir dist\ /b
        exit /b 1
    )
) else (
    echo  [32m✓[0m AEGIS.exe found in dist\AEGIS\
)

echo.

REM ─── Step 5: Prepare release directory ─────────────────────────────────────────
echo [BUILD] Step 5/6 — Preparing release directory...

mkdir "%RELEASE_DIR%" 2>nul

REM Copy the executable
if exist "dist\AEGIS\AEGIS.exe" (
    copy "dist\AEGIS\AEGIS.exe" "%RELEASE_DIR%\AEGIS.exe" >nul
) else (
    copy "dist\AEGIS.exe" "%RELEASE_DIR%\AEGIS.exe" >nul
)
echo  [32m✓[0m AEGIS.exe copied

REM Copy documentation
if exist "AEGIS_Documentation.html" (
    copy "AEGIS_Documentation.html" "%RELEASE_DIR%\" >nul
    echo  [32m✓[0m Documentation copied
)

if exist "investor_one_pager.html" (
    copy "investor_one_pager.html" "%RELEASE_DIR%\" >nul
    echo  [32m✓[0m Investor one-pager copied
)

REM Copy config
mkdir "%RELEASE_DIR%\config" 2>nul
if exist "config\file_baseline.json" (
    copy "config\file_baseline.json" "%RELEASE_DIR%\config\" >nul
    echo  [32m✓[0m Config copied
)

REM Copy validation reports
if exist "validation\reports" (
    mkdir "%RELEASE_DIR%\validation\reports" 2>nul
    xcopy "validation\reports\*.html" "%RELEASE_DIR%\validation\reports\" /y >nul 2>nul
    echo  [32m✓[0m Validation reports copied
)

REM Copy README
if exist "README.md" (
    copy "README.md" "%RELEASE_DIR%\" >nul
    echo  [32m✓[0m README copied
)

REM Copy icon
copy "image.ico" "%RELEASE_DIR%\" >nul
echo  [32m✓[0m Icon copied

echo  [32m✓[0m Release directory prepared at: %RELEASE_DIR%
echo.

REM ─── Step 6: Verify executable ─────────────────────────────────────────────────
echo [BUILD] Step 6/6 — Verifying executable...

REM Check file size
for %%I in ("%RELEASE_DIR%\AEGIS.exe") do (
    set FILESIZE=%%~zI
)

if !FILESIZE! GTR 0 (
    set /a FILESIZE_MB=!FILESIZE! / 1048576
    echo  [32m✓[0m AEGIS.exe size: !FILESIZE_MB! MB
) else (
    echo [WARNING] AEGIS.exe appears to be empty!
)

REM Quick sanity check — try --help
echo  [32m✓[0m Running --help verification...
"%RELEASE_DIR%\AEGIS.exe" --help >nul 2>&1
if errorlevel 1 (
    echo  [33m⚠[0m --help check returned errorlevel %errorlevel% (may be expected if no Python)
) else (
    echo  [32m✓[0m --help responded OK
)

echo.

REM ─── Done ──────────────────────────────────────────────────────────────────────
echo ╔══════════════════════════════════════════════════════╗
echo ║     BUILD COMPLETE                                   ║
echo ║     Release: %RELEASE_DIR%            ║
echo ╚══════════════════════════════════════════════════════╝
echo.

REM ─── Optional: Inno Setup Installer ───────────────────────────────────────
if "%QUICK%"=="1" goto :done

:installer
if exist "%PROGRAMFILES(x86)%\Inno Setup 6\ISCC.exe" (
    echo [BUILD] Generating Inno Setup installer...
    "%PROGRAMFILES(x86)%\Inno Setup 6\ISCC.exe" installer.iss
    if errorlevel 1 (
        echo  [33m⚠[0m Inno Setup compilation had warnings (check output above)
    ) else (
        echo  [32m✓[0m Installer created
    )
) else (
    echo  [33m⚠[0m Inno Setup not found at %%PROGRAMFILES(x86)%%\Inno Setup 6\ISCC.exe
    echo    Skipping installer generation.
    echo    To create the installer, install Inno Setup from https://jrsoftware.org/isinfo.php
    echo    and run: ISCC installer.iss
)

:done
echo.
echo [BUILD] All done! Release is ready at: %RELEASE_DIR%
echo.
echo To distribute:
echo   1. Share the "%RELEASE_DIR%\" folder
echo   2. Or share AEGIS_Setup_v%VERSION%.exe if the installer was created
echo.
