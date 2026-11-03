@echo off
title Cyber Hashira - Standalone Desktop Workstation
echo ======================================================================
echo ⚔️  CYBER HASHIRA — Launching Standalone Desktop Workstation Window
echo ======================================================================

set SCRIPT_DIR=%~dp0
echo [*] Initializing Cyber Hashira security engine and backend daemon...
start "" /B "%SCRIPT_DIR%scripts\python_env\python.exe" "%SCRIPT_DIR%ui\web\app.py" 2>nul || start "" /B python "%SCRIPT_DIR%ui\web\app.py"

timeout /t 2 /nobreak >nul

set EDGE_X86="C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
set EDGE_X64="C:\Program Files\Microsoft\Edge\Application\msedge.exe"
set CHROME_X64="C:\Program Files\Google\Chrome\Application\chrome.exe"
set CHROME_X86="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"

if exist %EDGE_X86% (
    echo [*] Opening native application window via Edge App Mode...
    start "" %EDGE_X86% --app="http://127.0.0.1:8080" --window-size=1440,900 --user-data-dir="%TEMP%\hashira-desktop-profile"
) else if exist %EDGE_X64% (
    echo [*] Opening native application window via Edge App Mode...
    start "" %EDGE_X64% --app="http://127.0.0.1:8080" --window-size=1440,900 --user-data-dir="%TEMP%\hashira-desktop-profile"
) else if exist %CHROME_X64% (
    echo [*] Opening native application window via Chrome App Mode...
    start "" %CHROME_X64% --app="http://127.0.0.1:8080" --window-size=1440,900 --user-data-dir="%TEMP%\hashira-desktop-profile"
) else if exist %CHROME_X86% (
    echo [*] Opening native application window via Chrome App Mode...
    start "" %CHROME_X86% --app="http://127.0.0.1:8080" --window-size=1440,900 --user-data-dir="%TEMP%\hashira-desktop-profile"
) else (
    echo [*] Opening default web interface...
    start "" http://127.0.0.1:8080
)
