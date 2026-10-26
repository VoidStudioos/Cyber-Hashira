@echo off
setlocal
cd /d "%~dp0\.."
echo ======================================================
echo   CYBER HASHIRA - WINDOWS DISTRIBUTION PACKAGER
echo ======================================================
python scripts\build_installers.py
echo.
echo Standalone packages are available in dist\packages\
pause
