@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" launch.py
) else (
    python launch.py
)
if errorlevel 1 (
    echo.
    echo If packages are missing, run SETUP_WINDOWS.cmd first.
    pause
)
endlocal
