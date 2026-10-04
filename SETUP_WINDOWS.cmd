@echo off
setlocal
cd /d "%~dp0"
echo Creating a project-only Python environment. Python 3.13 is recommended.
if not exist ".venv\Scripts\python.exe" (
    where py >nul 2>nul
    if errorlevel 1 (
        python -m venv .venv
    ) else (
        py -3.13 -m venv .venv
    )
)
if not exist ".venv\Scripts\python.exe" (
    echo Python 3.13 could not be found. Install Python 3.13 and try again.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo Dependency installation failed. Check the messages above and your Internet connection.
    pause
    exit /b 1
)
echo.
echo Setup complete. Double-click START_DASHBOARD.cmd.
pause
endlocal
