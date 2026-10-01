@echo off
rem Hardware report: double-click this file to run hardware_info.py
cd /d "%~dp0"
where py >/dev/null 2>nul
if %errorlevel%==0 (
    py -3 "%~dp0hardware_info.py" --open %*
    goto done
)
where python >/dev/null 2>nul
if %errorlevel%==0 (
    python "%~dp0hardware_info.py" --open %*
    goto done
)
echo Python 3 not found. Install it from https://www.python.org/downloads/
:done
pause
