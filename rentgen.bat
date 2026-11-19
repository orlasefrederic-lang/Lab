@echo off
rem Rentgen: double-click this file to check the computer's hardware.
rem Parameters are passed on to the program, e.g.: rentgen.bat --stress
cd /d "%~dp0"
set "PY="
py -3 -c "import sys; sys.exit(sys.version_info < (3, 8))" >nul 2>&1 && set "PY=py -3"
if not defined PY (
    python -c "import sys; sys.exit(sys.version_info < (3, 8))" >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo Python 3.8 or newer was not found.
    echo Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
    goto done
)
%PY% "%~dp0rentgen.py" --open %*
:done
pause
