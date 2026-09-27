@echo off
rem Network activity monitor: starts without a console window.
rem Administrator rights are requested by the program itself (UAC).
cd /d "%~dp0"
where pyw >nul 2>nul && (start "" pyw -3 "%~dp0main.py" %*) || (start "" pythonw "%~dp0main.py" %*)
