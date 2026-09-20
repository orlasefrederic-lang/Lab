@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

if "%~1"=="" (
    echo Перетащите на этот файл фото или видео мышкой -
    echo я покажу все метаданные, какие в нём есть.
    echo.
    pause
    exit /b 0
)

set "PY=py"
where py >nul 2>nul
if not %errorlevel% equ 0 set "PY=python"

:loop
if "%~1"=="" goto done
%PY% -m mediameta show --raw "%~1"
echo.
shift
goto loop

:done
pause
