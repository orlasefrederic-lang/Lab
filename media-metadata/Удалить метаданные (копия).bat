@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

if "%~1"=="" (
    echo Перетащите на этот файл фото или видео - я сделаю копию
    echo без метаданных ^(без геолокации, камеры и дат^) рядом с оригиналом,
    echo с пометкой _clean в имени. Оригинал останется нетронутым.
    echo.
    pause
    exit /b 0
)

set "PY=py"
where py >nul 2>nul
if not %errorlevel% equ 0 set "PY=python"

:loop
if "%~1"=="" goto done
set "SRC=%~1"
set "DIR=%~dp1"
set "BASE=%~n1"
set "EXT=%~x1"
echo Чищу: %~nx1
%PY% -m mediameta remove "%SRC%" --all --output "%DIR%%BASE%_clean%EXT%"
shift
goto loop

:done
echo.
pause
