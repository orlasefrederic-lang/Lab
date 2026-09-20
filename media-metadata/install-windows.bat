@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

echo ==========================================
echo   Установка mediameta
echo ==========================================
echo.

set "PY="
where py >nul 2>nul
if %errorlevel% equ 0 set "PY=py"
if defined PY goto found
where python >nul 2>nul
if %errorlevel% equ 0 set "PY=python"
if defined PY goto found

echo Python не найден.
echo.
echo Установите его с https://www.python.org/downloads/
echo При установке обязательно отметьте галочку "Add python.exe to PATH".
echo Потом запустите этот файл ещё раз.
echo.
pause
exit /b 1

:found
echo Использую Python: %PY%
%PY% --version
echo.
echo Ставлю пакет и зависимости...
echo.

%PY% -m pip install --upgrade pip
%PY% -m pip install -e .
if errorlevel 1 (
    echo.
    echo Установка не удалась - скопируйте текст ошибки выше.
    pause
    exit /b 1
)

echo.
echo ==========================================
echo   Готово
echo ==========================================
%PY% -m mediameta --version
echo.
echo Примеры:
echo   mediameta show "%USERPROFILE%\Pictures\photo.jpg"
echo   mediameta set "%USERPROFILE%\Pictures\photo.jpg" -s title="Закат"
echo.
echo Если команда mediameta не находится, тот же вызов через Python:
echo   %PY% -m mediameta show "%USERPROFILE%\Pictures\photo.jpg"
echo.
pause
