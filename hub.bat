@echo off
:: Проверка прав администратора
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :run
) else (
    echo Запуск от имени Администратора...
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

:run
cd /d "%~dp0"
powershell.exe -ExecutionPolicy Bypass -File "%~dp0hub.ps1"
if %errorLevel% neq 0 (
    echo.
    echo Произошла ошибка при выполнении скрипта.
    pause
)
