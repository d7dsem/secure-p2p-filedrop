@echo off
rem Обгортка запуску тестів для Windows. Шлях рахується відносно цього
rem файлу, тому команда працює незалежно від поточної директорії.
rem Групи по шарах (docs/architecture.md) — усі аргументи передаються далі
rem в tests/_groups.py: назви груп/аліасів, прапорці unittest, дотовані імена.
setlocal
set "SCRIPT_DIR=%~dp0"
set "TESTS_DIR=%SCRIPT_DIR%..\tests"

where py >nul 2>nul
if %ERRORLEVEL%==0 (
    py "%TESTS_DIR%\_groups.py" %*
) else (
    python "%TESTS_DIR%\_groups.py" %*
)
