@echo off
rem Обгортка запуску тестів для Windows. Шлях рахується відносно цього
rem файлу, тому команда працює незалежно від поточної директорії.
setlocal
set "SCRIPT_DIR=%~dp0"
set "TESTS_DIR=%SCRIPT_DIR%..\tests"

where py >nul 2>nul
if %ERRORLEVEL%==0 (
    py -m unittest discover -s "%TESTS_DIR%" %*
) else (
    python -m unittest discover -s "%TESTS_DIR%" %*
)
