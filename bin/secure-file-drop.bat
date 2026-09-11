@echo off
rem Обгортка запуску для Windows. Шлях до застосунку рахується відносно
rem цього файлу, тому команда працює незалежно від поточної директорії
rem (зокрема коли bin/ додано в PATH).
setlocal
set "SCRIPT_DIR=%~dp0"
set "ENTRY=%SCRIPT_DIR%..\src\secure_file_drop_entry.py"

where py >nul 2>nul
if %ERRORLEVEL%==0 (
    py "%ENTRY%" %*
) else (
    python "%ENTRY%" %*
)
