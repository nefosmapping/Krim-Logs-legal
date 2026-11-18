@echo off
setlocal
cd /d "%~dp0"

set "PY=venv\Scripts\python.exe"

if not exist "%PY%" (
    echo [Krim Logs] venv не найден — создаю...
    python -m venv venv || goto :error
)

"%PY%" -c "import discord, dotenv, vosk; from discord.ext import voice_recv" 2>nul
if errorlevel 1 (
    echo [Krim Logs] Устанавливаю зависимости...
    "%PY%" -m pip install --upgrade pip >nul
    "%PY%" -m pip install -r requirements.txt || goto :error
)

echo [Krim Logs] Запуск...
"%PY%" Krim_logs.py
exit /b %errorlevel%

:error
echo [Krim Logs] Не удалось подготовить окружение.
pause
exit /b 1
