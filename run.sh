#!/usr/bin/env bash
# Krim Logs — запуск на Linux (Raspberry Pi OS, Debian/Ubuntu, arm64/x86_64).
set -euo pipefail

cd "$(dirname "$0")"

PY="venv/bin/python"

if [ ! -x "$PY" ]; then
    echo "[Krim Logs] venv не найден — создаю..."
    python3 -m venv venv
    "$PY" -m pip install --upgrade pip
fi

if ! "$PY" -c "import discord, dotenv, vosk, numpy; from discord.ext import voice_recv" >/dev/null 2>&1; then
    echo "[Krim Logs] Устанавливаю зависимости..."
    "$PY" -m pip install --upgrade pip
    "$PY" -m pip install -r requirements.txt
fi

if [ ! -f .env ]; then
    echo "[Krim Logs] Внимание: .env не найден — укажите DISCORD_TOKEN в .env" >&2
fi

echo "[Krim Logs] Запуск..."
exec "$PY" Krim_logs.py
