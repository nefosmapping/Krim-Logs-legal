"""
Krim Logs — бот для логирования событий Discord + AI-ассистент + Модератор + Транскрипция.

Установка:
  python -m venv venv
  venv\\Scripts\\python.exe -m pip install -r requirements.txt
  # модель распознавания речи положить рядом со скриптом:
  #   vosk-model-small-ru-0.22/   (https://alphacephei.com/vosk/models)

Запуск (только интерпретатором из venv):
  Windows:  run.bat
            либо venv\\Scripts\\python.exe Krim_logs.py
  Linux:    ./run.sh
            либо venv/bin/python Krim_logs.py
            (для режима Zapret — через sudo или с NOPASSWD для nft/nfqws)

Авто-транскрипция войса (config.json):
  "voice_auto": true,
  "voice_guilds": [<ID_сервера>, ...]   # проверяются только эти серверы
Бот сам заходит в голосовой канал, где есть люди, и выходит, когда все ушли.

Обход блокировок Discord (config.json → network):
  "network": {
    "enabled": true,
    "mode": "vless",      # vless | proxy
    "fallback": "proxy"   # proxy | vless | none
  }
  VLESS-подписка вставляется в network.vless.subscription: URL, строка
  vless:// или список строк. Подробнее — PROXY_SETUP.md.
"""

from __future__ import annotations

import asyncio
import copy
import difflib
import html as html_module
import json
import logging
import os
import re
import socket
import sqlite3
import sys
import time
import io
import numpy as np
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

try:
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass


def _startup_error(lines: list[str]) -> None:
    """Диагностика латиницей — читается в консоли с любой кодировкой."""
    sys.stderr.write("\n[Krim Logs] " + "\n".join(lines) + "\n")


try:
    import aiohttp
    import discord
    from discord.ext import voice_recv
    import vosk
    from dotenv import load_dotenv
except (ModuleNotFoundError, ImportError) as exc:  # зависимость не установлена
    _startup_error([
        f"missing dependency: {getattr(exc, 'name', None) or exc}",
        f"current interpreter: {sys.executable}",
        "",
        "Note: voice_recv requires the 'discord-ext-voice-recv' package,",
        "vosk requires 'vosk', voice support requires 'PyNaCl'.",
        "",
        "Install all requirements into the active environment:",
        "  python -m pip install -r requirements.txt",
        "",
        "or run the bot from venv:",
        "  venv\\Scripts\\python.exe -m pip install -r requirements.txt",
        "  run.bat",
    ])
    raise SystemExit(1) from exc

if not hasattr(discord, "Intents"):
    # discord.py-self и старый пакет "discord" тоже импортируются как discord,
    # но несовместимы с discord.py.
    _startup_error([
        "incompatible 'discord' package found:",
        f"  file:     {getattr(discord, '__file__', '?')}",
        f"  version:  {getattr(discord, '__version__', 'unknown')}",
        f"  python:   {sys.executable}",
        "",
        "Install discord.py instead of a fork:",
        "  python -m pip uninstall -y discord.py-self discord.py discord",
        "  python -m pip install -r requirements.txt",
    ])
    raise SystemExit(1)

try:
    from netbypass import (
        DEFAULT_VLESS_EXTRA_SOURCES,
        DEFAULT_VLESS_KEY_INDEX,
        DIRECT_MODE,
        NetBypassManager,
    )
except ImportError as exc:  # модуль обхода отсутствует или повреждён
    _startup_error([
        f"missing module: netbypass ({exc})",
        "",
        "Файл netbypass.py должен лежать рядом с Krim_logs.py.",
        f"current interpreter: {sys.executable}",
    ])
    raise SystemExit(1) from exc

# ---------- Пути ----------

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
DATA_DIR = BASE_DIR / "data"
DOSSIER_DIR = BASE_DIR / "dossiers"
CONFIG_FILE = BASE_DIR / "config.json"
AI_CONFIG_FILE = BASE_DIR / "ai_config.json"
DB_PATH = DATA_DIR / "krim.db"
VOSK_MODEL_PATH = BASE_DIR / "vosk-model-small-ru-0.22"

SESSION_KEEP = 2
MESSAGE_LIMIT = 1900
CONTENT_LIMIT = 900
BLOCKED_NOTICE_INTERVAL = 300

load_dotenv(BASE_DIR / ".env")

TOKEN = os.getenv("DISCORD_TOKEN")
AI_API_KEY = os.getenv("AI_API_KEY", "")
ADMIN_IDS: set[int] = {
    int(x.strip())
    for x in os.getenv("ADMIN_IDS", "").split(",")
    if x.strip().isdigit()
}

SESSION_FILE: Path = LOG_DIR / "krim_logs.log"

# ---------- Конфиг ----------
log_channel_id: Optional[int] = None
emperial_id: Optional[int] = None
guilds_config: dict = {}
ai_config: dict = {}
network_config: dict = {}
proxy_manager: Optional[NetBypassManager] = None

# Авто-транскрипция: бот сам заходит в войс, но только на разрешённых серверах.
voice_guild_ids: set[int] = set()
voice_auto_enabled: bool = True

DEFAULT_AI_CONFIG = {
    "model": "gpt-4o-mini",
    "base_url": "https://api.relaymodels.com/v1",
    "max_tokens": 1200,
    "temperature": 0.7,
    "context_limit": 20,
    # DeepNeuro: первичная быстрая модель (Mini) и сильная модель.
    "deep_mini_enabled": True,
    "deep_mini_model": "gpt-4o-mini",
    "deep_mini_max_tokens": 900,
    "deep_mini_temperature": 0.7,
    "deep_mini_timeout": 90,
    "deep_mini_system_prompt": (
        "Ты — Krim DeepNeuro Mini, первичная быстрая модель. "
        "Твоя задача — предложить черновой вариант решения или несколько идей. "
        "Не претендуй на финальный ответ: твой результат будет передан "
        "более сильной модели Krim DeepNeuro."
    ),
    "deep_model": "gpt-4o",
    "deep_max_tokens": 2000,
    "deep_temperature": 0.5,
    "deep_timeout": 180,
    "deep_system_prompt": (
        "Ты — Krim DeepNeuro, сильная модель глубокого рассуждения. "
        "Ты получаешь задачу пользователя и, если есть, черновик от Krim DeepNeuro Mini. "
        "Критически проверь черновик, исправь ошибки, углубь анализ. "
        "Решай задачу пошагово, проверяй предположения, отделяй факты от догадок. "
        "Если данных не хватает — прямо скажи об этом. "
        "Финальный ответ должен быть структурированным, практичным и без воды."
    ),
    "politeness": {
        "initial": 100,
        "max": 100,
        "min": 0,
        "critical_threshold": 20,
        "restore_on_apology": 100,
        "apology_words": ["извин", "прости", "прощу", "сорри", "sorry", "apolog", "виноват"],
    },
    "system_prompt": "Ты — {bot_name} (Логгер), вежливый ассистент-кибербезопасник. Твой ID: {bot_id}. Собеседник: {name} (ID {id})."
}

# ---------- Сетевой обход (VLESS / HTTPS-прокси) ----------
# enabled=false  — работаем напрямую (как раньше, нужен системный VPN);
# enabled=true   — трафик Discord идёт через выбранный обход.
# mode="vless"   — подписка VLESS + автоматический Xray-core;
# mode="proxy"   — поиск быстрых HTTPS-прокси, активный + 4 запасных.
DEFAULT_NETWORK_CONFIG = {
    "enabled": False,
    "mode": "vless",
    # Порядок резервных режимов: vless → zapret → proxy.
    "fallback": ["zapret", "proxy"],
    "health_interval": 60,
    "vless": {
        "subscription": "https://warp-gen.cyb-portal.org/CP-040",
        "extra_sources": list(DEFAULT_VLESS_EXTRA_SOURCES),
        "keys_index": DEFAULT_VLESS_KEY_INDEX,
        "subscription_file": "",
        "subscription_url": "",
        "core_path": "",
        "auto_download": True,
        "local_port": 0,
        "max_attempts": 0,
        "startup_timeout": 8,
        "test_timeout": 15,
        "probe_concurrency": 6,
    },
    "zapret": {
        "base_dir": "",
        "core_path": "",
        "strategy": "general.bat",
        "interface": "",
        "max_strategies": 4,
    },
    "proxy": {
        "sources": [
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
            "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt",
            "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
            "https://api.openproxylist.xyz/http.txt",
            "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&proxy_format=ipport&format=text&timeout=10000",
            "https://www.proxy-list.download/api/v1/get?type=https",
            "https://proxyspace.pro/https.txt",
        ],
        "pool_size": 4,
        "test_url": "https://discord.com/api/v10/gateway",
        "test_timeout": 8,
        "verify_attempts": 2,
        "max_candidates": 300,
        "cache_limit": 50,
        "concurrency": 60,
        "refresh_minutes": 30,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Рекурсивно накладывает пользовательский конфиг на дефолтный."""
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result

def load_ai_config() -> None:
    """Читает ai_config.json и дополняет его новыми ключами из дефолта."""
    global ai_config
    if AI_CONFIG_FILE.exists():
        try:
            with AI_CONFIG_FILE.open("r", encoding="utf-8") as fp:
                data = json.load(fp)
            if isinstance(data, dict):
                merged = _deep_merge(copy.deepcopy(DEFAULT_AI_CONFIG), data)
                ai_config = merged
                if merged != data:
                    try:
                        with AI_CONFIG_FILE.open("w", encoding="utf-8") as fp:
                            json.dump(merged, fp, ensure_ascii=False, indent=2)
                    except OSError:
                        pass
                return
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Не удалось прочитать ai_config.json: %s — используется дефолт", exc)
    ai_config = copy.deepcopy(DEFAULT_AI_CONFIG)
    try:
        with AI_CONFIG_FILE.open("w", encoding="utf-8") as fp:
            json.dump(ai_config, fp, ensure_ascii=False, indent=2)
    except OSError:
        pass

def load_config() -> None:
    global log_channel_id, emperial_id, guilds_config, voice_guild_ids, voice_auto_enabled, network_config
    network_config = copy.deepcopy(DEFAULT_NETWORK_CONFIG)
    if not CONFIG_FILE.exists():
        save_config()  # создаём конфиг с секцией network, чтобы её можно было включить
        return
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as fp:
            data = json.load(fp)
    except (OSError, json.JSONDecodeError):
        return

    if not isinstance(data, dict):
        return

    if isinstance(data.get("log_channel_id"), int):
        log_channel_id = data["log_channel_id"]
    if isinstance(data.get("emperial_id"), int):
        emperial_id = data["emperial_id"]
    if isinstance(data.get("guilds"), dict):
        guilds_config = data["guilds"]

    need_save = False
    raw_voice = data.get("voice_guilds")
    if isinstance(raw_voice, list):
        parsed: set[int] = set()
        for x in raw_voice:
            try:
                parsed.add(int(x))
            except (TypeError, ValueError):
                continue
        voice_guild_ids = parsed
    else:
        need_save = True

    if isinstance(data.get("voice_auto"), bool):
        voice_auto_enabled = data["voice_auto"]
    else:
        need_save = True

    raw_network = data.get("network")
    if isinstance(raw_network, dict):
        network_config = _deep_merge(copy.deepcopy(DEFAULT_NETWORK_CONFIG), raw_network)
    else:
        need_save = True

    if need_save:  # дозаписываем новые поля, чтобы их было видно в config.json
        save_config()

def save_config() -> None:
    payload = {
        "log_channel_id": log_channel_id,
        "emperial_id": emperial_id,
        "guilds": guilds_config,
        "voice_auto": voice_auto_enabled,
        "voice_guilds": sorted(voice_guild_ids),
        "network": network_config,
    }
    tmp = CONFIG_FILE.with_name(CONFIG_FILE.name + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as fp:
            json.dump(payload, fp, ensure_ascii=False, indent=2)
        tmp.replace(CONFIG_FILE)
    except OSError as exc:
        log.error("Не удалось сохранить config.json: %s", exc)

# ---------- Логирование ----------
def _prune_sessions(keep: int = SESSION_KEEP) -> None:
    try:
        files = sorted(LOG_DIR.glob("krim_logs_*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return
    for old in files[keep:]:
        try:
            old.unlink()
        except OSError:
            pass

def setup_logging() -> logging.Logger:
    global SESSION_FILE
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    SESSION_FILE = LOG_DIR / f"krim_logs_{datetime.now():%Y-%m-%d_%H-%M-%S}.log"

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = logging.FileHandler(SESSION_FILE, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)

    lg = logging.getLogger("krim")
    lg.setLevel(logging.DEBUG)
    lg.addHandler(fh)
    lg.addHandler(ch)
    lg.propagate = False

    dl = logging.getLogger("discord")
    dl.setLevel(logging.WARNING)
    dl.addHandler(fh)
    dl.addHandler(ch)
    dl.propagate = False

    _prune_sessions()

    def _hook(t, e, tb):
        lg.critical("Необработанное исключение", exc_info=(t, e, tb))
        sys.__excepthook__(t, e, tb)

    sys.excepthook = _hook
    return lg

log = setup_logging()
load_ai_config()

# ---------- Vosk ----------
try:
    vosk.SetLogLevel(-1)
    log.info("Загрузка модели Vosk...")
    vosk_model = vosk.Model(str(VOSK_MODEL_PATH))
    log.info("Модель Vosk успешно загружена.")
except Exception as e:
    log.error(f"Ошибка загрузки Vosk: {e}. Убедитесь, что папка {VOSK_MODEL_PATH.name} лежит рядом с ботом.")
    vosk_model = None

# ---------- БД ----------
def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS ai_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, bot_id INTEGER, 
                channel_id INTEGER, role TEXT, content TEXT, timestamp REAL, in_context INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS user_state (
                user_id INTEGER PRIMARY KEY, politeness INTEGER DEFAULT 100, is_blocked INTEGER DEFAULT 0, updated_at REAL
            );
            CREATE TABLE IF NOT EXISTS active_mutes (
                guild_id INTEGER, user_id INTEGER, unmute_at REAL, PRIMARY KEY (guild_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS voice_transcripts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER, channel_id INTEGER, channel_name TEXT,
                user_id INTEGER, user_name TEXT, user_avatar TEXT, text TEXT, timestamp REAL
            );
        """)
        conn.commit()
    finally:
        conn.close()

async def db_execute(sql: str, params: tuple = ()):
    def _run():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(sql, params)
            head = sql.strip().upper()
            if head.startswith("SELECT") or head.startswith("WITH"):
                return [dict(r) for r in cur.fetchall()]
            conn.commit()
            return None
        finally:
            conn.close()

    try:
        return await asyncio.to_thread(_run)
    except sqlite3.OperationalError as exc:
        # Схема могла быть удалена или БД создана впервые — поднимаем её и повторяем.
        if "no such table" in str(exc).lower():
            log.warning("Схема БД отсутствует — создаю таблицы заново (%s)", exc)
            init_db()
            return await asyncio.to_thread(_run)
        raise

async def save_ai_message(user_id: int, bot_id: int, channel_id: int, role: str, content: str) -> None:
    await db_execute(
        "INSERT INTO ai_messages(user_id, bot_id, channel_id, role, content, timestamp, in_context) VALUES (?,?,?,?,?,?,1)",
        (user_id, bot_id, channel_id, role, content, time.time()),
    )

async def get_context(user_id: int, bot_id: int, channel_id: int, limit: int) -> list[dict]:
    rows = await db_execute(
        "SELECT role, content FROM ai_messages WHERE user_id=? AND bot_id=? AND channel_id=? AND in_context=1 ORDER BY id DESC LIMIT ?",
        (user_id, bot_id, channel_id, limit),
    )
    if not rows: return []
    rows.reverse()
    return [{"role": r["role"], "content": r["content"]} for r in rows]

async def clear_context(user_id: int) -> None:
    await db_execute("UPDATE ai_messages SET in_context=0 WHERE user_id=?", (user_id,))

async def get_ai_counts(user_id: int, bot_id: int) -> dict[str, int]:
    rows = await db_execute("SELECT role, COUNT(*) as cnt FROM ai_messages WHERE user_id=? AND bot_id=? GROUP BY role", (user_id, bot_id))
    counts = {"user": 0, "assistant": 0}
    for r in rows: counts[r["role"]] = r["cnt"]
    return counts

# ---------- Состояние пользователя ----------
async def get_user_state(user_id: int) -> dict:
    rows = await db_execute("SELECT politeness, is_blocked FROM user_state WHERE user_id=?", (user_id,))
    if rows: return {"politeness": rows[0]["politeness"], "is_blocked": bool(rows[0]["is_blocked"])}
    return {"politeness": ai_config.get("politeness", {}).get("initial", 100), "is_blocked": False}

async def set_politeness(user_id: int, value: int) -> int:
    pol_cfg = ai_config.get("politeness", {})
    lo, hi = pol_cfg.get("min", 0), pol_cfg.get("max", 100)
    value = max(lo, min(hi, value))
    await db_execute(
        "INSERT INTO user_state(user_id, politeness, is_blocked, updated_at) VALUES(?, ?, 0, ?) "
        "ON CONFLICT(user_id) DO UPDATE SET politeness=excluded.politeness, updated_at=excluded.updated_at",
        (user_id, value, time.time()),
    )
    return value

async def adjust_politeness(user_id: int, delta: int) -> int:
    st = await get_user_state(user_id)
    return await set_politeness(user_id, st["politeness"] + delta)

async def set_user_blocked(user_id: int, blocked: bool) -> None:
    initial = ai_config.get("politeness", {}).get("initial", 100)
    await db_execute(
        "INSERT INTO user_state(user_id, politeness, is_blocked, updated_at) VALUES(?, ?, ?, ?) "
        "ON CONFLICT(user_id) DO UPDATE SET is_blocked=excluded.is_blocked, updated_at=excluded.updated_at",
        (user_id, initial, 1 if blocked else 0, time.time()),
    )

def detect_apology(text: str) -> bool:
    if not text: return False
    low = text.lower()
    return any(w.lower() in low for w in ai_config.get("politeness", {}).get("apology_words", []))

# ---------- Транскрипция (Sink) ----------

VOSK_RATE = 16000

def pcm_to_vosk(pcm: bytes, in_rate: int = 48000) -> bytes:
    """Конвертирует PCM 48кГц Stereo s16le (от Discord) в 16кГц Mono s16le (для Vosk)."""
    if not pcm:
        return b""
    try:
        # Переводим байты в массив numpy (16-битные целые)
        audio_array = np.frombuffer(pcm, dtype=np.int16)
        
        # Если количество сэмплов нечетное (битый пакет) — отрезаем хвост
        if len(audio_array) % 2 != 0:
            audio_array = audio_array[:-1]
            
        # Стерео -> Моно (усредняем левый и правый каналы)
        audio_array = audio_array.reshape(-1, 2).mean(axis=1).astype(np.int16)
        
        # 48000 Гц -> 16000 Гц (берем каждый 3-й сэмпл)
        # Для распознавания речи это работает отлично
        if in_rate == 48000:
            audio_array = audio_array[::3]
            
        return audio_array.tobytes()
    except Exception as e:
        log.error("Ошибка конвертации аудио: %s", e)
        return b""


class TranscriptionSink(voice_recv.AudioSink):
    def __init__(self):
        super().__init__()
        self.recognizers: dict[int, vosk.KaldiRecognizer] = {}

    def wants_opus(self) -> bool:
        return False

    def cleanup(self) -> None:
        self.recognizers.clear()

    def write(self, user: Optional[discord.User], data: voice_recv.VoiceData):
        if not user or not vosk_model:
            return
        if client.user and user.id == client.user.id:
            return

        # ОТЛАДКА: выводим в консоль, что пакет от пользователя получен
        # (Отключи этот print, когда убедишься, что всё работает)
        # log.debug("Получен аудио-пакет от %s", user.display_name)

        try:
            pcm = pcm_to_vosk(data.pcm)
            if not pcm:
                return
                
            rec = self.recognizers.get(user.id)
            if rec is None:
                rec = self.recognizers[user.id] = vosk.KaldiRecognizer(vosk_model, VOSK_RATE)
            
            # AcceptWaveform возвращает True, когда Vosk накапливает достаточно звука и слышит паузу
            if rec.AcceptWaveform(pcm):
                text = (json.loads(rec.Result()).get("text") or "").strip()
                if text:
                    log.info("Vosk РАСПОЗНАЛ [%s]: %s", user.display_name, text)
                    asyncio.run_coroutine_threadsafe(
                        self.process_text(user, text), client.loop
                    )
        except Exception:
            log.exception("Ошибка распознавания речи (%s)", getattr(user, "id", "?"))
            
    # process_text оставляем без изменений
    async def process_text(self, user: discord.User, text: str) -> None:
        # data.source — это пользователь, а не канал: канал берём у voice-клиента
        channel = getattr(self.voice_client, "channel", None)
        if channel is None:
            return
        try:
            avatar = getattr(getattr(user, "display_avatar", None), "url", "")
            await db_execute(
                "INSERT INTO voice_transcripts (guild_id, channel_id, channel_name, user_id, user_name, user_avatar, text, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    channel.guild.id,
                    channel.id,
                    channel.name,
                    user.id,
                    getattr(user, "display_name", str(user)),
                    avatar,
                    text,
                    time.time(),
                ),
            )
            await generate_transcript_html()
        except Exception:
            log.exception("Ошибка сохранения транскрипта (%s)", user.id)

# ---------- HTML Транскрипт ----------
async def generate_transcript_html():
    rows = await db_execute("SELECT * FROM voice_transcripts ORDER BY timestamp DESC LIMIT 1000")
    
    html_parts = []
    if rows:
        days_data = {}
        for r in rows:
            dt = datetime.fromtimestamp(r["timestamp"])
            day_str = dt.strftime("%d %B %Y")
            if day_str not in days_data:
                days_data[day_str] = []
            days_data[day_str].append(r)

        for i, (day, msgs) in enumerate(days_data.items()):
            msgs_html = ""
            for m in reversed(msgs):
                time_str = datetime.fromtimestamp(m["timestamp"]).strftime("%H:%M:%S")
                msgs_html += f"""
                <div class="message">
                    <img class="avatar" src="{m['user_avatar']}">
                    <div class="msg-body">
                        <div class="msg-header">
                            <span class="author">{html_module.escape(m['user_name'])}</span>
                            <span class="channel-badge">🔊 {html_module.escape(m['channel_name'])}</span>
                            <span class="time">{time_str}</span>
                        </div>
                        <div class="text">{html_module.escape(m['text'])}</div>
                    </div>
                </div>"""
                
            open_attr = "open" if i == 0 else ""
            html_parts.append(f"""
            <details {open_attr}>
                <summary><span>{day}</span><span class="arrow">▶</span></summary>
                <div class="day-content">{msgs_html}</div>
            </details>""")
    else:
        html_parts.append("<p style='color: #949ba4; text-align: center; padding: 20px;'>Пока нет распознанных реплик. Зайдите в войс и начните говорить.</p>")

    full_html = f"""<!DOCTYPE html>
    <html lang="ru">
    <head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="30">
    <title>Krim Logs — Транскрипция</title>
    <style>
      :root {{ --bg: #313338; --bg-secondary: #2b2d31; --bg-tertiary: #1e1f22; --text: #dbdee1; --muted: #949ba4; --accent: #5865f2; --border: #3f4147; }}
      body {{ font-family: 'gg sans', sans-serif; background: var(--bg); color: var(--text); padding: 40px 20px; margin: 0; }}
      .container {{ max-width: 900px; margin: 0 auto; }}
      .header h1 {{ color: #fff; margin-bottom: 8px; }}
      .header p {{ color: var(--muted); font-size: 14px; margin-bottom: 30px; }}
      details {{ background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 16px; }}
      summary {{ padding: 16px 20px; font-weight: 600; color: #fff; cursor: pointer; background: var(--bg-tertiary); display: flex; justify-content: space-between; align-items: center; border-radius: 8px; }}
      details[open] summary {{ border-radius: 8px 8px 0 0; border-bottom: 1px solid var(--border); }}
      summary::-webkit-details-marker {{ display: none; }}
      .arrow {{ transition: transform 0.2s; font-size: 12px; color: var(--muted); }}
      details[open] .arrow {{ transform: rotate(90deg); }}
      .day-content {{ padding: 20px; display: flex; flex-direction: column; gap: 16px; }}
      .message {{ display: flex; gap: 16px; padding: 8px; border-radius: 6px; }}
      .message:hover {{ background: rgba(0,0,0,0.1); }}
      .avatar {{ width: 40px; height: 40px; border-radius: 50%; }}
      .msg-body {{ flex: 1; }}
      .msg-header {{ display: flex; align-items: baseline; gap: 8px; margin-bottom: 4px; }}
      .author {{ color: #fff; font-weight: 500; font-size: 15px; }}
      .channel-badge {{ background: rgba(88,101,242,0.15); color: #7983f5; font-size: 11px; padding: 2px 6px; border-radius: 4px; font-weight: 600; }}
      .time {{ color: var(--muted); font-size: 12px; }}
      .text {{ font-size: 15px; line-height: 1.4; }}
    </style>
    </head>
    <body>
    <div class="container">
      <div class="header">
        <h1>Аудио-транскрипция</h1>
        <p>История распознанных реплик (авто-обновление каждые 30 сек)</p>
      </div>
      {"".join(html_parts)}
    </div>
    </body>
    </html>"""
    
    path = DATA_DIR / "voice_transcript.html"
    path.write_text(full_html, encoding="utf-8")

# ---------- Модерация ----------
def parse_duration(dur_str: str) -> int:
    m = re.match(r"^(\d+)([mhd])$", dur_str.lower())
    if not m: return 0
    val, unit = int(m.group(1)), m.group(2)
    if unit == 'm': return val * 60
    if unit == 'h': return val * 3600
    if unit == 'd': return val * 86400
    return 0

async def apply_mute(guild: discord.Guild, member: discord.Member, duration_sec: int, reason: str = "Krim Logs"):
    cfg = guilds_config.get(str(guild.id))
    if not cfg: return False, "Сервер не настроен в config.json для мутов."

    unmute_at = time.time() + duration_sec
    mode = cfg.get("mode", "role")
    
    if mode == "role":
        role_id = cfg.get("mute_role_id")
        if not role_id: return False, "Не указан ID роли для мутов."
        role = guild.get_role(role_id)
        if not role: return False, "Роль для мутов не найдена."
        try:
            await member.add_roles(role, reason=reason)
        except discord.Forbidden:
            return False, "У бота нет прав на выдачу роли (или роль бота ниже)."
    elif mode == "permissions":
        try:
            await member.timeout(timedelta(seconds=duration_sec), reason=reason)
        except discord.Forbidden:
            return False, "У бота нет прав на тайм-аут участников."

    await db_execute("INSERT INTO active_mutes(guild_id, user_id, unmute_at) VALUES (?, ?, ?) ON CONFLICT(guild_id, user_id) DO UPDATE SET unmute_at=excluded.unmute_at", (guild.id, member.id, unmute_at))
    asyncio.create_task(unmute_later(guild, member.id, duration_sec))
    return True, "OK"

async def remove_mute(guild: discord.Guild, member: discord.Member, reason: str = "Krim Logs Unmute"):
    cfg = guilds_config.get(str(guild.id))
    if not cfg: return False, "Сервер не настроен в config.json."

    mode = cfg.get("mode", "role")
    if mode == "role":
        role_id = cfg.get("mute_role_id")
        if role_id:
            role = guild.get_role(role_id)
            if role and role in member.roles:
                try: await member.remove_roles(role, reason=reason)
                except discord.Forbidden: return False, "Нет прав на снятие роли."
    elif mode == "permissions":
        try: await member.timeout(None, reason=reason)
        except discord.Forbidden: return False, "Нет прав на снятие тайм-аута."

    await db_execute("DELETE FROM active_mutes WHERE guild_id=? AND user_id=?", (guild.id, member.id))
    return True, "OK"

async def unmute_later(guild: discord.Guild, user_id: int, delay: int):
    await asyncio.sleep(delay)
    member = guild.get_member(user_id)
    if member: await remove_mute(guild, member, reason="Время мута истекло")

async def check_mute_status(guild: discord.Guild, member: discord.Member) -> bool:
    cfg = guilds_config.get(str(guild.id))
    if not cfg: return False
    mode = cfg.get("mode", "role")
    if mode == "role":
        role_id = cfg.get("mute_role_id")
        if role_id:
            role = guild.get_role(role_id)
            return role in member.roles if role else False
    elif mode == "permissions":
        return member.is_timed_out()
    return False

async def generate_chat_log_html(messages: list[discord.Message]) -> str:
    msgs_html = []
    for msg in reversed(messages):
        avatar = msg.author.display_avatar.url
        name = html_module.escape(msg.author.display_name)
        color = f"#{msg.author.color.value:06x}" if hasattr(msg.author, "color") and msg.author.color.value != 0 else "#ffffff"
        time_str = msg.created_at.strftime("%d.%m.%Y %H:%M")
        content = html_module.escape(msg.content)
        
        content = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", content)
        content = re.sub(r"\*(.+?)\*", r"<i>\1</i>", content)
        content = re.sub(r"__(.+?)__", r"<u>\1</u>", content)
        content = re.sub(r"`(.+?)`", r"<code>\1</code>", content)
        content = re.sub(r"```(.*?)```", r"<pre><code>\1</code></pre>", content, flags=re.DOTALL)
        content = content.replace("\n", "<br>")

        attachments = "".join(f'<div class="attachment"><a href="{att.url}" target="_blank">{att.filename}</a></div>' for att in msg.attachments)
        bot_tag = '<span class="bot-tag">BOT</span>' if msg.author.bot else ""

        msgs_html.append(f"""
        <div class="message">
            <img class="avatar" src="{avatar}">
            <div class="msg-content">
                <div class="msg-header">
                    <span class="author" style="color: {color};">{name}</span>{bot_tag}
                    <span class="time">{time_str}</span>
                </div>
                <div class="text">{content} {attachments}</div>
            </div>
        </div>""")

    return f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8"><title>Удаленный чат</title>
<style>
  body {{ background-color: #313338; color: #dbdee1; font-family: sans-serif; margin: 0; padding: 20px; }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  .message {{ display: flex; margin-bottom: 17px; }}
  .avatar {{ width: 40px; height: 40px; border-radius: 50%; margin-right: 16px; }}
  .msg-content {{ flex: 1; }}
  .msg-header {{ display: flex; align-items: baseline; margin-bottom: 4px; }}
  .author {{ font-weight: 500; font-size: 16px; margin-right: 8px; }}
  .time {{ color: #949ba4; font-size: 12px; margin-left: 8px; }}
  .bot-tag {{ background-color: #5865f2; color: #fff; font-size: 10px; padding: 1px 4px; border-radius: 3px; text-transform: uppercase; font-weight: 600; }}
  .text {{ font-size: 16px; line-height: 1.375; }}
  code {{ background-color: #2b2d31; padding: 2px 4px; border-radius: 3px; }}
  pre {{ background-color: #2b2d31; padding: 10px; border-radius: 4px; }}
</style></head><body><div class="container">{"".join(msgs_html)}</div></body></html>"""

# ---------- StatsStorage ----------
class StatsStorage:
    def __init__(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        DOSSIER_DIR.mkdir(parents=True, exist_ok=True)
        self.users_file = DATA_DIR / "users.json"
        self.messages_file = DATA_DIR / "messages.jsonl"
        self.voice_file = DATA_DIR / "voice.jsonl"
        self.active_file = DATA_DIR / "active_voice.json"
        self.users: dict[str, dict] = {}
        self.active_sessions: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if self.users_file.exists():
            try:
                with self.users_file.open("r", encoding="utf-8") as fp:
                    self.users = json.load(fp).get("users", {})
            except: self.users = {}
        if self.active_file.exists():
            try:
                with self.active_file.open("r", encoding="utf-8") as fp:
                    self.active_sessions = json.load(fp)
            except: self.active_sessions = {}

    def _save_users(self) -> None:
        tmp = self.users_file.with_name(self.users_file.name + ".tmp")
        try:
            with tmp.open("w", encoding="utf-8") as fp:
                json.dump({"users": self.users}, fp, ensure_ascii=False, indent=2)
            tmp.replace(self.users_file)
        except: pass

    def _save_active(self) -> None:
        tmp = self.active_file.with_name(self.active_file.name + ".tmp")
        try:
            with tmp.open("w", encoding="utf-8") as fp:
                json.dump(self.active_sessions, fp, ensure_ascii=False, indent=2)
            tmp.replace(self.active_file)
        except: pass

    def update_user(self, user) -> dict:
        uid = str(user.id)
        avatar = user.display_avatar.url if getattr(user, "display_avatar", None) else ""
        first_seen = self.users.get(uid, {}).get("first_seen", time.time())
        info = {
            "id": uid, "name": str(user), "display_name": getattr(user, "display_name", str(user)),
            "avatar": avatar, "first_seen": first_seen,
            "created_at": user.created_at.timestamp() if getattr(user, "created_at", None) else None,
            "joined_at": user.joined_at.timestamp() if getattr(user, "joined_at", None) else None,
            "roles": [r.name for r in getattr(user, "roles", []) if r.name != "@everyone"],
        }
        if self.users.get(uid) != info:
            self.users[uid] = info
            self._save_users()
        return info

    def record_message(self, user) -> None:
        try:
            with self.messages_file.open("a", encoding="utf-8") as fp:
                fp.write(json.dumps({"uid": str(user.id), "ts": time.time()}, ensure_ascii=False) + "\n")
        except: pass

    def start_voice(self, user, channel) -> dict:
        uid = str(user.id)
        session = {"channel_id": str(channel.id), "channel_name": getattr(channel, "name", "?"), "start": time.time()}
        self.active_sessions[uid] = session
        self._save_active()
        return session

    def end_voice(self, user_or_id, end_ts: Optional[float] = None) -> Optional[float]:
        uid = str(user_or_id.id) if hasattr(user_or_id, "id") else str(user_or_id)
        session = self.active_sessions.pop(uid, None)
        if session is None: return None
        end_ts = end_ts or time.time()
        try:
            with self.voice_file.open("a", encoding="utf-8") as fp:
                fp.write(json.dumps({"uid": uid, "cid": session["channel_id"], "cname": session["channel_name"], "start": session["start"], "end": end_ts}, ensure_ascii=False) + "\n")
        except: pass
        self._save_active()
        return end_ts - session["start"]

    def get_stats(self, user_id) -> tuple[dict[str, int], dict[str, float]]:
        uid = str(user_id)
        now = time.time()
        periods = {"day": now - 86400, "week": now - 7 * 86400, "month": now - 30 * 86400, "year": now - 365 * 86400, "five_years": now - 5 * 365 * 86400}
        msg_counts = {k: 0 for k in periods}
        voice_seconds = {k: 0.0 for k in periods}

        if self.messages_file.exists():
            try:
                with self.messages_file.open("r", encoding="utf-8") as fp:
                    for line in fp:
                        try: d = json.loads(line)
                        except: continue
                        if d.get("uid") != uid: continue
                        for k, start in periods.items():
                            if d.get("ts", 0) >= start: msg_counts[k] += 1
            except: pass

        if self.voice_file.exists():
            try:
                with self.voice_file.open("r", encoding="utf-8") as fp:
                    for line in fp:
                        try: d = json.loads(line)
                        except: continue
                        if d.get("uid") != uid: continue
                        s, e = d.get("start", 0), d.get("end", 0)
                        for k, pstart in periods.items():
                            if max(e, pstart) > max(s, pstart): voice_seconds[k] += max(e, pstart) - max(s, pstart)
            except: pass

        active = self.active_sessions.get(uid)
        if active:
            s, e = active["start"], now
            for k, pstart in periods.items():
                if e > max(s, pstart): voice_seconds[k] += e - max(s, pstart)

        return msg_counts, voice_seconds

stats = StatsStorage()

# ---------- Совместимость с voice_recv ----------

def enable_dave_decryption() -> None:
    """
    voice_recv не расшифровывает DAVE (E2EE). Патчим PacketRouter.feed_rtp,
    чтобы прогонять payload через встроенный метод discord.py.
    """
    try:
        from discord.ext.voice_recv import router as vr_router
    except Exception:
        log.warning("voice_recv не найден", exc_info=True)
        return

    original_feed_rtp = vr_router.PacketRouter.feed_rtp
    if getattr(original_feed_rtp, "_krim_dave", False):
        return

    warned_ssrc: set[int] = set()

    def feed_rtp(self, packet) -> None:
        try:
            state = getattr(self.reader.voice_client, "_connection", None)
            if state and getattr(state, "dave_session", None) and getattr(state, "dave_protocol_version", 0) > 0:
                user_id = self.reader.voice_client._get_id_from_ssrc(packet.ssrc)
                if user_id:
                    if hasattr(state, "_decrypt_dave_packet"):
                        # Просто вызываем метод, он меняет packet.decrypted_data "на месте"
                        state._decrypt_dave_packet(user_id, packet)
                    else:
                        # Фоллбек для старых версий discord.py
                        import davey
                        decrypted = state.dave_session.decrypt(user_id, davey.MediaType.audio, packet.decrypted_data)
                        if not decrypted:
                            return
                        packet.decrypted_data = decrypted
        except Exception as exc:
            if packet.ssrc not in warned_ssrc:
                warned_ssrc.add(packet.ssrc)
                log.debug("DAVE-дешифровка пропущена (ssrc %s): %s", packet.ssrc, exc)
            return # Пропускаем битый пакет
        
        return original_feed_rtp(self, packet)

    feed_rtp._krim_dave = True  # type: ignore[attr-defined]
    vr_router.PacketRouter.feed_rtp = feed_rtp  # type: ignore[assignment]
    log.info("DAVE-дешифровка активирована (исправленный метод discord.py)")


# ---------- Защита от двойного запуска ----------

_instance_lock = None


def acquire_single_instance_lock() -> bool:
    """Не даёт запустить второй экземпляр: иначе бот отвечает на сообщения дважды."""
    global _instance_lock
    lock_path = BASE_DIR / "krim_logs.lock"
    try:
        handle = open(lock_path, "a+")
    except OSError as exc:
        log.warning("Не удалось открыть lock-файл %s: %s", lock_path, exc)
        return True
    try:
        if os.name == "nt":
            import msvcrt
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return False
    try:
        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()))
        handle.flush()
    except OSError:
        pass
    _instance_lock = handle  # держим файл открытым на всё время работы
    return True


# ---------- Клиент ----------
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
intents.voice_states = True
intents.guilds = True

client = discord.Client(intents=intents)
tree = discord.app_commands.CommandTree(client)

# ---------- Авто-транскрипция войса ----------

VOICE_CHECK_INTERVAL = 10      # как часто проверяем голосовые каналы (сек)
VOICE_CONNECT_RETRY = 60       # пауза после неудачного подключения к каналу (сек)

voice_auto_task: Optional[asyncio.Task] = None
_voice_fail_at: dict[int, float] = {}


def humans_in(channel) -> int:
    """Сколько живых (не ботов) участников в голосовом канале."""
    return sum(1 for m in getattr(channel, "members", []) if not m.bot)


def pick_voice_channel(guild):
    """Первый голосовой канал сервера, где есть люди. AFK-канал пропускаем."""
    afk_id = getattr(getattr(guild, "afk_channel", None), "id", None)
    for channel in guild.voice_channels:
        if afk_id and channel.id == afk_id:
            continue
        if humans_in(channel) > 0:
            return channel
    return None


async def disconnect_voice(vc) -> None:
    try:
        if getattr(vc, "is_listening", lambda: False)():
            vc.stop_listening()
    except Exception:
        log.debug("stop_listening завершился с ошибкой", exc_info=True)
    try:
        await vc.disconnect(force=True)
    except Exception:
        log.debug("Не удалось отключить voice-клиент", exc_info=True)


async def connect_voice(guild, channel) -> None:
    try:
        vc = await channel.connect(cls=voice_recv.VoiceRecvClient, self_deaf=True)
        vc.listen(TranscriptionSink())
        _voice_fail_at.pop(channel.id, None)
        log.info(
            "[%s] Подключился к войсу: #%s (%d чел.)",
            guild.name, channel.name, humans_in(channel),
        )
    except discord.Forbidden:
        _voice_fail_at[channel.id] = time.time()
        log.error("[%s] Нет прав на подключение к #%s", guild.name, channel.name)
    except Exception:
        _voice_fail_at[channel.id] = time.time()
        log.exception("[%s] Не удалось подключиться к #%s", guild.name, channel.name)


async def auto_voice_tick() -> None:
    """Держит бота в голосовом канале с людьми — только на разрешённых серверах."""
    if not voice_auto_enabled or not voice_guild_ids:
        return

    for guild in client.guilds:
        if guild.id not in voice_guild_ids:
            continue

        vc = guild.voice_client
        # Уже сидим в канале, где есть люди — ничего не делаем.
        if vc and vc.channel and humans_in(vc.channel) > 0:
            continue

        target = pick_voice_channel(guild)

        if target is None:
            if vc and vc.channel:
                log.info("[%s] В войсе никого не осталось — отключаюсь", guild.name)
                await disconnect_voice(vc)
            continue

        if vc and vc.channel and vc.channel.id == target.id:
            continue

        if time.time() - _voice_fail_at.get(target.id, 0) < VOICE_CONNECT_RETRY:
            continue

        if vc:
            await disconnect_voice(vc)
        await connect_voice(guild, target)


async def auto_voice_worker() -> None:
    await client.wait_until_ready()
    while not client.is_closed():
        try:
            await auto_voice_tick()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Ошибка авто-транскрипции")
        await asyncio.sleep(VOICE_CHECK_INTERVAL)

# ---------- AI ----------
POLITENESS_TAG = re.compile(r"\[POLITENESS:\s*([+-]?\d+)\s*\]", re.IGNORECASE)
BLOCK_TAG = re.compile(r"\[BLOCK\]", re.IGNORECASE)
DOSSIER_TAG = re.compile(r"\[DOSSIER:\s*([^\]]+)\]", re.IGNORECASE)
CLEAR_TAG = re.compile(r"\[CLEAR:\s*(\d+)\]", re.IGNORECASE)
MUTE_TAG = re.compile(r"\[MUTE:\s*(\d+):\s*([a-zA-Z0-9]+)\]", re.IGNORECASE)
UNMUTE_TAG = re.compile(r"\[UNMUTE:\s*(\d+)\]", re.IGNORECASE)
ANY_TAG = re.compile(r"\[(?:POLITENESS:\s*[+-]?\d+|BLOCK|DOSSIER:\s*[^\]]+|CLEAR:\s*\d+|MUTE:\s*\d+:\s*[a-zA-Z0-9]+|UNMUTE:\s*\d+)\]", re.IGNORECASE)

_blocked_notice_at: dict[int, float] = {}
_ai_bot_cooldown: dict[int, list[float]] = {}

def parse_ai_tags(text: str) -> dict:
    result = {"clean": text, "politeness_delta": 0, "block": False, "dossier_targets": [], "clear": None, "mute": None, "unmute": None}
    for m in POLITENESS_TAG.findall(text):
        try: result["politeness_delta"] += int(m)
        except: pass
    if BLOCK_TAG.search(text): result["block"] = True
    result["dossier_targets"] = [t.strip() for t in DOSSIER_TAG.findall(text) if t.strip()][:3]
    if CLEAR_TAG.search(text): result["clear"] = int(CLEAR_TAG.search(text).group(1))
    if MUTE_TAG.search(text): result["mute"] = {"user_id": int(MUTE_TAG.search(text).group(1)), "time": MUTE_TAG.search(text).group(2)}
    if UNMUTE_TAG.search(text): result["unmute"] = int(UNMUTE_TAG.search(text).group(1))
    result["clean"] = ANY_TAG.sub("", text).strip()
    return result

def build_system_prompt(user, politeness: int) -> str:
    prompt = ai_config.get("system_prompt", DEFAULT_AI_CONFIG["system_prompt"])
    status = "ADMIN" if is_admin(user.id) else "USER"
    return prompt.replace("{name}", getattr(user, "display_name", str(user))).replace("{id}", str(user.id)).replace("{politeness}", str(politeness)).replace("{is_admin}", status).replace("{bot_id}", str(client.user.id) if client.user else "0").replace("{bot_name}", client.user.display_name if client.user else "Krim Logs")

async def call_ai(
    messages: list[dict],
    *,
    model: Optional[str] = None,
    max_tokens: Optional[int] = None,
    temperature: Optional[float] = None,
    timeout: int = 90,
) -> Optional[str]:
    """Запрос к OpenAI-совместимому API. Параметры можно переопределить для DeepNeuro."""
    if not AI_API_KEY: return None
    url = f"{ai_config.get('base_url', 'https://api.relaymodels.com/v1').rstrip('/')}/chat/completions"
    headers = {"Authorization": f"Bearer {AI_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": model or ai_config.get("model", "gpt-4o-mini"),
        "messages": messages,
        "max_tokens": max_tokens if max_tokens is not None else ai_config.get("max_tokens", 1200),
        "temperature": temperature if temperature is not None else ai_config.get("temperature", 0.7),
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                headers=headers,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=max(30, int(timeout))),
            ) as resp:
                if resp.status != 200:
                    log.warning("AI API вернул HTTP %s", resp.status)
                    return None
                data = await resp.json()
                return data["choices"][0]["message"]["content"]
    except Exception:
        log.exception("Ошибка запроса к AI API")
        return None

async def resolve_user_target(target: str, guild) -> Optional[int]:
    target = target.strip()
    m = re.match(r"^<@!?(\d{17,20})>$", target)
    if m: return int(m.group(1))
    if target.isdigit() and 17 <= len(target) <= 20: return int(target)
    if not guild: return None
    clean = target.lstrip("@").strip().lower()
    for member in guild.members:
        if clean in {member.name.lower(), (member.nick or "").lower(), member.display_name.lower(), str(member).lower()}: return member.id
    return None

async def get_dossier_text(user_id: int) -> str:
    info = stats.users.get(str(user_id), {})
    msg_counts, voice_seconds = stats.get_stats(user_id)
    state = await get_user_state(user_id)
    guild = client.guilds[0] if client.guilds else None
    is_muted = "Да" if guild and guild.get_member(user_id) and await check_mute_status(guild, guild.get_member(user_id)) else "Нет"
    lines = [f"=== ДОСЬЕ: {info.get('name', f'Неизвестный ({user_id})')} ===", f"ID: {user_id}", f"Роли: {', '.join(info.get('roles', [])) or '—'}", f"Замучен: {is_muted}", f"Вежливость: {state['politeness']}/100"]
    if state["is_blocked"]: lines.append("Статус: ЗАБЛОКИРОВАН для AI")
    lines.append(f"\nСообщений: день={msg_counts['day']}, нед={msg_counts['week']}, мес={msg_counts['month']}")
    lines.append(f"Голос: день={format_duration(voice_seconds['day'])}, нед={format_duration(voice_seconds['week'])}")
    return "\n".join(lines)

async def _notify_blocked(message: discord.Message) -> None:
    now = time.time()
    if now - _blocked_notice_at.get(message.author.id, 0.0) >= BLOCKED_NOTICE_INTERVAL:
        _blocked_notice_at[message.author.id] = now
        try: await message.reply("Ваши сообщения к AI-ассистенту заблокированы. Извинитесь, чтобы восстановить доступ.", mention_author=False)
        except: pass

# ---------- Текст из вложений для ИИ ----------

ATTACH_MAX_FILES = 10                      # Discord разрешает до 10 вложений
ATTACH_MAX_BYTES = 5 * 1024 * 1024         # не читаем файлы больше 5 МБ
ATTACH_ONE_FILE_CHARS = 6000               # лимит символов на один файл
ATTACH_TOTAL_CHARS = 15000                 # общий лимит символов на сообщение

TEXT_EXTENSIONS = {
    ".txt", ".text", ".md", ".markdown", ".rst", ".log", ".csv", ".tsv",
    ".json", ".jsonl", ".ndjson", ".xml", ".yml", ".yaml", ".toml", ".ini",
    ".cfg", ".conf", ".env", ".properties",
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue",
    ".html", ".htm", ".xhtml", ".css", ".scss", ".sass", ".less",
    ".sql", ".sh", ".bash", ".bat", ".cmd", ".ps1", ".psm1",
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cs", ".java", ".kt", ".kts",
    ".go", ".rs", ".rb", ".php", ".lua", ".swift", ".dart", ".r", ".pl",
    ".dockerfile", ".gitignore", ".gitattributes", ".editorconfig", ".makefile",
}
DOCX_EXTENSIONS = {".docx"}

_DOCX_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _decode_bytes(raw: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "cp1251", "koi8-r", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _docx_to_text(raw: bytes) -> str:
    """Достаёт текст из .docx (это zip с word/document.xml) без внешних библиотек."""
    try:
        import zipfile
        import xml.etree.ElementTree as ET

        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            parts: list[str] = []
            for name in ("word/document.xml", "word/footnotes.xml", "word/endnotes.xml"):
                if name not in zf.namelist():
                    continue
                root = ET.fromstring(zf.read(name))
                for paragraph in root.iter(_DOCX_NS + "p"):
                    text = "".join(
                        node.text or "" for node in paragraph.iter(_DOCX_NS + "t")
                    )
                    if text.strip():
                        parts.append(text)
            return "\n".join(parts)
    except Exception as exc:
        log.warning("Не удалось прочитать .docx: %s", exc)
        return ""


async def extract_attachment_text(attachment) -> Optional[str]:
    """Возвращает текстовый блок для одного вложения или None, если формат не поддержан."""
    filename = attachment.filename or "file"
    ext = Path(filename).suffix.lower()
    content_type = attachment.content_type or ""
    is_docx = ext in DOCX_EXTENSIONS
    is_text = ext in TEXT_EXTENSIONS or content_type.startswith("text/") or content_type in (
        "application/json", "application/xml", "application/x-yaml", "application/javascript",
    )
    if not (is_docx or is_text):
        return None

    size = getattr(attachment, "size", 0) or 0
    if size > ATTACH_MAX_BYTES:
        return f"--- Файл: {filename} ---\n[пропущен: слишком большой, {size} байт]"

    try:
        raw = await attachment.read()
    except Exception as exc:
        log.warning("Не удалось скачать вложение %s: %s", filename, exc)
        return f"--- Файл: {filename} ---\n[не удалось скачать: {exc}]"

    if not is_docx and b"\x00" in raw[:2048]:
        return f"--- Файл: {filename} ---\n[пропущен: похоже на бинарный файл]"

    text = _docx_to_text(raw) if is_docx else _decode_bytes(raw)
    if not text.strip():
        return None
    if len(text) > ATTACH_ONE_FILE_CHARS:
        text = text[:ATTACH_ONE_FILE_CHARS] + "\n…[файл обрезан]"
    return f"--- Файл: {filename} ---\n{text}"


async def extract_attachments_text(message: discord.Message) -> str:
    """Собирает текст всех поддерживаемых вложений сообщения в один блок."""
    attachments = getattr(message, "attachments", None) or []
    if not attachments:
        return ""

    blocks: list[str] = []
    total = 0
    skipped = 0
    for attachment in attachments[:ATTACH_MAX_FILES]:
        block = await extract_attachment_text(attachment)
        if not block:
            skipped += 1
            continue
        if total + len(block) > ATTACH_TOTAL_CHARS:
            remaining = ATTACH_TOTAL_CHARS - total
            if remaining > 300:
                blocks.append(block[:remaining] + "\n…[обрезано]")
            skipped += 1
            break
        blocks.append(block)
        total += len(block)

    if not blocks:
        return ""
    header = "[ПРИКРЕПЛЁННЫЕ ФАЙЛЫ — используй их как контекст для ответа]"
    if skipped:
        header += f" (пропущено файлов: {skipped})"
    return header + "\n\n" + "\n\n".join(blocks)


async def handle_ai(message: discord.Message, is_bot_chat: bool = False) -> None:
    if not AI_API_KEY or not client.user: return
    content = re.sub(rf"<@!?{client.user.id}>", "", message.content).strip()
    content = _resolve_mentions(content, message.guild).strip()
    attachments_text = await extract_attachments_text(message)
    if attachments_text:
        content = f"{content}\n\n{attachments_text}".strip() if content else attachments_text
    if not content: return

    user_id = message.author.id
    state = await get_user_state(user_id)
    just_unblocked = False

    if not is_bot_chat and state["is_blocked"]:
        if detect_apology(content):
            await set_user_blocked(user_id, False)
            await set_politeness(user_id, ai_config.get("politeness", {}).get("restore_on_apology", 100))
            just_unblocked = True
        else:
            await _notify_blocked(message)
            return

    await save_ai_message(user_id, client.user.id, message.channel.id, "user", content)
    history = await get_context(user_id, client.user.id, message.channel.id, ai_config.get("context_limit", 20))
    politeness_now = (await get_user_state(user_id))["politeness"]
    messages = [{"role": "system", "content": build_system_prompt(message.author, politeness_now)}]

    if is_bot_chat: messages.append({"role": "system", "content": "[СИСТЕМА] С тобой общается другой ИИ-бот."})
    elif just_unblocked: messages.append({"role": "system", "content": f"[СИСТЕМА] Блокировка снята. Поприветствуй возвращение."})
    messages.extend(history)

    raw_reply = await call_ai(messages)
    if not raw_reply:
        if not is_bot_chat: await message.reply("Не удалось получить ответ от ИИ.", mention_author=False)
        return

    parsed = parse_ai_tags(raw_reply)
    if parsed["dossier_targets"]:
        dossier_blocks = []
        for target in parsed["dossier_targets"]:
            target_id = await resolve_user_target(target, message.guild)
            if target_id: dossier_blocks.append(await get_dossier_text(target_id))
        if dossier_blocks:
            messages.append({"role": "assistant", "content": raw_reply})
            messages.append({"role": "system", "content": "[ДОСЬЕ]\n\n" + "\n\n---\n\n".join(dossier_blocks)})
            second = await call_ai(messages)
            if second:
                parsed = parse_ai_tags(second)
                parsed["dossier_targets"] = []

    final_text = parsed["clean"] or "*[пустой ответ]*"

    if is_admin(user_id) and message.guild:
        if parsed["clear"] is not None:
            try: await message.channel.purge(limit=min(parsed["clear"], 100))
            except discord.Forbidden: await message.channel.send("⚠️ Не удалось очистить чат.")
        if parsed["mute"]:
            secs = parse_duration(parsed["mute"]["time"])
            if secs > 0 and (member := message.guild.get_member(parsed["mute"]["user_id"])):
                success, err = await apply_mute(message.guild, member, secs, reason=f"AI mute by {message.author}")
                if not success: await message.channel.send(f"⚠️ Не удалось замутить: {err}")
        if parsed["unmute"]:
            if member := message.guild.get_member(parsed["unmute"]):
                success, err = await remove_mute(message.guild, member, reason=f"AI unmute by {message.author}")
                if not success: await message.channel.send(f"⚠️ Не удалось размутить: {err}")

    if not is_bot_chat:
        if parsed["politeness_delta"]: await adjust_politeness(user_id, parsed["politeness_delta"])
        if parsed["block"]: await set_user_blocked(user_id, True)

    await save_ai_message(user_id, client.user.id, message.channel.id, "assistant", final_text)
    allowed_mentions = discord.AllowedMentions(users=True, roles=False, everyone=False)
    for i, part in enumerate(split_message(final_text)):
        try:
            if i == 0: await message.reply(part, mention_author=False, allowed_mentions=allowed_mentions)
            else: await message.channel.send(part, allowed_mentions=allowed_mentions)
        except: pass

# ---------- HTML Досье ----------
async def write_dossier(user_id: int) -> Path:
    ai_data = {}
    if client.user:
        our = await get_ai_counts(user_id, client.user.id)
        emp = await get_ai_counts(user_id, emperial_id) if emperial_id else {}
        ai_data = {"our": our, "emperial": emp}
    state = await get_user_state(user_id)
    content = generate_dossier_html(user_id, ai_data, state)
    path = DOSSIER_DIR / f"dossier_{user_id}.html"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)
    return path

def generate_dossier_html(user_id: int, ai_data: dict, state: dict) -> str:
    uid = str(user_id)
    info = stats.users.get(uid, {})
    name = info.get("name", f"Неизвестный ({uid})")
    avatar = info.get("avatar", "")
    msg_counts, voice_seconds = stats.get_stats(uid)
    politeness, blocked = state.get("politeness", 100), state.get("is_blocked", False)
    pol_class = "pol-good" if politeness >= 70 else "pol-warn" if politeness >= 20 else "pol-bad"
    blocked_html = '<span class="badge badge-blocked">ЗАБЛОКИРОВАН</span>' if blocked else ""
    roles_html = f'<div class="roles">{"".join(f"<span class=\"role-tag\">{html_module.escape(r)}</span>" for r in info.get("roles", []))}</div>' if info.get("roles") else ""
    activity_rows = "".join(f"<tr><td>{l}</td><td class='num'>{format_duration(voice_seconds[k])}</td><td class='num'>{msg_counts[k]}</td></tr>" for k, l in [("day", "За день"), ("week", "За неделю"), ("month", "За месяц"), ("year", "За год"), ("five_years", "За 5 лет")])
    ai_html = ""
    if ai_data:
        rows = f"<tr><td>Krim AI</td><td class='num'>{ai_data['our'].get('user', 0)}</td><td class='num'>{ai_data['our'].get('assistant', 0)}</td></tr>"
        if emperial_id: rows += f"<tr><td>Emperial</td><td class='num'>{ai_data['emperial'].get('user', 0)}</td><td class='num'>{ai_data['emperial'].get('assistant', 0)}</td></tr>"
        ai_html = f"<div class='card'><h2>Диалоги с ИИ</h2><table><thead><tr><th>Бот</th><th>Отправлено</th><th>Получено</th></tr></thead><tbody>{rows}</tbody></table></div>"

    return f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><title>Досье — {html_module.escape(name)}</title>
<style>
  :root {{ --bg: #0f1117; --card: #1a1d27; --border: #2a2e3a; --text: #e4e6eb; --muted: #8b8f9a; --accent: #5865F2; --success: #57f287; --warn: #faa61a; --danger: #ed4245; }}
  body {{ font-family: sans-serif; background: var(--bg); color: var(--text); padding: 40px 20px; }}
  .container {{ max-width: 1000px; margin: 0 auto; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 28px; margin-bottom: 24px; }}
  .profile {{ display: flex; gap: 28px; }}
  .avatar {{ width: 120px; height: 120px; border-radius: 50%; border: 3px solid var(--accent); }}
  .badges {{ display: flex; gap: 8px; margin-bottom: 12px; }}
  .badge {{ padding: 3px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; }}
  .badge-id {{ background: rgba(88,101,242,0.15); color: #7983f5; }} .badge-blocked {{ background: rgba(237,66,69,0.18); color: var(--danger); }}
  .pol-wrap {{ display: flex; align-items: center; gap: 10px; margin: 8px 0; }}
  .pol-bar {{ width: 220px; height: 8px; background: rgba(255,255,255,0.08); border-radius: 4px; }}
  .pol-fill {{ height: 100%; border-radius: 4px; }}
  .pol-good .pol-fill {{ background: var(--success); }} .pol-warn .pol-fill {{ background: var(--warn); }} .pol-bad .pol-fill {{ background: var(--danger); }}
  .roles {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 14px; }}
  .role-tag {{ background: rgba(88,101,242,0.1); color: #7983f5; padding: 3px 10px; border-radius: 12px; font-size: 12px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }} th, td {{ padding: 12px; border-bottom: 1px solid var(--border); text-align: left; }}
  th {{ background: rgba(88,101,242,0.1); color: #7983f5; font-size: 12px; }} .num {{ font-family: monospace; color: #7983f5; }}
</style></head><body><div class="container">
  <div class="card"><div class="profile"><img class="avatar" src="{html_module.escape(avatar) if avatar else ''}">
    <div><h1>{html_module.escape(name)}</h1><div class="badges"><span class="badge badge-id">ID: {uid}</span>{blocked_html}</div>
    <div class="pol-wrap {pol_class}"><span>Вежливость</span><div class="pol-bar"><div class="pol-fill" style="width:{politeness}%"></div></div><span class="num">{politeness}/100</span></div>
    {roles_html}</div></div></div>
  <div class="card"><h2>Активность</h2><table><thead><tr><th>Период</th><th>Голос</th><th>Сообщений</th></tr></thead><tbody>{activity_rows}</tbody></table></div>
  {ai_html}
</div></body></html>"""

# ---------- Утилиты ----------
def utcnow(): return datetime.now(timezone.utc)
def fmt_dt(dt): return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "—"
def avatar_url(user): return user.display_avatar.url if getattr(user, "display_avatar", None) else "—"
def truncate(text, limit=CONTENT_LIMIT): return text if len(text) <= limit else text[:limit-1] + "…"
def quote(text, limit=CONTENT_LIMIT): return "\n".join(f"> {line}" if line else ">" for line in truncate(text, limit).splitlines() or [""])
def split_message(text, limit=MESSAGE_LIMIT):
    if len(text) <= limit: return [text]
    parts, current = [], ""
    for line in text.splitlines(keepends=True):
        while len(line) > limit:
            if current: parts.append(current); current = ""
            parts.append(line[:limit]); line = line[limit:]
        if len(current) + len(line) > limit: parts.append(current); current = line
        else: current += line
    if current: parts.append(current)
    return [p for p in parts if p.strip()]
def is_supported_channel(ch): return isinstance(ch, (discord.TextChannel, discord.Thread))
def footer(): return f"`{fmt_dt(utcnow())}`"
def format_duration(seconds):
    s = int(max(0, seconds))
    if s < 60: return f"{s} сек"
    m, s2 = divmod(s, 60)
    if m < 60: return f"{m} мин {s2} сек" if s2 else f"{m} мин"
    h, m2 = divmod(m, 60)
    if h < 24: return f"{h} ч {m2} мин" if m2 else f"{h} ч"
    d, h2 = divmod(h, 24)
    return f"{d} д {h2} ч" if h2 else f"{d} д"

def _resolve_mentions(text: str, guild) -> str:
    def _repl(m):
        uid = int(m.group(1))
        if guild and (member := guild.get_member(uid)): return f"@{member.display_name}(id={uid})"
        return f"@user(id={uid})"
    return re.sub(r"<@!?(\d+)>", _repl, text)

async def get_log_channel():
    if log_channel_id is None: return None
    ch = client.get_channel(log_channel_id)
    if ch is None:
        try: ch = await client.fetch_channel(log_channel_id)
        except: return None
    return ch if is_supported_channel(ch) else None

def missing_permissions(channel):
    guild = getattr(channel, "guild", None)
    me = getattr(guild, "me", None) if guild else None
    if me is None: return []
    try: perms = channel.permissions_for(me)
    except: return []
    missing = []
    for p, n in [(perms.send_messages, "Send Messages"), (perms.read_message_history, "Read Message History"), (perms.embed_links, "Embed Links"), (perms.attach_files, "Attach Files"), (perms.manage_messages, "Manage Messages"), (perms.manage_roles, "Manage Roles")]:
        if not p: missing.append(n)
    return missing

async def send_log(text: str, *, event: str = "log"):
    channel = await get_log_channel()
    if channel is None: return None
    first = None
    try:
        for part in split_message(text):
            sent = await channel.send(part, allowed_mentions=discord.AllowedMentions.none())
            if first is None: first = sent
    except discord.Forbidden: log.error("Нет прав на отправку лога '%s'", event)
    except Exception: log.exception("Ошибка отправки лога '%s'", event)
    return first

# ---------- Команды ----------
LOG_CMD_SET_RE = re.compile(r"^log!(?:<#(\d{17,20})>|(\d{17,20}))$", re.IGNORECASE)
LOG_CMD_OFF_RE = re.compile(r"^log!(?:off|reset|stop)$", re.IGNORECASE)
LOG_CMD_HELP_RE = re.compile(r"^log!help$", re.IGNORECASE)
LOG_CMD_STAT_RE = re.compile(r"^log!stat-(\d{17,20})$", re.IGNORECASE)
LOG_CMD_DIALOG_CLEAR_RE = re.compile(r"^log!dialog-clear$", re.IGNORECASE)
LOG_CMD_CLEAR_RE = re.compile(r"^log!clear\s+(\d+)$", re.IGNORECASE)
LOG_CMD_MUTE_RE = re.compile(r"^log!mute\s+(\d{17,20})\s+(\d+[mhd])$", re.IGNORECASE)
LOG_CMD_UNMUTE_RE = re.compile(r"^log!unmute\s+(\d{17,20})$", re.IGNORECASE)
LOG_CMD_PROXY_RE = re.compile(r"^log!proxy$", re.IGNORECASE)
LOG_CMD_PING_RE = re.compile(r"^log!ping$", re.IGNORECASE)
LOG_CMD_DEEPN_RE = re.compile(r"^log!deepneuro\s+(.+)$", re.IGNORECASE | re.DOTALL)

HELP_TEXT = (
    "**Krim Logs — Помощь**\n\n"
    "**Настройка:**\n"
    "• `log!<ID_канала>` — установить канал\n"
    "• `log!off` — отключить\n\n"
    "**Статистика:**\n"
    "• `log!stat-<ID>` — досье\n\n"
    "**Диагностика:**\n"
    "• `log!ping` — пинг до ya.ru, google.com и relaymodels.com\n"
    "• `log!proxy` — активный прокси/VLESS, IP и страна (админы)\n\n"
    "**Модерация (админы):**\n"
    "• `log!clear <кол-во>`\n"
    "• `log!mute <ID> <1m, 1h, 1d>`\n"
    "• `log!unmute <ID>`\n\n"
    "**Войс:**\n"
    "• `log!join` — слушать канал\n"
    "• `log!leave` — отключиться\n\n"
    "**ИИ:**\n"
    "• `@бот <сообщение>`\n"
    "• можно прикрепить до 10 файлов (.txt, .md, .json, .py, .html, .docx, .csv и др.) — ИИ прочитает их текст\n"
    "• `log!deepneuro \"<промпт>\" <1-4>` — Mini + сильная модель, глубокое рассуждение (админы)\n"
    "   пример: `log!deepneuro \"проанализируй отчёт\" 3`\n"
    "• `log!dialog-clear` — сброс контекста"
)

def is_admin(user_id: int) -> bool: return user_id in ADMIN_IDS

# ---------- Диагностика и DeepNeuro ----------

_geo_cache: dict[str, str] = {}


async def resolve_host_ip(host: str) -> str:
    """Возвращает IP для домена/адреса; при ошибке — исходную строку."""
    host = (host or "").strip().strip("[]")
    if not host:
        return "?"
    try:
        return await asyncio.to_thread(socket.gethostbyname, host)
    except OSError:
        return host


async def geo_country(ip: str) -> str:
    """Страна по IP через бесплатный ipwho.is. Результат кэшируется."""
    if not ip or ip == "?":
        return "неизвестно"
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://ipwho.is/{ip}",
                timeout=aiohttp.ClientTimeout(total=8),
            ) as response:
                if response.status != 200:
                    return "неизвестно"
                data = await response.json()
        if not data.get("success", False):
            return "неизвестно"
        country = data.get("country") or "неизвестно"
        code = data.get("country_code") or ""
        result = f"{country} ({code})" if code else country
        _geo_cache[ip] = result
        return result
    except Exception:
        log.debug("Не удалось определить страну по IP %s", ip, exc_info=True)
        return "неизвестно"


async def tcp_ping(
    host: str, port: int = 443, attempts: int = 3, timeout: float = 5.0
) -> tuple[str, Optional[float]]:
    """Минимальная задержка TCP-подключения из нескольких попыток."""
    ip = await resolve_host_ip(host)
    target = ip if ip and ip != "?" else host
    best: Optional[float] = None
    for _ in range(attempts):
        writer = None
        started = time.perf_counter()
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=timeout
            )
            elapsed = (time.perf_counter() - started) * 1000.0
            if best is None or elapsed < best:
                best = elapsed
        except Exception:
            pass
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
    return ip, best


async def handle_ping(message: discord.Message) -> None:
    targets = [("ya.ru", 443), ("google.com", 443), ("relaymodels.com", 443)]
    results = await asyncio.gather(
        *(tcp_ping(host, port) for host, port in targets)
    )
    lines = ["🏓 **Пинг (TCP 443, минимум из 3)**"]
    for (host, _port), (ip, latency) in zip(targets, results):
        if latency is None:
            lines.append(f"• **{host}** — ⚪ нет ответа · `{ip}`")
        else:
            icon = "🟢" if latency < 100 else "🟡" if latency < 300 else "🔴"
            lines.append(f"• **{host}** — {icon} {latency:.0f} мс · `{ip}`")
    await message.reply("\n".join(lines), mention_author=False)


async def handle_proxy_status(message: discord.Message) -> None:
    if proxy_manager is None or not proxy_manager.proxy_url:
        await message.reply(
            "🌐 Сетевой обход выключен — бот подключён напрямую.",
            mention_author=False,
        )
        return

    status = proxy_manager.status()
    mode = status.get("mode")

    if mode == "vless" and status.get("vless"):
        cfg = status["vless"]
        ip = await resolve_host_ip(cfg["address"])
        country = await geo_country(ip)
        text = (
            "🌐 **VLESS-подключение**\n"
            f"• Сервер: {cfg['name']}\n"
            f"• Адрес: `{cfg['address']}:{cfg['port']}`\n"
            f"• IP: `{ip}`\n"
            f"• Страна: {country}\n"
            f"• Транспорт: `{cfg['network']}/{cfg['security']}`\n"
            f"• Локальный прокси: `{status['proxy_url']}`"
        )
    else:
        proxy_url = status["proxy_url"]
        host_port = proxy_url.split("://", 1)[-1]
        host, _, port = host_port.rpartition(":")
        if not host:
            host, port = host_port, "?"
        ip = await resolve_host_ip(host)
        country = await geo_country(ip)
        backups = status.get("backups") or []
        text = (
            "🌐 **HTTPS-прокси**\n"
            f"• Адрес: `{host}:{port}`\n"
            f"• IP: `{ip}`\n"
            f"• Страна: {country}\n"
            f"• Запасных: {len(backups)}/{status.get('pool_size', 0)}\n"
            "• Проверка: `https://discord.com/api/v10/gateway`"
        )

    await message.reply(text, mention_author=False)


_DEEPN_ARGS_RE = re.compile(
    r"^(?:\"((?:\\.|[^\"\\])*)\"|'((?:\\.|[^'\\])*)')\s+(\d+)\s*$",
    re.DOTALL,
)


def parse_deepneuro_args(raw: str) -> Optional[tuple[str, int]]:
    """Разбирает '«промпт» 3' -> ('промпт', 3). Промпт обязан быть в кавычках."""
    raw = (raw or "").strip()
    if not raw:
        return None
    match = _DEEPN_ARGS_RE.match(raw)
    if not match:
        return None
    prompt = match.group(1) if match.group(1) is not None else match.group(2)
    prompt = prompt.replace('\\"', '"').replace("\\'", "'").strip()
    steps = int(match.group(3))
    if not prompt or not 1 <= steps <= 4:
        return None
    return prompt, steps


async def handle_deepneuro(
    message: discord.Message, prompt: str, steps: int
) -> None:
    """Многошаговое рассуждение отдельной моделью из ai_config.json."""
    if not AI_API_KEY or not client.user:
        await message.reply("AI_API_KEY не задан в .env.", mention_author=False)
        return

    attachments_text = await extract_attachments_text(message)
    content = prompt.strip()
    if attachments_text:
        content = (
            f"{content}\n\n{attachments_text}".strip()
            if content
            else attachments_text
        )
    if not content:
        await message.reply("Пустой промпт.", mention_author=False)
        return

    steps = max(1, min(4, steps))
    mini_enabled = bool(ai_config.get("deep_mini_enabled", True))
    mini_model = ai_config.get("deep_mini_model") or "gpt-4o-mini"
    deep_model = ai_config.get("deep_model") or ai_config.get("model", "gpt-4o-mini")
    deep_system = ai_config.get(
        "deep_system_prompt", DEFAULT_AI_CONFIG["deep_system_prompt"]
    )
    deep_max_tokens = int(ai_config.get("deep_max_tokens", 2000))
    deep_temperature = float(ai_config.get("deep_temperature", 0.5))
    deep_timeout = int(ai_config.get("deep_timeout", 180))

    user_id = message.author.id
    state = await get_user_state(user_id)
    base_system = build_system_prompt(message.author, state["politeness"])
    history = await get_context(
        user_id,
        client.user.id,
        message.channel.id,
        ai_config.get("context_limit", 20),
    )

    try:
        placeholder = await message.reply(
            "🧠 DeepNeuro: готовлюсь…", mention_author=False
        )
    except discord.HTTPException:
        return

    # 1. Первичная быстрая модель Krim DeepNeuro Mini предлагает черновик.
    draft = ""
    if mini_enabled:
        mini_system = ai_config.get(
            "deep_mini_system_prompt",
            DEFAULT_AI_CONFIG["deep_mini_system_prompt"],
        )
        mini_messages = [
            {"role": "system", "content": base_system + "\n\n" + mini_system},
            *history,
            {"role": "user", "content": content},
        ]
        try:
            await placeholder.edit(
                content="🧠 Krim DeepNeuro Mini: черновой вариант…"
            )
        except discord.HTTPException:
            pass
        draft = (
            await call_ai(
                mini_messages,
                model=mini_model,
                max_tokens=int(ai_config.get("deep_mini_max_tokens", 900)),
                temperature=float(ai_config.get("deep_mini_temperature", 0.7)),
                timeout=int(ai_config.get("deep_mini_timeout", 90)),
            )
            or ""
        )
        if not draft:
            log.warning(
                "DeepNeuro Mini не дал ответ — продолжаю только сильной моделью"
            )

    # 2. Сильная модель Krim DeepNeuro обрабатывает задачу в N шагов.
    messages = [
        {"role": "system", "content": base_system + "\n\n" + deep_system},
        *history,
        {"role": "user", "content": content},
    ]
    if draft:
        messages.append(
            {
                "role": "system",
                "content": (
                    "[ЧЕРНОВОЙ ВАРИАНТ ОТ Krim DeepNeuro Mini]\n"
                    f"{draft}\n\n"
                    "Используй его как отправную точку, но критически проверь "
                    "и улучши."
                ),
            }
        )

    final_raw = ""
    for step in range(1, steps + 1):
        if steps == 1:
            instruction = (
                "Дай финальный ответ. Сначала продумай решение, затем выдай "
                "структурированный ответ."
            )
        elif step == 1:
            instruction = (
                f"Шаг 1/{steps}. Проанализируй задачу и черновик Mini (если он "
                "есть): условия, ограничения, риски, неизвестные. Составь "
                "подробный план решения. Не давай финальный ответ."
            )
        elif step < steps:
            instruction = (
                f"Шаг {step}/{steps}. Проверь предыдущие рассуждения, найди "
                "ошибки и пробелы, углубь анализ. Не давай финальный ответ."
            )
        else:
            instruction = (
                f"Шаг {steps}/{steps}. Сформируй финальный ответ пользователю: "
                "структурированно, по делу, с учётом всех предыдущих шагов."
            )

        messages.append({"role": "system", "content": instruction})
        try:
            await placeholder.edit(
                content=f"🧠 Krim DeepNeuro: шаг {step}/{steps}…"
            )
        except discord.HTTPException:
            pass

        reply = await call_ai(
            messages,
            model=deep_model,
            max_tokens=deep_max_tokens,
            temperature=deep_temperature,
            timeout=deep_timeout,
        )
        if not reply:
            try:
                await placeholder.edit(
                    content=(
                        "❌ DeepNeuro: не удалось получить ответ "
                        f"на шаге {step}/{steps}."
                    )
                )
            except discord.HTTPException:
                pass
            return

        final_raw = reply
        messages.append({"role": "assistant", "content": reply})

    final_text = parse_ai_tags(final_raw)["clean"] or "*[пустой ответ]*"
    await save_ai_message(
        user_id, client.user.id, message.channel.id, "user", content
    )
    await save_ai_message(
        user_id, client.user.id, message.channel.id, "assistant", final_text
    )

    if not mini_enabled:
        mini_label = "Mini выкл."
    elif draft:
        mini_label = f"Mini `{mini_model}`"
    else:
        mini_label = "Mini без ответа"
    header = (
        f"🧠 **DeepNeuro** · модель `{deep_model}` · {mini_label} · "
        f"шагов: {steps}\n\n"
    )
    parts = split_message(final_text)
    first = parts[0]
    if len(header) + len(first) > MESSAGE_LIMIT:
        first = first[: max(0, MESSAGE_LIMIT - len(header) - 1)] + "…"
    try:
        await placeholder.edit(content=header + first)
    except discord.HTTPException:
        await message.channel.send(header + first)
    for part in parts[1:]:
        await message.channel.send(part)

@tree.command(name="print", description="Отправить сообщение от лица бота")
async def print_cmd(interaction: discord.Interaction, text: str):
    if interaction.user.id not in ADMIN_IDS:
        await interaction.response.send_message("Нет прав.", ephemeral=True); return
    await interaction.channel.send(text)
    await interaction.response.send_message("Отправлено.", ephemeral=True)

async def handle_command(message: discord.Message) -> bool:
    global log_channel_id
    content = message.content.strip()

    # Пинг доступен всем пользователям и не требует прав администратора.
    if LOG_CMD_PING_RE.match(content):
        await handle_ping(message); return True

    if LOG_CMD_DIALOG_CLEAR_RE.match(content):
        await clear_context(message.author.id)
        await message.reply("Контекст диалога очищен.", mention_author=False); return True

    if not is_admin(message.author.id):
        if content.startswith("log!") and not content.startswith("log!dialog-clear"):
            await message.reply("У вас нет прав на использование команд модератора.", mention_author=False); return True
        return False

    if LOG_CMD_HELP_RE.match(content):
        await message.reply(HELP_TEXT, mention_author=False); return True

    if LOG_CMD_PROXY_RE.match(content):
        await handle_proxy_status(message); return True

    if LOG_CMD_DEEPN_RE.match(content):
        parsed = parse_deepneuro_args(LOG_CMD_DEEPN_RE.match(content).group(1))
        if parsed is None:
            await message.reply(
                "Использование: `log!deepneuro \"<промпт>\" <шаги 1-4>`\n"
                "Пример: `log!deepneuro \"проанализируй отчёт\" 3`",
                mention_author=False,
            ); return True
        prompt, steps = parsed
        await handle_deepneuro(message, prompt, steps); return True

    if LOG_CMD_OFF_RE.match(content):
        log_channel_id = None; save_config()
        await message.reply("Канал логов сброшен.", mention_author=False); return True

    if LOG_CMD_STAT_RE.match(content):
        user_id = int(LOG_CMD_STAT_RE.match(content).group(1))
        if str(user_id) not in stats.users:
            try: stats.update_user(await client.fetch_user(user_id))
            except: pass
        path = await write_dossier(user_id)
        await message.reply(f"Досье пользователя `{user_id}`:", file=discord.File(path, filename=path.name), mention_author=False); return True

    if LOG_CMD_CLEAR_RE.match(content):
        count = min(int(LOG_CMD_CLEAR_RE.match(content).group(1)), 100)
        try:
            messages_to_delete = [m async for m in message.channel.history(limit=count)]
            if not messages_to_delete:
                await message.reply("Нет сообщений для удаления.", mention_author=False); return True
            html_content = await generate_chat_log_html(messages_to_delete)
            await message.channel.purge(limit=count)
            file = discord.File(fp=io.BytesIO(html_content.encode("utf-8")), filename="deleted_chat.html")
            await message.channel.send("Чат очищен. Лог:", file=file)
        except discord.Forbidden: await message.reply("Нет прав на удаление сообщений.", mention_author=False)
        return True

    if LOG_CMD_MUTE_RE.match(content):
        match = LOG_CMD_MUTE_RE.match(content)
        target_id, time_str = int(match.group(1)), match.group(2)
        if member := message.guild.get_member(target_id):
            success, msg = await apply_mute(message.guild, member, parse_duration(time_str), reason=f"Мут от {message.author}")
            if success: await message.reply(f"Участник {member.mention} замьючен на {time_str}.", mention_author=False)
            else: await message.reply(f"Ошибка: {msg}", mention_author=False)
        else: await message.reply("Участник не найден.", mention_author=False)
        return True

    if LOG_CMD_UNMUTE_RE.match(content):
        target_id = int(LOG_CMD_UNMUTE_RE.match(content).group(1))
        if member := message.guild.get_member(target_id):
            if not await check_mute_status(message.guild, member):
                await message.reply("Участник не в муте.", mention_author=False); return True
            success, msg = await remove_mute(message.guild, member, reason=f"Размут от {message.author}")
            if success: await message.reply(f"Участник {member.mention} размьючен.", mention_author=False)
            else: await message.reply(f"Ошибка: {msg}", mention_author=False)
        return True

    if content == "log!join":
        if not message.author.voice:
            await message.reply("Вы не в голосовом канале.", mention_author=False); return True
        channel = message.author.voice.channel
        if message.guild.voice_client: await message.guild.voice_client.disconnect()
        try:
            vc = await channel.connect(cls=voice_recv.VoiceRecvClient)
            vc.listen(TranscriptionSink())
            await message.reply(f"Подключился к {channel.name} и начал транскрипцию.", mention_author=False)
        except Exception as e: await message.reply(f"Ошибка: {e}", mention_author=False)
        return True

    if content == "log!leave":
        vc = message.guild.voice_client
        if vc:
            vc.stop_listening(); await vc.disconnect()
            await message.reply("Отключился от войса.", mention_author=False)
        return True

    if match := LOG_CMD_SET_RE.match(content):
        new_id = int(match.group(1) or match.group(2))
        channel = message.guild.get_channel(new_id)
        if not channel:
            try: channel = await client.fetch_channel(new_id)
            except: channel = None
        if is_supported_channel(channel) and channel.guild.id == message.guild.id:
            log_channel_id = new_id; save_config()
            missing = missing_permissions(channel)
            if missing: await message.reply(f"Канал логов: {channel.mention}\nНе хватает прав: **{', '.join(missing)}**", mention_author=False)
            else: await message.reply(f"Канал логов установлен: {channel.mention}", mention_author=False)
            await send_log(f"**Канал логов настроен**\n━━━━━━━━━━━━━━━━━━━━\n**Канал:** {channel.mention} (`{channel.id}`)\n{footer()}", event="тест")
        else: await message.reply("Канал не найден.", mention_author=False)
        return True
    return False

# ---------- События ----------
@client.event
async def on_message(message: discord.Message) -> None:
    try:
        if not message.guild or (client.user and message.author.id == client.user.id): return
        if message.content.startswith("log!"):
            if await handle_command(message): return
        if emperial_id and message.author.id == emperial_id:
            if client.user and client.user.mentioned_in(message):
                now = time.time()
                history = [t for t in _ai_bot_cooldown.get(message.channel.id, []) if now - t < 60]
                if len(history) < 3:
                    history.append(now); _ai_bot_cooldown[message.channel.id] = history
                    await handle_ai(message, is_bot_chat=True)
            return
        if message.author.bot: return
        if client.user and client.user.mentioned_in(message):
            await handle_ai(message); return
        stats.update_user(message.author)
        stats.record_message(message.author)
    except Exception: log.exception("Ошибка в on_message")

@client.event
async def on_message_edit(before: discord.Message, after: discord.Message) -> None:
    if not after.guild or (client.user and before.author.id == client.user.id): return
    if before.content == after.content: return
    diff = list(difflib.unified_diff(before.content.splitlines(), after.content.splitlines(), lineterm=""))
    diff_text = truncate("\n".join(diff[:20]) if diff else "*[изменения не обнаружены]*", 800)
    await send_log(f"**Сообщение отредактировано**\n━━━━━━━━━━━━━━━━━━━━\n**Автор:** {before.author} (`{before.author.id}`)\n**Канал:** {before.channel.mention}\n**Изменения:**\n```diff\n{diff_text}\n```\n{footer()}", event="редактирование")

@client.event
async def on_message_delete(message: discord.Message) -> None:
    if not message.guild or (client.user and message.author.id == client.user.id): return
    content = message.content or ("*[без текста]*" if message.attachments else "*[недоступно]*")
    await send_log(f"**Сообщение удалено**\n━━━━━━━━━━━━━━━━━━━━\n**Автор:** {message.author} (`{message.author.id}`)\n**Канал:** {message.channel.mention}\n**Содержимое:**\n{quote(content)}\n{footer()}", event="удаление")

@client.event
async def on_voice_state_update(member: discord.Member, before: discord.VoiceState, after: discord.VoiceState) -> None:
    if member.bot: return
    if before.channel is None and after.channel is not None:
        stats.update_user(member); stats.start_voice(member, after.channel)
        await send_log(f"**Вход в войс**\n━━━━━━━━━━━━━━━━━━━━\n**Участник:** {member.mention}\n**Канал:** {after.channel.name}\n{footer()}", event="войс")
    elif before.channel is not None and after.channel is None:
        stats.update_user(member); duration = stats.end_voice(member)
        await send_log(f"**Выход из войса**\n━━━━━━━━━━━━━━━━━━━━\n**Участник:** {member.mention}\n**Время:** {format_duration(duration or 0)}\n{footer()}", event="войс")
    elif before.channel != after.channel:
        stats.update_user(member); duration = stats.end_voice(member); stats.start_voice(member, after.channel)
        await send_log(f"**Переход в войсе**\n━━━━━━━━━━━━━━━━━━━━\n**Участник:** {member.mention}\n**Из:** {before.channel.name} -> **В:** {after.channel.name}\n{footer()}", event="войс")

@client.event
async def on_member_join(member: discord.Member) -> None:
    stats.update_user(member)
    await send_log(f"**Участник присоединился**\n━━━━━━━━━━━━━━━━━━━━\n**Никнейм:** {member}\n**ID:** `{member.id}`\n{footer()}", event="вход")

@client.event
async def on_member_remove(member: discord.Member) -> None:
    await send_log(f"**Участник ушёл**\n━━━━━━━━━━━━━━━━━━━━\n**Никнейм:** {member}\n**ID:** `{member.id}`\n{footer()}", event="уход")

@client.event
async def on_member_update(before: discord.Member, after: discord.Member) -> None:
    if before.nick != after.nick:
        stats.update_user(after)
        await send_log(f"**Изменён никнейм**\n━━━━━━━━━━━━━━━━━━━━\n**Участник:** {after} (`{after.id}`)\n**Было:** {before.nick or '*[нет]*'}\n**Стало:** {after.nick or '*[нет]*'}\n{footer()}", event="никнейм")
    added = [r for r in after.roles if r not in before.roles]
    removed = [r for r in before.roles if r not in after.roles]
    if added or removed:
        lines = [f"**Изменены роли**\n━━━━━━━━━━━━━━━━━━━━\n**Участник:** {after} (`{after.id}`)"]
        if added: lines.append(f"**Выданы:** {', '.join(r.name for r in added)}")
        if removed: lines.append(f"**Сняты:** {', '.join(r.name for r in removed)}")
        lines.append(footer())
        await send_log("\n".join(lines), event="роли")

@client.event
async def on_ready() -> None:
    global voice_auto_task

    log.info("=== Krim Logs запущен как %s ===", client.user)
    if proxy_manager is not None and proxy_manager.proxy_url:
        log.info("Сетевой обход: %s", proxy_manager.describe())
    try: await tree.sync()
    except Exception as e: log.error("Ошибка синхронизации слэш-команд: %s", e)
    await client.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="логи | Krim Logs"))
    
    # Восстановление мутов
    mutes = await db_execute("SELECT guild_id, user_id, unmute_at FROM active_mutes")
    for m in mutes:
        if (guild := client.get_guild(m["guild_id"])) and (member := guild.get_member(m["user_id"])):
            delay = m["unmute_at"] - time.time()
            if delay <= 0: await remove_mute(guild, member, reason="Восстановление")
            else: asyncio.create_task(unmute_later(guild, member.id, int(delay)))

    # Авто-транскрипция войса
    if not voice_auto_enabled:
        log.info("Авто-транскрипция выключена (voice_auto=false в config.json)")
    elif not voice_guild_ids:
        log.warning(
            "voice_guilds пуст — авто-транскрипция выключена. "
            "Добавьте ID серверов в config.json. Доступные серверы: %s",
            ", ".join(f"{g.name} ({g.id})" for g in client.guilds) or "нет",
        )
    else:
        log.info(
            "Авто-транскрипция включена для серверов: %s",
            ", ".join(
                f"{g.name} ({g.id})" for g in client.guilds if g.id in voice_guild_ids
            ) or "ни один из разрешённых серверов не найден",
        )
        if voice_auto_task is None or voice_auto_task.done():
            voice_auto_task = asyncio.create_task(auto_voice_worker())

    try:
        await generate_transcript_html()
    except Exception:
        log.exception("Не удалось сгенерировать HTML транскриптов")

async def run_bot() -> None:
    """Поднимает сетевой обход до логина, чтобы Discord был доступен сразу."""
    global proxy_manager

    load_config()
    proxy_manager = NetBypassManager(network_config, BASE_DIR, log)
    try:
        proxy_url = await proxy_manager.start()
        proxy_manager.attach_client(client)
        # Zapret обходит DPI прозрачно, поэтому прокси в discord.py не нужен.
        client.http.proxy = None if proxy_url in (None, DIRECT_MODE) else proxy_url
    except Exception:
        log.exception(
            "Не удалось инициализировать сетевой обход — работаю напрямую"
        )
        try:
            await proxy_manager.stop()
        except Exception:
            log.debug(
                "Не удалось корректно остановить сетевой обход", exc_info=True
            )
        proxy_manager = None
        client.http.proxy = None

    try:
        await client.start(TOKEN)
    finally:
        if proxy_manager is not None:
            await proxy_manager.stop()


def main() -> None:
    if not TOKEN: raise SystemExit("Укажите DISCORD_TOKEN в .env")

    if not acquire_single_instance_lock():
        log.critical(
            "Уже запущен другой экземпляр Krim Logs. "
            "Второй запуск отменён, чтобы не дублировать ответы."
        )
        raise SystemExit(1)

    enable_dave_decryption()
    init_db()
    try:
        asyncio.run(run_bot())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()