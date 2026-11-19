# Krim Logs

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white">
  <img alt="discord.py" src="https://img.shields.io/badge/discord.py-2.7-5865F2?style=for-the-badge&logo=discord&logoColor=white">
  <img alt="SQLite" src="https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white">
  <img alt="Vosk" src="https://img.shields.io/badge/Vosk-STT-4E9F3D?style=for-the-badge">
  <img alt="Xray" src="https://img.shields.io/badge/VLESS%20%2B%20Xray-EF4444?style=for-the-badge">
</p>

**Krim Logs** — монолитный Discord-бот, который совмещает журналирование, модерацию, ИИ-ассистента, голосовую транскрипцию и сетевой обход блокировок Discord через VLESS или пул HTTPS-прокси.

| | |
|---|---|
| 📄 Строк кода | **3 655** |
| 🧩 Функций | **81** |
| 🏗 Классов | **3** |
| ⚡ Режима обхода | **2** (VLESS / HTTPS proxy) |

---

## 📋 Содержание

- [Возможности](#-возможности)
- [Архитектура](#-архитектура)
- [Установка и запуск](#-установка-и-запуск)
- [Команды](#-команды)
- [Конфигурация](#-конфигурация)
- [Безопасность](#-безопасность)
- [Карта исходников](#-карта-исходников)

---

## ✨ Возможности

### 📝 Логирование
Сообщения, редактирование, удаление, вход/выход из войса, роли, никнеймы, присоединения и уходы — всё уходит в настроенный канал логов.

### 🤖 ИИ-ассистент
Обычный чат по упоминанию, система вежливости, блокировки, досье, анализ текстовых файлов и двухмодельный **DeepNeuro** (Mini + сильная модель).

### 🛡️ Модерация
Мьюты, снятие мьютов, очистка чата с HTML-логом, проверка прав и админские команды с префиксом `log!`.

### 🎙️ Голос
Авто-подключение к голосовым каналам, запись через `discord-ext-voice-recv`, распознавание речи **Vosk** и HTML-транскрипты.

### 🌐 Сетевой обход
VLESS через локальный Xray-core или пул HTTPS-прокси с проверкой TLS, сортировкой по скорости и 4 запасными серверами.

### 🗄️ Хранение
SQLite для контекста ИИ, состояния вежливости, активных мьютов и голосовых транскриптов. JSON-конфиги для настроек.

---

## 🏗 Архитектура

Два Python-модуля и один общий сетевой слой. `Krim_logs.py` отвечает за Discord и бизнес-логику, `netbypass.py` — за транспорт до Discord.

### Сетевой поток

```
discord.py → client.http.proxy → netbypass → VLESS / HTTPS proxy → Discord
```

> discord.py 2.x передаёт прокси и в REST-запросы, и в WebSocket-шлюз, поэтому одного `client.http.proxy` достаточно для обоих каналов.

### Поток ИИ

```
message → handle_ai / handle_deepneuro → attachments → call_ai → reply
```

Обычный чат использует `model`. DeepNeuro сначала зовёт `deep_mini_model` (**Krim DeepNeuro Mini**) за черновиком, затем `deep_model` (**Krim DeepNeuro**) проходит до 4 шагов.

### Поток логов

```
Discord event → send_log → log_channel → Embed / текст
```

События обрабатываются в `on_message`, `on_message_edit`, `on_message_delete`, `on_voice_state_update` и других обработчиках.

---

## 🚀 Установка и запуск

**Требования:** Python 3.12+

```bash
# 1. Клонируйте репозиторий и создайте окружение
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt

# 2. Положите модель распознавания речи рядом со скриптом:
#    vosk-model-small-ru-0.22/   (https://alphacephei.com/vosk/models)
```

**Запуск** (только интерпретатором из venv):

```
run.bat
```
или
```bash
venv\Scripts\python.exe Krim_logs.py
```

`run.bat` сам создаёт venv, ставит зависимости (если их нет) и запускает бота.

### Зависимости (requirements.txt)

```
discord.py>=2.4.0
python-dotenv>=1.0.0
aiohttp>=3.8.0
vosk>=0.3.45
discord-ext-voice-recv>=0.4.2
PyNaCl>=1.5.0
```

### Переменные окружения (`.env`)

| Переменная | Назначение |
|---|---|
| `DISCORD_TOKEN` | Токен Discord-бота |
| `AI_API_KEY` | Ключ OpenAI-совместимого API |
| `ADMIN_IDS` | ID администраторов через запятую |

### VLESS

При первом запуске Xray-core скачивается с GitHub в `bin/xray/`. Если GitHub недоступен — положите `xray.exe` туда вручную или укажите `network.vless.core_path`. Подробнее — в `PROXY_SETUP.md`.

---

## ⌨️ Команды

Префикс — `log!`.

| Команда | Доступ | Описание |
|---|---|---|
| `log!proxy` | админы | Активный прокси или VLESS-сервер: страна, IP, транспорт, запасные. |
| `log!ping` | все | TCP-пинг до ya.ru, google.com и relaymodels.com (минимум из 3 попыток). |
| `log!deepneuro "<промпт>" <1-4>` | админы | Сначала Krim DeepNeuro Mini даёт черновик, затем сильная Krim DeepNeuro проходит 1–4 шага. Поддерживает файлы. |
| `log!help` | админы | Справка по командам. |
| `log!<ID_канала>` | админы | Назначить канал логов. |
| `log!off` | админы | Сбросить канал логов. |
| `log!stat-<ID>` | админы | HTML-досье пользователя. |
| `log!clear <N>` | админы | Очистить чат и получить HTML-лог удалённых сообщений. |
| `log!mute <ID> <1m\|1h\|1d>` | админы | Замьютить участника. |
| `log!unmute <ID>` | админы | Снять мут. |
| `log!join` / `log!leave` | админы | Подключиться / отключиться от голосового канала. |
| `log!dialog-clear` | все | Сбросить контекст диалога с ИИ. |
| `@бот <текст>` | все | Обычный ИИ-чат; можно прикрепить до 10 текстовых файлов. |

💡 `log!deepneuro` требует промпт в кавычках и число шагов от 1 до 4:

```
log!deepneuro "проанализируй отчёт" 3
```

Сначала работает Krim DeepNeuro Mini, затем сильная Krim DeepNeuro. К сообщению можно прикрепить текстовые файлы.

---

## ⚙️ Конфигурация

Настройки разделены на `config.json` (бот и сеть) и `ai_config.json` (модели и ИИ).

### config.json → network

| Параметр | Назначение |
|---|---|
| `network.enabled` | Включить/выключить весь сетевой обход. |
| `network.mode` | `vless` или `proxy`. |
| `network.fallback` | `proxy`, `vless` или `none` — резервный режим. |
| `network.vless.subscription` | URL подписки, строка `vless://` или список строк. |
| `network.vless.auto_download` | Автоматически скачать Xray-core с GitHub. |
| `network.vless.probe_concurrency` | Сколько VLESS-конфигов проверять параллельно. |
| `network.proxy.pool_size` | Сколько запасных прокси держать (по умолчанию 4). |
| `network.proxy.verify_attempts` | Сколько HTTPS-запросов должен выдержать прокси. |
| `network.proxy.max_candidates` | Сколько кандидатов проверять за проход. |
| `network.proxy.refresh_minutes` | Период обновления списков прокси. |
| `network.health_interval` | Период проверки живости активного канала. |

Подписка VLESS вставляется в `network.vless.subscription` как URL, одна строка `vless://` или список строк. TXT-заметка больше не читается по умолчанию.

### ai_config.json

| Параметр | Назначение |
|---|---|
| `model` | Основная модель обычного ИИ-чата. |
| `base_url` | OpenAI-совместимый endpoint. |
| `deep_mini_enabled` | Включить первичную модель Mini. |
| `deep_mini_model` | Модель Krim DeepNeuro Mini (черновик). |
| `deep_mini_max_tokens` | Лимит токенов Mini. |
| `deep_mini_temperature` | Температура Mini. |
| `deep_mini_timeout` | Таймаут Mini, секунды. |
| `deep_mini_system_prompt` | Системная инструкция Mini. |
| `deep_model` | Сильная модель Krim DeepNeuro. |
| `deep_max_tokens` | Лимит токенов DeepNeuro. |
| `deep_temperature` | Температура DeepNeuro. |
| `deep_timeout` | Таймаут одного шага DeepNeuro, секунды. |
| `deep_system_prompt` | Системная инструкция режима глубокого рассуждения. |
| `context_limit` | Сколько сообщений истории передавать в модель. |
| `politeness` | Параметры системы вежливости. |

---

## 🔒 Безопасность

### Права администратора
Список `ADMIN_IDS` из `.env`. Команды `log!proxy` и `log!deepneuro` находятся после админской проверки в `handle_command`.

### Только HTTPS-прокси
Каждый кандидат проверяется двумя последовательными `CONNECT`-запросами к Discord с валидацией TLS. HTTP-прокси и MITM-прокси отбрасываются.

### Локальный Xray
VLESS-инбаунд Xray слушает только `127.0.0.1`. Наружу не открывается порт и не требуется системный VPN-клиент.

### Ограничения файлов
До 10 вложений, до 5 МБ на файл, 6 000 символов на файл и 15 000 символов суммарно. Бинарные файлы пропускаются.

### Секреты
Токены и ключи не попадают в документацию и примеры конфигурации — храните их только в `.env`.

### Контекст ИИ
История ограничена `context_limit`, хранится в SQLite и может быть сброшена командой `log!dialog-clear`.

---

## 🗺 Карта исходников

### `Krim_logs.py` — ключевые функции

| Функция | Что делает |
|---|---|
| `load_config` / `save_config` | Конфиг бота и сетевой секции. |
| `load_ai_config` | Слияние `ai_config.json` с дефолтами, включая DeepNeuro. |
| `handle_ai` | Обычный ИИ-чат с файлами и тегами. |
| `handle_deepneuro` | Mini-черновик + до 4 шагов сильной модели. |
| `handle_command` | Маршрутизация команд `log!` и админ-проверки. |
| `handle_proxy_status` / `handle_ping` | Диагностика сети. |
| `run_bot` | Поднимает обход до `client.start`. |

### `netbypass.py` — ключевые точки

| Функция | Что делает |
|---|---|
| `VlessConfig` / `parse_vless` | Разбор `vless://` и сборка outbound Xray. |
| `_try_vless_from` / `_probe_batch` | Параллельный перебор конфигов. |
| `_refresh_proxy_pool` | Поиск, HTTPS-проверка, сортировка, кэш. |
| `_proxy_health` / `_vless_health` | Watchdog и ротация. |
| `status` | Данные для `log!proxy`. |
| `_ensure_xray` | Автозагрузка Xray-core. |

---

<p align="center">
  <sub>Krim Logs · монолитный бот-логгер · секреты не включены в репозиторий</sub>
</p>
