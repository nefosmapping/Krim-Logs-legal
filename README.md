# Krim Logs

Discord-бот для логирования событий, модерации, ИИ-ассистента, транскрипции голоса и обхода блокировок Discord через VLESS, Zapret или пул HTTPS-прокси.

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![discord.py](https://img.shields.io/badge/discord.py-2.7-5865F2?logo=discord&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-WAL-003B57?logo=sqlite&logoColor=white)
![Vosk](https://img.shields.io/badge/STT-Vosk-4B8BBE)
![Network](https://img.shields.io/badge/Bypass-VLESS%20%2B%20Xray%20%2F%20Zapret%20%2F%20HTTPS--proxy-E55302)

| Параметр | Значение |
|---|---|
| Строк кода | 3 655 |
| Функций | 81 |
| Классов | 3 |
| Режимов обхода | 3 (VLESS / Zapret / HTTPS-прокси) |
| Новых команд | `log!proxy`, `log!ping`, `log!deepneuro` |

## Возможности

- **📝 Логирование** — сообщения, редактирование (с diff), удаление, вход/выход из войса, роли, никнеймы, присоединения и уходы — всё уходит в настроенный канал логов.
- **🤖 ИИ-ассистент** — обычный чат по упоминанию, система вежливости с блокировкой и разблокировкой за извинения, досье, анализ текстовых файлов и `.docx`, двухмодельный DeepNeuro (Mini + сильная модель, до 4 шагов рассуждения).
- **🛡️ Модерация** — мьюты (роль или тайм-аут), снятие мьютов с восстановлением после перезапуска, очистка чата с HTML-логом, админские команды с префиксом `log!`, slash-команда `/print` от лица бота.
- **🎙️ Голос** — авто-подключение к голосовым каналам (бот заходит, где есть люди, и выходит, когда все ушли; AFK-канал пропускается), запись через `discord-ext-voice-recv`, DAVE/E2EE-дешифровка голоса, распознавание речи Vosk и HTML-транскрипты с автообновлением.
- **🌐 Сетевой обход** — VLESS через локальный Xray-core, прозрачный Zapret или пул HTTPS-прокси с проверкой TLS, сортировкой по скорости и запасными серверами.
- **🗄️ Хранение** — SQLite (WAL) для контекста ИИ, состояния вежливости, активных мьютов и голосовых транскриптов. JSON-конфиги для настроек.
- **🔒 Запуск в один экземпляр** — lock-файл `krim_logs.lock` не даёт запустить бота дважды (иначе он отвечает на сообщения по два раза).

## Архитектура

Два Python-модуля и один общий сетевой слой. `Krim_logs.py` отвечает за Discord и бизнес-логику, `netbypass.py` — за транспорт до Discord.

### Сетевой поток

```
discord.py → client.http.proxy → netbypass → VLESS / Zapret / HTTPS proxy → Discord
```

discord.py 2.x передаёт прокси и в REST-запросы, и в WebSocket-шлюз, поэтому одного `client.http.proxy` достаточно для обоих каналов. Zapret работает прозрачно (обход DPI на уровне системы), поэтому для него прокси в discord.py не подставляется — используется `DIRECT_MODE`.

### Поток ИИ

```
message → handle_ai / handle_deepneuro → attachments (.txt/.docx) → call_ai → reply
```

Обычный чат использует `model`. DeepNeuro сначала зовёт `deep_mini_model` (Krim DeepNeuro Mini) за черновиком, затем `deep_model` (Krim DeepNeuro) проходит до 4 шагов.

### Поток логов

```
Discord event → send_log → log_channel → Embed/текст
```

События обрабатываются в `on_message`, `on_message_edit` (diff строк через difflib), `on_message_delete`, `on_voice_state_update` и других обработчиках.

## Известные проблемы и ограничения

- **🎙️ Транскрипция нестабильна.** На тестах функция транскрипции голоса не работала корректно, поэтому в рабочем конфиге она отключена (`"voice_auto": false` в `config.json`). Код транскрипции остаётся в проекте, но по умолчанию авто-заход в войс выключен.
- **🌐 Подключение VLESS/Proxy долгое.** При старте бот проверяет сотни и более конфигов из подписки/списков прокси параллельным перебором, поэтому первый выход «в сеть» может занимать продолжительное время. Пайплайн поиска требует оптимизации (см. раздел «Оптимизация» ниже).

## Оптимизация — план на будущее

- Ограничивать `max_candidates` и использовать кэш живых прокси между перезапусками.
- Поднимать `probe_concurrency` / `concurrency` под текущий канал.
- Для VLESS — срезать таймаут пробы (`test_timeout`) и в первую очередь пробовать конфиги, которые уже работали (persist-список успешных узлов).

## Установка и запуск

1. Клонировать репозиторий и создать окружение:

   ```bash
   python -m venv venv
   venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

2. Положить модель распознавания речи рядом со скриптом:

   ```
   vosk-model-small-ru-0.22/   (https://alphacephei.com/vosk/models)
   ```

3. Заполнить `.env`:

   ```env
   DISCORD_TOKEN=токен_бота
   AI_API_KEY=ключ_от_ИИ_эндпоинта
   ADMIN_IDS=ID1,ID2,ID3
   ```

4. Запуск (только интерпретатором из venv):

   - **Windows:** `run.bat` либо `venv\Scripts\python.exe Krim_logs.py`
   - **Linux:** `./run.sh` либо `venv/bin/python Krim_logs.py` (для режима Zapret — через `sudo` или с NOPASSWD для `nft`/`nfqws`)

### requirements.txt

```
aiohttp
discord.py
discord-ext-voice-recv
vosk
python-dotenv
numpy
PyNaCl
```

## Команды

`log!proxy` и `log!deepneuro` защищены проверкой администратора; `log!ping`, `log!dialog-clear` и `@бот <текст>` доступны всем.

| Команда | Доступ | Описание |
|---|---|---|
| `log!proxy` | админы | Активный прокси/VLESS/Zapret: страна, IP, транспорт, запасные |
| `log!ping` | все | TCP-пинг до ya.ru, google.com и relaymodels.com (минимум из 3 попыток) |
| `log!deepneuro "<промпт>" <1-4>` | админы | Сначала Krim DeepNeuro Mini даёт черновик, затем сильная Krim DeepNeuro проходит 1-4 шага. Поддерживает файлы |
| `log!help` | админы | Справка по командам |
| `log!<ID_канала>` | админы | Назначить канал логов |
| `log!off` | админы | Сбросить канал логов |
| `log!stat-<ID>` | админы | HTML-досье пользователя |
| `log!clear <N>` | админы | Очистить чат и получить HTML-лог удалённых сообщений |
| `log!mute <ID> <1m\|1h\|1d>` | админы | Замьютить участника |
| `log!unmute <ID>` | админы | Снять мут |
| `log!join / log!leave` | админы | Подключиться/отключиться от голосового канала |
| `log!dialog-clear` | все | Сбросить контекст диалога с ИИ |
| `@бот <текст>` | все | Обычный ИИ-чат; можно прикрепить до 10 текстовых файлов |
| `/print <текст>` | админы | Slash-команда: отправить сообщение от лица бота |

`log!deepneuro` требует промпт в кавычках и число шагов от 1 до 4: `log!deepneuro "проанализируй отчёт" 3`. Сначала работает Krim DeepNeuro Mini, затем сильная Krim DeepNeuro. К сообщению можно прикрепить текстовые файлы.

## Конфигурация

Настройки разделены на `config.json` (бот и сеть) и `ai_config.json` (модели и ИИ).

### config.json → network

| Параметр | Описание |
|---|---|
| `network.enabled` | Включить/выключить весь сетевой обход |
| `network.mode` | `vless`, `zapret` или `proxy` |
| `network.fallback` | **Список** резервных режимов по порядку: по умолчанию `["zapret", "proxy"]` |
| `network.health_interval` | Период проверки живости активного канала |
| `network.vless.subscription` | URL подписки, строка `vless://` или список строк |
| `network.vless.extra_sources` | Дополнительные источники конфигов (из `DEFAULT_VLESS_EXTRA_SOURCES`) |
| `network.vless.keys_index` | Индекс ключей подписки (`DEFAULT_VLESS_KEY_INDEX`) |
| `network.vless.auto_download` | Автоматически скачать Xray-core с GitHub |
| `network.vless.test_timeout` | Таймаут пробы одного VLESS-конфига, сек |
| `network.vless.probe_concurrency` | Сколько VLESS-конфигов проверять параллельно |
| `network.zapret.base_dir` | Папка с zapret |
| `network.zapret.core_path` | Путь к исполняемому файлу zapret |
| `network.zapret.strategy` | Стратегия обхода (по умолчанию `general.bat`) |
| `network.zapret.interface` | Сетевой интерфейс (опционально) |
| `network.zapret.max_strategies` | Сколько стратегий перебирать (по умолчанию 4) |
| `network.proxy.pool_size` | Сколько запасных прокси держать (по умолчанию 4) |
| `network.proxy.verify_attempts` | Сколько HTTPS-запросов должен выдержать прокси |
| `network.proxy.max_candidates` | Сколько кандидатов проверять за проход |
| `network.proxy.refresh_minutes` | Период обновления списков прокси |

### config.json → бот

| Параметр | Описание |
|---|---|
| `voice_auto` | Авто-заход в войс и транскрипция (на тестах не работала — выключено) |
| `voice_guilds` | Список ID серверов, где разрешена авто-транскрипция |
| `guilds` | Настройки мутов по серверам: `mode` = `role` (роль-мут) или `permissions` (тайм-аут), `mute_role_id` |

### ai_config.json

| Параметр | Описание |
|---|---|
| `model` | Основная модель обычного ИИ-чата |
| `base_url` | OpenAI-совместимый endpoint |
| `deep_mini_enabled` | Включить первичную модель Mini |
| `deep_mini_model` | Модель Krim DeepNeuro Mini (черновик) |
| `deep_mini_max_tokens` | Лимит токенов Mini |
| `deep_mini_temperature` | Температура Mini |
| `deep_mini_timeout` | Таймаут Mini, секунды |
| `deep_mini_system_prompt` | Системная инструкция Mini |
| `deep_model` | Сильная модель Krim DeepNeuro |
| `deep_max_tokens` | Лимит токенов DeepNeuro |
| `deep_temperature` | Температура DeepNeuro |
| `deep_timeout` | Таймаут одного шага DeepNeuro, секунды |
| `deep_system_prompt` | Системная инструкция режима глубокого рассуждения |
| `context_limit` | Сколько сообщений истории передавать в модель |
| `politeness` | Параметры системы вежливости (порог блокировки, слова-извинения и т. д.) |

Подписка VLESS вставляется в `network.vless.subscription` как URL, одна строка `vless://` или список строк.

## Безопасность

- **Права администратора** — список `ADMIN_IDS` из `.env`. Команды `log!proxy` и `log!deepneuro` находятся после админской проверки в `handle_command`.
- **Только HTTPS-прокси** — каждый кандидат проверяется двумя последовательными `CONNECT`-запросами к Discord с валидацией TLS. HTTP-прокси и MITM-прокси отбрасываются.
- **Локальный Xray** — VLESS-инбаунд Xray слушает только `127.0.0.1`. Наружу не открывается порт и не требуется системный VPN-клиент.
- **Ограничения файлов** — до 10 вложений, до 5 МБ на файл, 6000 символов на файл и 15000 символов суммарно. Бинарные файлы пропускаются, поддерживаются 60+ текстовых расширений и `.docx` (парсинг без внешних библиотек).
- **Секреты** — токены и ключи не попадают в HTML-презентацию. В ней только исходный код и примеры конфигурации без значений секретов.
- **Контекст ИИ** — история ограничена `context_limit`, хранится в SQLite и может быть сброшена командой `log!dialog-clear`.
- **Один экземпляр** — lock-файл защищает от двойного запуска и дублирования ответов.

## Карта исходников

### Krim_logs.py — ключевые функции

- `load_config` / `save_config` — конфиг бота и сетевой секции.
- `load_ai_config` — слияние ai_config.json с дефолтами, включая DeepNeuro.
- `handle_ai` — обычный ИИ-чат с файлами (`.txt`, `.docx` и др.) и тегами.
- `handle_deepneuro` — Mini-черновик + до 4 шагов сильной модели.
- `handle_command` — маршрутизация команд `log!` и админ-проверки.
- `handle_proxy_status` / `handle_ping` — диагностика сети.
- `enable_dave_decryption` — патч `PacketRouter.feed_rtp` для расшифровки DAVE/E2EE в войсе.
- `acquire_single_instance_lock` — защита от двойного запуска.
- `auto_voice_worker` / `connect_voice` / `pick_voice_channel` — авто-транскрипция.
- `TranscriptionSink` / `pcm_to_vosk` — приём PCM 48 кГц стерео → 16 кГц моно для Vosk.
- `apply_mute` / `remove_mute` — муты в двух режимах (роль или тайм-аут).
- `run_bot` — поднимает обход до `client.start`.

### netbypass.py — ключевые точки

- `VlessConfig` / `parse_vless` — разбор `vless://` и сборка outbound Xray.
- `_try_vless_from` / `_probe_batch` — параллельный перебор конфигов.
- `_refresh_proxy_pool` — поиск, HTTPS-проверка, сортировка, кэш.
- `_proxy_health` / `_vless_health` — watchdog и ротация.
- Zapret-менеджмент — запуск стратегий, перебор, `DIRECT_MODE`.
- `status` — данные для `log!proxy`.
- `_ensure_xray` — автозагрузка Xray-core.
