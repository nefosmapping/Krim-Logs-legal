# Обход блокировок Discord в Krim Logs

Бот умеет работать без отдельного VPN-клиента. Весь трафик `discord.py`
(HTTP API и WebSocket-шлюз) идёт через один локальный или внешний HTTP-прокси,
который выбирает менеджер `netbypass.py`.

Поддерживаются два режима:

| Режим | Что делает |
|---|---|
| `vless` | Берёт VLESS-подписку из `config.json`, при необходимости скачивает Xray-core, поднимает локальный HTTP-прокси `127.0.0.1:<порт>` и перебирает конфиги до первого рабочего. |
| `proxy` | Скачивает публичные списки прокси, строго проверяет их по HTTPS, сортирует по скорости и держит активный сервер + 4 запасных. |

Если основной режим не поднялся, бот автоматически пробует резервный
(`network.fallback`). Если не поднялся ни один — работает напрямую, как раньше.

---

## Быстрый старт

1. Запустите бота один раз (или создайте `config.json` вручную) — секция
   `network` появится в конфиге автоматически.
2. Откройте `config.json`.
3. Включите обход:

```json
"network": {
  "enabled": true
}
```

4. Выберите режим:

```json
"mode": "vless"
```

или

```json
"mode": "proxy"
```

5. Запустите `run.bat`.

При первом запуске в режиме `vless` бот скачает Xray-core с GitHub в
`bin/xray/` (около 15 МБ). Дальше он запускается локально.

---

## Полный пример `config.json`

```json
{
  "log_channel_id": null,
  "emperial_id": null,
  "guilds": {},
  "voice_auto": false,
  "voice_guilds": [],
  "network": {
    "enabled": true,
    "mode": "vless",
    "fallback": "proxy",
    "health_interval": 60,
    "vless": {
      "subscription": "https://warp-gen.cyb-portal.org/CP-040",
      "subscription_file": "",
      "subscription_url": "",
      "core_path": "",
      "auto_download": true,
      "local_port": 0,
      "max_attempts": 0,
      "startup_timeout": 8,
      "probe_concurrency": 6
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
        "https://proxyspace.pro/https.txt"
      ],
      "pool_size": 4,
      "test_url": "https://discord.com/api/v10/gateway",
      "test_timeout": 8,
      "verify_attempts": 2,
      "max_candidates": 300,
      "cache_limit": 50,
      "concurrency": 60,
      "refresh_minutes": 30
    }
  }
}
```

---

## Режим `vless`

### Куда вставлять подписку

Поле `network.vless.subscription` принимает три варианта.

**1. URL подписки (по умолчанию):**

```json
"subscription": "https://warp-gen.cyb-portal.org/CP-040"
```

**2. Одна или несколько `vless://` строк в одной строке:**

```json
"subscription": "vless://...\nvless://..."
```

В JSON перевод строки записывается как `\n`.

**3. Список строк — самый удобный вариант для вставки:**

```json
"subscription": [
  "vless://77998cc6-8a4d-4251-b974-ebff48a84c4d@95.129.236.117:443?type=ws&security=tls&sni=example.com#node1",
  "vless://11aabba0-5fd1-4f15-8068-74c1a466cefc@193.163.203.170:443?type=tcp&security=reality&flow=xtls-rprx-vision&pbk=...&sid=...&sni=yandex.ru#node2"
]
```

Можно смешивать URL и `vless://` строки в одном списке. Текстовый файл
`vless подписка киберщит.txt` больше не нужен — он остаётся только как заметка.
Старые поля `subscription_file` и `subscription_url` поддерживаются для
совместимости, но по умолчанию пусты.

### Параметры VLESS

| Параметр | Смысл |
|---|---|
| `core_path` | Путь к готовому `xray.exe` / `xray`. Пусто — искать в `bin/xray/`. |
| `auto_download` | `true` — скачать Xray-core с GitHub, если его нет. |
| `local_port` | `0` — случайный свободный порт. Фиксированный порт включает последовательную проверку конфигов. |
| `max_attempts` | `0` — проверить все конфиги. Число — ограничить перебор. |
| `startup_timeout` | Сколько секунд ждать открытия локального порта Xray. |
| `probe_concurrency` | Сколько конфигов проверять параллельно (1–16). Ускоряет старт. |

### Как выбирается конфиг

1. Подписка скачивается и кэшируется в `data/netbypass/subscription_cache.txt`.
2. Конфиги дедуплицируются и сортируются: сначала reality/tcp, затем ws/tls,
   затем более экзотические транспорты.
3. Последний рабочий конфиг из `data/netbypass/last_good.txt` поднимается в
   начало очереди — повторные запуски быстрее.
4. Конфиги проверяются пачками: для каждого временно запускается Xray на своём
   порту и делается HTTPS-запрос к Discord. Побеждает самый быстрый рабочий.
5. При падении туннеля watchdog останавливает Xray и перебирает следующий
   конфиг. Если не помогло — обновляет подписку и пробует заново. Если и это
   не помогло — переключается на пул прокси.

---

## Режим `proxy`

1. Бот скачивает все источники из `network.proxy.sources`.
2. Парсит строки `ip:port`, `http://ip:port`, `https://ip:port`.
3. Проверяет каждый кандидат **только по HTTPS**: `CONNECT` к
   `test_url` с проверкой TLS-сертификата. HTTP-прокси и прокси с подменой
   сертификата отбрасываются.
4. Делает `verify_attempts` последовательных запросов — так отсеиваются
   прокси, которые отдают один ответ и умирают.
5. Сортирует по задержке: первый — активный, следующие `pool_size` (по
   умолчанию 4) — запасные.
6. Каждые `health_interval` секунд проверяет активный. Если тот отвалился —
   берёт запасной, а пул пополняет новым поиском.
7. Раз в `refresh_minutes` минут обновляет список источников.
8. Рабочие адреса сохраняются в `data/netbypass/proxy_pool_cache.json`
   (до `cache_limit` штук) и проверяются при следующем запуске.

| Параметр | Смысл |
|---|---|
| `sources` | Любые URL, отдающие список `ip:port` (по одному в строке). |
| `pool_size` | Сколько запасных держать. По умолчанию 4. |
| `test_url` | HTTPS-URL проверки. По умолчанию Discord gateway. |
| `test_timeout` | Таймаут одной проверки, секунды. |
| `verify_attempts` | Сколько успешных запросов подряд должен выдержать прокси. |
| `max_candidates` | Сколько кандидатов проверять за один проход. |
| `cache_limit` | Сколько рабочих прокси запоминать. |
| `concurrency` | Сколько прокси проверять одновременно. |
| `refresh_minutes` | Период обновления списков. |

---

## Общие параметры

| Параметр | Смысл |
|---|---|
| `enabled` | `false` — полностью выключить обход и работать напрямую. |
| `mode` | `"vless"` или `"proxy"`. |
| `fallback` | `"proxy"`, `"vless"` или `"none"` — резервный режим. |
| `health_interval` | Период проверки живости активного канала, секунды. |

---

## Где смотреть диагностику

- `logs/krim_logs_*.log` — основной лог бота, строки `netbypass`.
- `data/netbypass/xray-*.log` — лог конкретного запуска Xray.
- `data/netbypass/xray-*.json` — сгенерированный конфиг Xray.
- `data/netbypass/last_good.txt` — последний рабочий VLESS-конфиг.
- `data/netbypass/proxy_pool_cache.json` — кэш рабочих прокси.
- `data/netbypass/subscription_cache.txt` — последняя скачанная подписка.

---

## Режим `zapret` (обход DPI без сервера)

Zapret не требует подписки и VPN-сервера: он искажает TLS/QUIC-пакеты так,
чтобы DPI не распознал соединение с Discord. Режим работает прозрачно, поэтому
discord.py ходит напрямую (`proxy = None`), а обход выполняется на уровне ОС.

```json
"network": {
  "enabled": true,
  "mode": "zapret",
  "fallback": ["vless", "proxy"],
  "zapret": {
    "base_dir": "",
    "core_path": "",
    "strategy": "general.bat",
    "interface": "",
    "max_strategies": 4
  }
}
```

Бот сам находит папку Zapret: `zapret*` рядом с ботом, в родительском каталоге
или в домашней папке. Ядро и стратегия определяются автоматически
(`nfqws` + `nftables` на Linux, `winws.exe` + WinDivert на Windows).

### Linux (Raspberry Pi OS / Debian)

Zapret требует root и пакет `libnetfilter-queue1`:

```bash
sudo apt update
sudo apt install -y nftables libnetfilter-queue1
```

Затем либо запускайте бота через sudo:

```bash
sudo ./run.sh
```

либо разрешите `nft` и `nfqws` без пароля:

```bash
# путь к nfqws подставьте свой (см. network.zapret.base_dir)
NFQWS=/home/krim/zapret-discord-youtube-linux-arm64/nfqws
echo "krim ALL=(root) NOPASSWD: /usr/sbin/nft, $NFQWS, /usr/bin/pkill" \
  | sudo tee /etc/sudoers.d/krim-zapret
sudo chmod 0440 /etc/sudoers.d/krim-zapret
```

Бот вызывает `nft -f -` (без промежуточного `sh`), поэтому в sudoers нужен
только сам `nft`, ядро `nfqws` и `pkill` для очистки процессов.

После этого бот запускается обычным `./run.sh`, а режим `zapret` используется
как резервный (или основной — по `network.mode`).

### Windows

Нужны права администратора и папка Zapret с `winws.exe` + WinDivert
(например, сборка Flowseal). Запустите бота от имени администратора.

### Если Zapret не поднялся

Бот пишет причину в лог и переходит к следующему режиму из `fallback`.
Типичные причины: нет прав root/администратора, не установлен
`libnetfilter-queue1`, не найден интерфейс (`network.zapret.interface`),
стратегия не подходит для провайдера (увеличьте `max_strategies`).

**Важно:** Zapret обходит DPI, но не IP-блокировки. Если соединение к
`discord.com:443` обрывается по TCP-таймауту (curl возвращает `000`, а
Google при этом открывается), провайдер блокирует адреса на уровне
маршрутизации — в этом случае поможет только VLESS/прокси/VPN. Проверка:
`curl -m 8 -o /dev/null -w "%{http_code}" https://discord.com/api/v10/gateway`.

---

## Ограничения

- **Голосовой канал Discord использует UDP.** HTTP-прокси и VLESS-туннель
  покрывают REST и WebSocket, но не UDP-трафик голоса. Автотранскрипция войса
  может не работать, если Discord Voice заблокирован на уровне сети.
- **Бесплатные прокси нестабильны.** Даже после двух проверок они могут
  умереть через минуту. Watchdog ротирует их автоматически, но пул из 4
  запасных не всегда удаётся набрать: это зависит от источников. Увеличьте
  `max_candidates`, добавьте свои источники или используйте VLESS.
- **VLESS-подписка может устареть.** Если все конфиги перестали отвечать,
  обновите `subscription` в `config.json`.
- **Xray-core скачивается с GitHub.** Если GitHub недоступен, положите
  `xray.exe` в `bin/xray/` или укажите `core_path` вручную.
- **Проверка TLS.** Прокси с самоподписанным сертификатом или MITM не
  попадут в пул — это сделано намеренно.
