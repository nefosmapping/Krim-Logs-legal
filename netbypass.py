"""
netbypass.py — обход блокировок Discord для Krim Logs.

Поддерживаются три независимых режима, переключаемых в config.json:

  network.mode = "vless"
      Берёт VLESS-подписку (файл рядом с ботом или URL), BLACK/WHITE-списки
      для России (igareck/vpn-configs-for-russia) и индекс проверенных ключей
      (tiagorrg/vless-checker), при необходимости скачивает Xray-core,
      поднимает локальный HTTP-прокси 127.0.0.1:<port> и гоняет весь трафик
      discord.py через него. Конфиги перебираются до первого рабочего; при
      падении туннеля происходит ротация на следующий конфиг.

  network.mode = "proxy"
      На старте скачивает публичные списки прокси, проверяет их строго по
      HTTPS (CONNECT + валидный TLS до discord.com), сортирует по скорости и
      держит активный сервер + N запасных (по умолчанию 4). При отказе
      активного прокси бот переключается на запасной, а пул пополняется.

  network.mode = "zapret"
      Обход DPI без сервера: на Linux запускает nfqws + nftables, на Windows —
      winws.exe + WinDivert. Работает прозрачно, discord.py ходит напрямую.
      Требует root/администратора и пакет libnetfilter-queue1 на Linux.
      Помогает только при DPI-блокировках: если IP серверов Discord
      заблокирован на уровне маршрутизации (TCP-таймаут), нужен VLESS.

Резервные режимы задаются списком network.fallback и пробуются по порядку.

Наружу отдаётся один HTTP-прокси URL. discord.py 2.x передаёт его и в REST
(`HTTPClient.request`), и в WebSocket (`HTTPClient.ws_connect`), поэтому
менеджер просто выставляет `client.http.proxy`. Для Zapret прокси не нужен —
возвращается маркер ``DIRECT_MODE``, и клиент работает напрямую.

Модуль не импортирует discord — только aiohttp и стандартную библиотеку.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import platform
import random
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, unquote, urlsplit

import aiohttp


DEFAULT_TEST_URL = "https://discord.com/api/v10/gateway"
DEFAULT_SUBSCRIPTION_URL = "https://warp-gen.cyb-portal.org/CP-040"

# Дополнительные источники VLESS-ключей для России. Список BLACK обновляется
# автором ежедневно и содержит ключи, рассчитанные на обход блокировок РФ.
DEFAULT_VLESS_EXTRA_SOURCES = (
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt",
)

# Готовый индекс уже проверенных ключей (tiagorrg/vless-checker, обновляется
# по расписанию GitHub Actions). Ключи оттуда пробуются первыми.
DEFAULT_VLESS_KEY_INDEX = (
    "https://raw.githubusercontent.com/tiagorrg/vless-checker/main/docs/keys.json"
)

# Маркер режима Zapret: он не даёт HTTP-прокси, а прозрачно обходит DPI,
# поэтому discord.py должен ходить напрямую (proxy=None).
DIRECT_MODE = "direct"

# Публичные списки прокси. Проверка всё равно жёсткая: прокси попадёт в пул
# только если через него открывается HTTPS-страница Discord с валидным TLS.
DEFAULT_PROXY_SOURCES = (
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
)

SUPPORTED_NETWORKS = {"tcp", "raw", "ws", "grpc", "httpupgrade", "xhttp", "h2", "http"}


# ---------------------------------------------------------------------------
# VLESS
# ---------------------------------------------------------------------------


@dataclass
class _ProbeResult:
    """Результат удачной проверки одного VLESS-конфига."""

    index: int
    cfg: "VlessConfig"
    latency: float
    proxy_url: str
    port: int
    proc: asyncio.subprocess.Process
    log_handle: Any
    config_path: Path


@dataclass
class VlessConfig:
    """Разобранная vless:// ссылка, готовая к превращению в outbound Xray."""

    raw: str
    uuid: str
    address: str
    port: int
    network: str = "tcp"
    security: str = "none"
    sni: str = ""
    host: str = ""
    path: str = "/"
    service_name: str = ""
    flow: str = ""
    fingerprint: str = "chrome"
    public_key: str = ""
    short_id: str = ""
    mode: str = ""
    header_type: str = "none"
    alpn: str = ""
    packet_encoding: str = ""
    extra: Optional[dict] = None
    label: str = ""
    priority: int = 0

    @property
    def key(self) -> tuple:
        return (
            self.uuid,
            self.address,
            self.port,
            self.network,
            self.security,
            self.path,
            self.sni,
            self.service_name,
        )

    @property
    def name(self) -> str:
        if self.label:
            return self.label
        return f"{self.address}:{self.port} [{self.network}/{self.security}]"

    def score(self) -> int:
        """Чем больше, тем раньше пробуем конфиг."""
        # Ключи из проверенного индекса и BLACK-списков важнее случайной
        # подписки, поэтому приоритет источника доминирует над типом транспорта.
        score = self.priority * 1000
        if self.security == "reality":
            score += 40
        elif self.security == "tls":
            score += 25
        if self.network in ("tcp", "raw"):
            score += 15
        elif self.network == "ws":
            score += 12
        elif self.network == "grpc":
            score -= 5
        elif self.network == "httpupgrade":
            score -= 8
        elif self.network == "xhttp":
            score -= 15
        if self.flow:
            score += 5
        return score

    def outbound(self) -> dict:
        network = "tcp" if self.network in ("tcp", "raw") else self.network
        stream: dict[str, Any] = {"network": network, "security": self.security}

        if self.security == "tls":
            tls: dict[str, Any] = {
                "serverName": self.sni or self.host or self.address,
                "allowInsecure": False,
            }
            if self.fingerprint:
                tls["fingerprint"] = self.fingerprint
            if self.alpn:
                tls["alpn"] = [x.strip() for x in self.alpn.split(",") if x.strip()]
            stream["tlsSettings"] = tls
        elif self.security == "reality":
            stream["realitySettings"] = {
                "serverName": self.sni or self.host or self.address,
                "fingerprint": self.fingerprint or "chrome",
                "publicKey": self.public_key,
                "shortId": self.short_id,
                "spiderX": "/",
                "show": False,
            }

        if network == "tcp":
            stream["tcpSettings"] = {"header": {"type": self.header_type or "none"}}
        elif network == "ws":
            stream["wsSettings"] = {
                "path": self.path or "/",
                "headers": {"Host": self.host or self.sni or self.address},
            }
        elif network == "grpc":
            stream["grpcSettings"] = {
                "serviceName": self.service_name,
                "multiMode": self.mode == "multi",
            }
        elif network == "httpupgrade":
            stream["httpupgradeSettings"] = {
                "path": self.path or "/",
                "host": self.host or self.sni or self.address,
            }
        elif network == "xhttp":
            xhttp: dict[str, Any] = {
                "path": self.path or "/",
                "host": self.host or self.sni or self.address,
                "mode": self.mode or "auto",
            }
            if self.extra:
                xhttp["extra"] = self.extra
            stream["xhttpSettings"] = xhttp
        elif network in ("h2", "http"):
            stream["network"] = "h2"
            stream["httpSettings"] = {
                "path": self.path or "/",
                "host": [self.host or self.sni or self.address],
            }

        user: dict[str, Any] = {"id": self.uuid, "encryption": "none"}
        if self.flow:
            user["flow"] = self.flow
        if self.packet_encoding:
            user["packetEncoding"] = self.packet_encoding

        return {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": self.address,
                        "port": self.port,
                        "users": [user],
                    }
                ]
            },
            "streamSettings": stream,
        }


def parse_vless(uri: str) -> Optional[VlessConfig]:
    """Разбирает vless:// ссылку. Возвращает None, если конфиг не поддержан."""
    uri = (uri or "").strip()
    if not uri.lower().startswith("vless://"):
        return None
    try:
        parts = urlsplit(uri)
    except ValueError:
        return None

    if parts.scheme.lower() != "vless" or not parts.username or not parts.hostname:
        return None
    try:
        port = int(parts.port or 443)
    except (TypeError, ValueError):
        return None

    query = {k.lower(): v for k, v in parse_qs(parts.query, keep_blank_values=True).items()}

    def q1(*names: str, default: str = "") -> str:
        for name in names:
            values = query.get(name.lower())
            if values:
                return values[0]
        return default

    network = q1("type", "network", default="tcp").lower()
    if network not in SUPPORTED_NETWORKS:
        return None

    security = q1("security", default="none").lower()
    if security not in ("none", "tls", "reality"):
        return None

    public_key = q1("pbk")
    if security == "reality" and not public_key:
        return None

    extra: Optional[dict] = None
    raw_extra = q1("extra")
    if raw_extra:
        try:
            parsed_extra = json.loads(raw_extra)
            if isinstance(parsed_extra, dict):
                extra = parsed_extra
        except (TypeError, ValueError):
            extra = None

    return VlessConfig(
        raw=uri,
        uuid=parts.username,
        address=parts.hostname,
        port=port,
        network=network,
        security=security,
        sni=q1("sni"),
        host=q1("host"),
        path=q1("path", default="/") or "/",
        service_name=q1("servicename"),
        flow=q1("flow"),
        fingerprint=q1("fp", default="chrome") or "chrome",
        public_key=public_key,
        short_id=q1("sid"),
        mode=q1("mode"),
        header_type=q1("headertype", default="none") or "none",
        alpn=q1("alpn"),
        packet_encoding=q1("packetencoding"),
        extra=extra,
        label=unquote(parts.fragment or ""),
    )


# ---------------------------------------------------------------------------
# Менеджер обхода
# ---------------------------------------------------------------------------


class NetBypassManager:
    """Единая точка управления VLESS-туннелем и пулом HTTPS-прокси."""

    def __init__(self, config: dict, base_dir: Path, logger: logging.Logger):
        self.config: dict = config or {}
        self.base_dir = Path(base_dir)
        self.log = logger.getChild("netbypass") if hasattr(logger, "getChild") else logger

        self._mode: Optional[str] = None
        self._proxy_url: Optional[str] = None
        self._client: Any = None
        self._zapret_active: bool = False
        self._zapret_proc: Optional[asyncio.subprocess.Process] = None
        self._zapret_procs: list[asyncio.subprocess.Process] = []
        self._zapret_nft_rules: list[str] = []
        self._zapret_interface: str = ""
        self._zapret_desc: str = ""
        self._sudo_checked: Optional[bool] = None
        self._nfqws_opts: Optional[set[str]] = None

        self._stop = asyncio.Event()
        self._watchdog_task: Optional[asyncio.Task] = None
        self._refresh_lock = asyncio.Lock()
        self._rotate_lock = asyncio.Lock()

        self._xray_proc: Optional[asyncio.subprocess.Process] = None
        self._xray_log: Optional[Any] = None
        self._xray_port: Optional[int] = None
        self._xray_cfg_path: Optional[Path] = None
        self._xray_exe: Optional[str] = None

        self._vless_pool: list[VlessConfig] = []
        self._vless_index: int = -1
        self._vless_priority: dict[str, int] = {}
        self._backups: list[str] = []
        self._last_refresh: float = 0.0

        data_dir = self.base_dir / "data" / "netbypass"
        self._cache_file = data_dir / "subscription_cache.txt"
        self._last_good_file = data_dir / "last_good.txt"
        self._proxy_cache_file = data_dir / "proxy_pool_cache.json"

    # -- публичный API ------------------------------------------------------

    @property
    def proxy_url(self) -> Optional[str]:
        return self._proxy_url

    @property
    def enabled(self) -> bool:
        return bool(self.config.get("enabled", False))

    def describe(self) -> str:
        if self._mode == "zapret" and self._zapret_active:
            return self._zapret_desc or "Zapret (обход DPI)"
        if not self._proxy_url:
            return "выключен"
        if self._mode == "vless":
            cfg = None
            if 0 <= self._vless_index < len(self._vless_pool):
                cfg = self._vless_pool[self._vless_index]
            return f"VLESS ({cfg.name if cfg else '?'}) через {self._proxy_url}"
        return (
            f"HTTPS-прокси {self._proxy_url} "
            f"(запасных: {len(self._backups)}/{self._pool_size})"
        )

    def status(self) -> dict:
        """Машиночитаемое состояние для команды log!proxy."""
        vless = None
        if 0 <= self._vless_index < len(self._vless_pool):
            cfg = self._vless_pool[self._vless_index]
            vless = {
                "name": cfg.name,
                "address": cfg.address,
                "port": cfg.port,
                "network": cfg.network,
                "security": cfg.security,
            }
        return {
            "enabled": self.enabled,
            "mode": self._mode,
            "proxy_url": self._proxy_url,
            "vless": vless,
            "backups": list(self._backups),
            "pool_size": self._pool_size,
            "zapret": {
                "active": self._zapret_active,
                "interface": self._zapret_interface,
                "description": self._zapret_desc,
            }
            if self._mode == "zapret"
            else None,
        }

    def attach_client(self, client: Any) -> None:
        """Привязывает discord.py-клиент, чтобы менеджер мог менять прокси."""
        self._client = client
        try:
            client.http.proxy = None if self._zapret_active else self._proxy_url
        except Exception:
            self.log.debug("Не удалось сразу выставить прокси в клиенте", exc_info=True)

    async def start(self) -> Optional[str]:
        """Поднимает выбранный режим. Возвращает URL HTTP-прокси или None.

        Zapret не создаёт прокси, поэтому в этом режиме возвращается маркер
        ``DIRECT_MODE``: discord.py работает напрямую, а DPI обходится на
        уровне ОС (nfqws + nftables на Linux, winws + WinDivert на Windows).
        """
        if not self.enabled:
            self.log.info("Сетевой обход отключён (network.enabled=false)")
            return None

        self._stop.clear()
        mode = str(self.config.get("mode", "vless")).strip().lower()
        self.log.info("Сетевой обход включён, режим: %s", mode)

        # Резервные режимы: fallback может быть строкой или списком строк.
        raw_fallback = self.config.get("fallback", "proxy")
        if isinstance(raw_fallback, str):
            fallbacks = [raw_fallback]
        elif isinstance(raw_fallback, (list, tuple)):
            fallbacks = [str(item) for item in raw_fallback]
        else:
            fallbacks = []
        chain: list[str] = [mode]
        for item in fallbacks:
            item = item.strip().lower()
            if item and item not in chain:
                chain.append(item)

        url: Optional[str] = None
        for index, candidate in enumerate(chain):
            if index:
                self.log.warning(
                    "Режим %s не поднялся — пробую резервный режим %s",
                    chain[index - 1],
                    candidate,
                )
            try:
                url = await self._start_mode(candidate)
            except Exception:
                self.log.exception("Ошибка запуска режима %s", candidate)
                url = None
            if url:
                break

        if not url:
            self.log.error(
                "Не удалось поднять сетевой обход — работаю напрямую. "
                "Discord может быть недоступен без системного VPN."
            )
            return None

        self._apply(url, "start")
        self._watchdog_task = asyncio.create_task(
            self._watchdog(), name="netbypass-watchdog"
        )
        self.log.info("Сетевой обход активен: %s", self.describe())
        return url

    async def _start_mode(self, mode: str) -> Optional[str]:
        """Запускает один конкретный режим обхода."""
        if mode == "vless":
            return await self._start_vless()
        if mode == "proxy":
            return await self._start_proxy()
        if mode == "zapret":
            return await self._start_zapret()
        if mode in ("none", "direct", "off"):
            self._mode = "direct"
            return DIRECT_MODE if await self._test_direct() else None
        self.log.error(
            "Неизвестный network.mode=%r (ожидается 'vless', 'proxy' или 'zapret')",
            mode,
        )
        return None

    async def stop(self) -> None:
        self._stop.set()
        task = self._watchdog_task
        self._watchdog_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        await self._stop_xray()
        await self._stop_zapret()
        if self._client is not None:
            try:
                self._client.http.proxy = None
            except Exception:
                pass

    # -- настройки ----------------------------------------------------------

    def _section(self, name: str) -> dict:
        value = self.config.get(name)
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _int(cfg: dict, key: str, default: int) -> int:
        try:
            return int(cfg.get(key, default))
        except (TypeError, ValueError):
            return default

    @property
    def _test_url(self) -> str:
        return str(self._section("proxy").get("test_url") or DEFAULT_TEST_URL)

    @property
    def _test_timeout(self) -> int:
        return max(2, self._int(self._section("proxy"), "test_timeout", 8))

    @property
    def _vless_test_timeout(self) -> int:
        # VLESS-туннелю нужно больше времени на TLS/Reality handshake, чем
        # обычному HTTP-прокси, поэтому таймаут задаётся отдельно.
        return max(3, self._int(self._section("vless"), "test_timeout", 15))

    @property
    def _pool_size(self) -> int:
        return max(1, self._int(self._section("proxy"), "pool_size", 4))

    @property
    def _concurrency(self) -> int:
        return max(1, self._int(self._section("proxy"), "concurrency", 60))

    @property
    def _max_candidates(self) -> int:
        return max(1, self._int(self._section("proxy"), "max_candidates", 300))

    @property
    def _cache_limit(self) -> int:
        return max(5, self._int(self._section("proxy"), "cache_limit", 50))

    @property
    def _health_interval(self) -> int:
        return max(10, self._int(self.config, "health_interval", 60))

    @property
    def _startup_timeout(self) -> int:
        return max(3, self._int(self._section("vless"), "startup_timeout", 8))

    @property
    def _probe_concurrency(self) -> int:
        return max(1, min(16, self._int(self._section("vless"), "probe_concurrency", 6)))

    @property
    def _local_port(self) -> int:
        value = self._int(self._section("vless"), "local_port", 0)
        return value if 0 < value < 65536 else 0

    @property
    def _verify_attempts(self) -> int:
        return max(1, min(3, self._int(self._section("proxy"), "verify_attempts", 2)))

    # -- проверка доступности ----------------------------------------------

    async def _test_proxy(
        self,
        proxy_url: str,
        session: Optional[aiohttp.ClientSession] = None,
        confirm: Optional[int] = None,
        timeout: Optional[int] = None,
    ) -> Optional[float]:
        """Проверяет прокси запросом к Discord по HTTPS. Возвращает мс или None.

        confirm — сколько последовательных запросов должен выдержать прокси.
        Для пула бесплатных прокси двух проверок достаточно, чтобы отсеять
        сервера, которые отдают ровно один ответ и сразу умирают.
        """
        attempts = self._verify_attempts if confirm is None else max(1, confirm)
        total = max(2, timeout or self._test_timeout)
        own_session = session is None
        if own_session:
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=total),
                connector=aiohttp.TCPConnector(force_close=True),
            )
        try:
            latency: Optional[float] = None
            for _ in range(attempts):
                current = await self._single_proxy_request(
                    proxy_url, session, total
                )
                if current is None:
                    return None
                if latency is None:
                    latency = current
            return latency
        finally:
            if own_session:
                await session.close()

    async def _single_proxy_request(
        self,
        proxy_url: str,
        session: aiohttp.ClientSession,
        timeout: Optional[int] = None,
    ) -> Optional[float]:
        try:
            started = time.perf_counter()
            total = max(2, timeout or self._test_timeout)
            async with session.get(
                self._test_url,
                proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=total),
                allow_redirects=False,
                headers={"Connection": "close"},
            ) as response:
                if response.status not in (200, 204):
                    return None
                body = await response.read()
            # Discord gateway отвечает JSON вида {"url": "wss://gateway.discord.gg"}
            if b'"url"' not in body and b"discord" not in body.lower():
                return None
            return (time.perf_counter() - started) * 1000.0
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError):
            return None
        except Exception:
            self.log.debug("Ошибка проверки прокси %s", proxy_url, exc_info=True)
            return None

    async def _test_direct(self, timeout: Optional[int] = None) -> bool:
        """Проверяет Discord без прокси (нужно для режима Zapret)."""
        total = max(3, timeout or self._vless_test_timeout)
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=total),
                connector=aiohttp.TCPConnector(force_close=True),
            ) as session:
                async with session.get(
                    self._test_url,
                    allow_redirects=False,
                    headers={"Connection": "close"},
                ) as response:
                    if response.status not in (200, 204):
                        return False
                    body = await response.read()
                    return b'"url"' in body or b"discord" in body.lower()
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError):
            return False
        except Exception:
            self.log.debug("Ошибка прямой проверки Discord", exc_info=True)
            return False

    # -- режим VLESS --------------------------------------------------------

    async def _start_vless(self) -> Optional[str]:
        self._mode = "vless"
        pool = await self._load_vless_configs()
        if not pool:
            self.log.error(
                "VLESS: не удалось получить конфиги из подписки "
                "(заполните network.vless.subscription в config.json)"
            )
            return None

        exe = await asyncio.to_thread(self._ensure_xray)
        if not exe:
            self.log.error(
                "VLESS: ядро Xray-core не найдено. Включите network.vless.auto_download "
                "или укажите network.vless.core_path"
            )
            return None

        self._xray_exe = exe
        self._vless_pool = pool
        self._vless_index = -1

        last_good = self._read_last_good()
        if last_good:
            for position, cfg in enumerate(pool):
                if cfg.raw == last_good:
                    pool.insert(0, pool.pop(position))
                    self.log.info("VLESS: последний рабочий конфиг поднят в начало очереди")
                    break

        self.log.info(
            "VLESS: загружено %d уникальных конфигов, проверяю пачками по %d",
            len(pool),
            self._probe_concurrency,
        )
        return await self._try_vless_from(0, wrap=False)

    async def _try_vless_from(self, start: int, wrap: bool) -> Optional[str]:
        async with self._rotate_lock:
            total = len(self._vless_pool)
            if total == 0:
                return None

            # Старый (уже нерабочий) туннель больше не нужен.
            await self._stop_xray()

            max_attempts = self._int(self._section("vless"), "max_attempts", 0)
            limit = total if max_attempts <= 0 else min(max_attempts, total)
            order = [(start + offset) % total for offset in range(limit)]
            batch_size = 1 if self._local_port else self._probe_concurrency

            for offset in range(0, len(order), batch_size):
                batch = order[offset : offset + batch_size]
                self.log.info(
                    "VLESS: проверяю конфиги %d-%d из %d",
                    offset + 1,
                    offset + len(batch),
                    len(order),
                )
                winner = await self._probe_batch(batch)
                if winner is None:
                    continue

                self._xray_proc = winner.proc
                self._xray_log = winner.log_handle
                self._xray_port = winner.port
                self._xray_cfg_path = winner.config_path
                self._vless_index = winner.index
                self._save_last_good(winner.cfg)
                self.log.info(
                    "VLESS: подключено через %s (%.0f мс, порт %d)",
                    winner.cfg.name,
                    winner.latency,
                    winner.port,
                )
                return winner.proxy_url

            self.log.warning("VLESS: проверено %d конфигов, рабочих нет", len(order))
            return None

    async def _probe_batch(self, indices: list[int]) -> Optional[_ProbeResult]:
        ports = self._pick_ports(len(indices))
        tasks = [
            self._probe_config(index, self._vless_pool[index], port)
            for index, port in zip(indices, ports)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        successful = [item for item in results if isinstance(item, _ProbeResult)]
        if not successful:
            return None
        successful.sort(key=lambda item: item.latency)
        winner = successful[0]
        for extra in successful[1:]:
            await self._terminate_proc(extra.proc, extra.log_handle)
        return winner

    async def _probe_config(
        self, index: int, cfg: VlessConfig, port: int
    ) -> Optional[_ProbeResult]:
        data_dir = self.base_dir / "data" / "netbypass"
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self.log.error("VLESS: не удалось создать каталог %s: %s", data_dir, exc)
            return None

        config_path = data_dir / f"xray-{port}.json"
        xray_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": port,
                    "protocol": "http",
                    "settings": {"timeout": 300},
                }
            ],
            "outbounds": [cfg.outbound()],
        }
        try:
            config_path.write_text(
                json.dumps(xray_config, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            self.log.error("VLESS: не удалось записать конфиг Xray: %s", exc)
            return None

        log_path = data_dir / f"xray-{port}.log"
        try:
            log_handle = open(log_path, "ab")
        except OSError as exc:
            self.log.error("VLESS: не удалось открыть лог Xray: %s", exc)
            return None

        proc: Optional[asyncio.subprocess.Process] = None
        try:
            kwargs: dict[str, Any] = {}
            if os.name == "nt" and hasattr(subprocess, "CREATE_NO_WINDOW"):
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            assert self._xray_exe is not None
            proc = await asyncio.create_subprocess_exec(
                self._xray_exe,
                "run",
                "-c",
                str(config_path),
                stdout=log_handle,
                stderr=log_handle,
                **kwargs,
            )

            if not await self._wait_process_port(proc, port, self._startup_timeout):
                self.log.debug(
                    "VLESS: Xray не открыл порт %d (код %s), лог: %s",
                    port,
                    proc.returncode,
                    log_path,
                )
                await self._terminate_proc(proc, log_handle)
                return None

            proxy_url = f"http://127.0.0.1:{port}"
            latency = await self._test_proxy(
                proxy_url, confirm=1, timeout=self._vless_test_timeout
            )
            if latency is None:
                await self._terminate_proc(proc, log_handle)
                return None

            return _ProbeResult(
                index=index,
                cfg=cfg,
                latency=latency,
                proxy_url=proxy_url,
                port=port,
                proc=proc,
                log_handle=log_handle,
                config_path=config_path,
            )
        except Exception:
            self.log.debug("VLESS: ошибка проверки конфига %s", cfg.name, exc_info=True)
            if proc is not None:
                await self._terminate_proc(proc, log_handle)
            else:
                try:
                    log_handle.close()
                except Exception:
                    pass
            return None

    async def _stop_xray(self) -> None:
        proc = self._xray_proc
        log_handle = self._xray_log
        self._xray_proc = None
        self._xray_log = None
        self._xray_port = None
        self._xray_cfg_path = None
        await self._terminate_proc(proc, log_handle)

    async def _terminate_proc(
        self,
        proc: Optional[asyncio.subprocess.Process],
        log_handle: Optional[Any],
    ) -> None:
        if proc is not None and proc.returncode is None:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                try:
                    await proc.wait()
                except Exception:
                    pass
        if log_handle is not None:
            try:
                log_handle.close()
            except Exception:
                pass

    async def _wait_process_port(
        self, proc: asyncio.subprocess.Process, port: int, timeout: int
    ) -> bool:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            if proc.returncode is not None:
                return False
            try:
                _reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return True
            except OSError:
                await asyncio.sleep(0.25)
        return False

    def _pick_port(self) -> int:
        configured = self._local_port
        if configured:
            return configured
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def _pick_ports(self, count: int) -> list[int]:
        if self._local_port:
            # Фиксированный порт нельзя занять несколькими процессами сразу,
            # поэтому при local_port проверка всегда последовательная.
            return [self._local_port]
        ports: list[int] = []
        while len(ports) < count:
            port = self._pick_port()
            if port not in ports:
                ports.append(port)
        return ports

    async def _vless_health(self) -> None:
        if not self._proxy_url:
            return
        if (
            await self._test_proxy(
                self._proxy_url, timeout=self._vless_test_timeout
            )
            is not None
        ):
            return

        self.log.warning("VLESS: туннель перестал отвечать — ротация конфига")
        url = await self._try_vless_from(self._vless_index + 1, wrap=True)
        if url:
            self._apply(url, "rotate")
            return

        self.log.warning("VLESS: все конфиги из текущей подписки не работают, обновляю её")
        pool = await self._load_vless_configs(force_refresh=True)
        if pool:
            self._vless_pool = pool
            url = await self._try_vless_from(0, wrap=True)
            if url:
                self._apply(url, "rescan")
                return

        self.log.error("VLESS: рабочих конфигов нет — пробую резервные режимы")
        await self._fallback_from("vless")

    async def _fallback_from(self, current: str) -> None:
        """Пробует резервные режимы из network.fallback по порядку."""
        raw = self.config.get("fallback", "proxy")
        if isinstance(raw, str):
            fallbacks = [raw]
        elif isinstance(raw, (list, tuple)):
            fallbacks = [str(item) for item in raw]
        else:
            fallbacks = []

        for mode in fallbacks:
            mode = mode.strip().lower()
            if not mode or mode == current:
                continue
            self.log.warning("Сетевой обход: пробую резервный режим %s", mode)
            try:
                url = await self._start_mode(mode)
            except Exception:
                self.log.exception("Резервный режим %s не поднялся", mode)
                url = None
            if url:
                self._apply(url, "fallback")
                return

        self.log.error("Сетевой обход: ни один резервный режим не поднялся")

    async def _load_vless_configs(self, force_refresh: bool = False) -> list[VlessConfig]:
        text = await self._load_subscription_text(force_refresh=force_refresh)
        configs: list[VlessConfig] = []
        seen: set[tuple] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line.lower().startswith("vless://"):
                continue
            try:
                cfg = parse_vless(line)
            except Exception:
                self.log.debug("Не удалось разобрать VLESS-ссылку", exc_info=True)
                continue
            if cfg is None or cfg.key in seen:
                continue
            seen.add(cfg.key)
            cfg.priority = self._vless_priority.get(line, 0)
            configs.append(cfg)
        configs.sort(key=lambda item: item.score(), reverse=True)
        return configs

    def _save_last_good(self, cfg: VlessConfig) -> None:
        try:
            self._last_good_file.parent.mkdir(parents=True, exist_ok=True)
            self._last_good_file.write_text(cfg.raw, encoding="utf-8")
        except OSError:
            self.log.debug(
                "Не удалось сохранить последний рабочий VLESS-конфиг", exc_info=True
            )

    def _read_last_good(self) -> str:
        try:
            if self._last_good_file.exists():
                return self._last_good_file.read_text(
                    encoding="utf-8", errors="ignore"
                ).strip()
        except OSError:
            pass
        return ""

    async def _load_subscription_text(self, force_refresh: bool = False) -> str:
        """Собирает VLESS-конфиги из config.json.

        network.vless.subscription может быть:
          * строкой с URL подписки;
          * строкой с одной или несколькими vless:// ссылками;
          * списком строк (URL и/или vless://), что удобно для вставки.
        Старые поля subscription_file/subscription_url поддерживаются только
        для обратной совместимости.
        """
        vless_cfg = self._section("vless")
        self._vless_priority = {}
        raw_subscription = vless_cfg.get("subscription")

        subscription_items: list[str] = []
        if isinstance(raw_subscription, str):
            subscription_items = [raw_subscription]
        elif isinstance(raw_subscription, (list, tuple)):
            subscription_items = [str(item) for item in raw_subscription]

        raw_lines: list[str] = []
        subscription_urls: list[str] = []
        for item in subscription_items:
            for line in item.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("vless://"):
                    raw_lines.append(line)
                elif line.startswith(("http://", "https://")):
                    subscription_urls.append(line)

        # Старые поля читаем только если новое поле subscription не заполнено.
        if not subscription_items:
            legacy_file = str(vless_cfg.get("subscription_file") or "").strip()
            if legacy_file:
                path = Path(legacy_file)
                if not path.is_absolute():
                    path = self.base_dir / path
                try:
                    if path.exists():
                        legacy_text = path.read_text(
                            encoding="utf-8", errors="ignore"
                        )
                        for line in legacy_text.splitlines():
                            line = line.strip()
                            if line.startswith("vless://"):
                                raw_lines.append(line)
                            elif line.startswith(("http://", "https://")):
                                subscription_urls.append(line)
                except OSError as exc:
                    self.log.warning("VLESS: не удалось прочитать %s: %s", path, exc)

            legacy_url = str(vless_cfg.get("subscription_url") or "").strip()
            if legacy_url:
                subscription_urls.append(legacy_url)

        if not subscription_urls and not raw_lines:
            subscription_urls.append(DEFAULT_SUBSCRIPTION_URL)

        # Дополнительные источники ключей (BLACK/WHITE-списки для России).
        extra = vless_cfg.get("extra_sources", DEFAULT_VLESS_EXTRA_SOURCES)
        if isinstance(extra, str):
            extra_sources = [extra] if extra.strip() else []
        elif isinstance(extra, (list, tuple)):
            extra_sources = [str(item).strip() for item in extra if str(item).strip()]
        elif extra is None:
            extra_sources = list(DEFAULT_VLESS_EXTRA_SOURCES)
        else:
            extra_sources = []

        # Индекс уже проверенных ключей tiagorrg/vless-checker.
        keys_index = vless_cfg.get("keys_index", DEFAULT_VLESS_KEY_INDEX)
        if isinstance(keys_index, str):
            key_index_urls = [keys_index.strip()] if keys_index.strip() else []
        elif isinstance(keys_index, (list, tuple)):
            key_index_urls = [str(item).strip() for item in keys_index if str(item).strip()]
        elif keys_index is None:
            key_index_urls = [DEFAULT_VLESS_KEY_INDEX]
        else:
            key_index_urls = []

        fetched_parts: list[str] = []

        # 1) BLACK/WHITE-списки для РФ — самые актуальные ключи, пробуем первыми.
        for url in extra_sources:
            fetched = await self._fetch_subscription(url)
            if not fetched:
                continue
            for line in fetched.splitlines():
                line = line.strip()
                if line.startswith("vless://"):
                    self._vless_priority.setdefault(line, 3)
            fetched_parts.append(fetched)

        # 2) Индекс уже проверенных ключей tiagorrg/vless-checker.
        for url in key_index_urls:
            keys = await self._fetch_keys_index(url)
            if not keys:
                continue
            self.log.info("VLESS: индекс ключей %s — %d шт.", url, len(keys))
            for key in keys:
                self._vless_priority.setdefault(key, 2)
            fetched_parts.append("\n".join(keys))

        # 3) Основная подписка.
        for url in dict.fromkeys(subscription_urls):
            fetched = await self._fetch_subscription(url)
            if not fetched:
                continue
            for line in fetched.splitlines():
                line = line.strip()
                if line.startswith("vless://"):
                    self._vless_priority.setdefault(line, 1)
            fetched_parts.append(fetched)

        for line in raw_lines:
            self._vless_priority.setdefault(line, 1)

        text = "\n".join([*raw_lines, *fetched_parts])

        if "vless://" not in text:
            try:
                if self._cache_file.exists():
                    text = self._cache_file.read_text(
                        encoding="utf-8", errors="ignore"
                    )
                    self.log.info("VLESS: подписка недоступна, использую кэш")
            except OSError:
                pass
        else:
            try:
                self._cache_file.parent.mkdir(parents=True, exist_ok=True)
                self._cache_file.write_text(text, encoding="utf-8")
            except OSError:
                pass

        return text

    async def _fetch_keys_index(self, url: str) -> list[str]:
        """Скачивает docs/keys.json (tiagorrg/vless-checker) и вытаскивает ключи.

        Формат индекса — словарь режимов, в каждом из которых есть ``best``
        (строка) и ``top10`` (список объектов с полем ``key``). Структура может
        меняться, поэтому ключи собираются рекурсивно по всему документу.
        """
        headers = {"User-Agent": "v2rayN/6.31"}
        timeout = aiohttp.ClientTimeout(total=20)
        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        self.log.warning(
                            "VLESS: индекс ключей вернул HTTP %s", response.status
                        )
                        return []
                    data = await response.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
            self.log.warning("VLESS: не удалось скачать индекс ключей: %s", exc)
            return []

        found: list[str] = []

        def add(value: Any) -> None:
            if isinstance(value, str) and value.strip().startswith("vless://"):
                found.append(value.strip())

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "best":
                        add(value)
                    elif key in ("top10", "top5") and isinstance(value, (list, tuple)):
                        # Достаточно пары лучших ключей на режим, иначе перебор
                        # индекса занимает слишком много времени.
                        for item in value[:2]:
                            add(item.get("key") if isinstance(item, dict) else item)
                    elif isinstance(value, (dict, list, tuple)):
                        walk(value)
                    else:
                        add(value)
            elif isinstance(node, (list, tuple)):
                for item in node:
                    walk(item)

        walk(data)
        # Ограничиваем размер индекса, чтобы не перебирать сотни ключей.
        return list(dict.fromkeys(found))[:30]

    async def _fetch_subscription(self, url: str) -> str:
        headers = {"User-Agent": "v2rayN/6.31"}
        timeout = aiohttp.ClientTimeout(total=20)
        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        self.log.warning(
                            "VLESS: подписка вернула HTTP %s", response.status
                        )
                        return ""
                    text = await response.text(errors="ignore")
                    if "vless://" not in text:
                        self.log.warning("VLESS: в подписке нет vless:// ссылок")
                        return ""
                    return text
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            self.log.warning("VLESS: не удалось скачать подписку: %s", exc)
            return ""

    # -- Xray-core ----------------------------------------------------------

    def _ensure_xray(self) -> Optional[str]:
        vless_cfg = self._section("vless")

        custom = str(vless_cfg.get("core_path") or "").strip()
        if custom:
            path = Path(custom)
            if not path.is_absolute():
                path = self.base_dir / path
            if path.exists():
                return str(path)

        bin_dir = self.base_dir / "bin" / "xray"
        exe_name = "xray.exe" if os.name == "nt" else "xray"
        exe = bin_dir / exe_name
        if exe.exists():
            return str(exe)

        if not bool(vless_cfg.get("auto_download", True)):
            return None

        url = self._xray_download_url()
        if not url:
            self.log.error(
                "VLESS: нет готового архива Xray для платформы %s/%s",
                sys.platform,
                platform.machine(),
            )
            return None

        try:
            bin_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self.log.error("VLESS: не удалось создать %s: %s", bin_dir, exc)
            return None

        archive = bin_dir / "xray-download.zip"
        self.log.info("VLESS: скачиваю Xray-core (%s)", url)
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": "KrimLogs/1.0"}
            )
            with urllib.request.urlopen(request, timeout=120) as response:
                with open(archive, "wb") as handle:
                    shutil.copyfileobj(response, handle)
            with zipfile.ZipFile(archive) as zip_file:
                zip_file.extractall(bin_dir)
            archive.unlink(missing_ok=True)
        except Exception as exc:
            self.log.error("VLESS: не удалось скачать/распаковать Xray: %s", exc)
            try:
                archive.unlink(missing_ok=True)
            except OSError:
                pass
            return None

        if not exe.exists():
            for candidate in bin_dir.rglob(exe_name):
                try:
                    shutil.move(str(candidate), str(exe))
                    break
                except OSError:
                    continue

        if not exe.exists():
            self.log.error("VLESS: в архиве не найден %s", exe_name)
            return None

        if os.name != "nt":
            try:
                exe.chmod(0o755)
            except OSError:
                pass

        self.log.info("VLESS: Xray-core готов: %s", exe)
        return str(exe)

    @staticmethod
    def _xray_download_url() -> str:
        machine = platform.machine().lower()
        base = "https://github.com/XTLS/Xray-core/releases/latest/download/"
        if os.name == "nt":
            return base + "Xray-windows-64.zip"
        if sys.platform == "darwin":
            if machine in ("arm64", "aarch64"):
                return base + "Xray-macos-arm64-v8a.zip"
            return base + "Xray-macos-64.zip"
        if sys.platform.startswith("linux"):
            if machine in ("arm64", "aarch64"):
                return base + "Xray-linux-arm64-v8a.zip"
            if machine in ("armv7l", "armv7"):
                return base + "Xray-linux-arm32-v7a.zip"
            return base + "Xray-linux-64.zip"
        return ""

    # -- режим пула прокси --------------------------------------------------

    async def _start_proxy(self) -> Optional[str]:
        self._mode = "proxy"
        return await self._refresh_proxy_pool(keep_active=False)

    def _load_proxy_cache(self) -> list[str]:
        try:
            if self._proxy_cache_file.exists():
                data = json.loads(
                    self._proxy_cache_file.read_text(encoding="utf-8")
                )
                if isinstance(data, list):
                    return [
                        str(item).strip()
                        for item in data
                        if str(item).strip().startswith(("http://", "https://"))
                    ]
        except (OSError, ValueError):
            pass
        return []

    def _save_proxy_cache(self, proxies: list[str]) -> None:
        try:
            self._proxy_cache_file.parent.mkdir(parents=True, exist_ok=True)
            self._proxy_cache_file.write_text(
                json.dumps(proxies[: self._cache_limit], ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError:
            self.log.debug("Не удалось сохранить кэш прокси", exc_info=True)

    async def _refresh_proxy_pool(
        self, keep_active: bool, force_sources: bool = False
    ) -> Optional[str]:
        async with self._refresh_lock:
            proxy_cfg = self._section("proxy")
            sources = proxy_cfg.get("sources")
            if not isinstance(sources, (list, tuple)) or not sources:
                sources = DEFAULT_PROXY_SOURCES
            sources = [str(item) for item in sources if str(item).strip()]

            cached_hosts = [
                url.split("://", 1)[-1].strip("/")
                for url in self._load_proxy_cache()
            ]
            cached_hosts = [host for host in cached_hosts if host]

            headers = {"User-Agent": "Mozilla/5.0 (KrimLogs proxy scanner)"}
            timeout = aiohttp.ClientTimeout(total=25)
            connector = aiohttp.TCPConnector(
                limit=self._concurrency, force_close=True
            )
            results: list[tuple[float, str]] = []
            wanted = self._pool_size + 1

            async with aiohttp.ClientSession(
                timeout=timeout, headers=headers, connector=connector
            ) as session:
                if cached_hosts:
                    self.log.info(
                        "Прокси: проверяю кэш прошлых запусков (%d адресов)",
                        len(cached_hosts),
                    )
                    results.extend(await self._probe_all(session, cached_hosts))

                if force_sources or len(results) < wanted:
                    self.log.info(
                        "Прокси: скачиваю списки из %d источников", len(sources)
                    )
                    texts = await asyncio.gather(
                        *(self._fetch_text(session, source) for source in sources),
                        return_exceptions=True,
                    )
                    candidates: set[str] = set()
                    for text in texts:
                        if isinstance(text, str) and text:
                            candidates.update(self._parse_proxy_lines(text))

                    tested = set(cached_hosts)
                    fresh = [item for item in candidates if item not in tested]
                    random.shuffle(fresh)

                    if not fresh and not results:
                        self.log.error("Прокси: списки пусты или недоступны")
                        return None

                    batch = fresh[: self._max_candidates]
                    if batch:
                        self.log.info(
                            "Прокси: найдено %d адресов, проверяю HTTPS "
                            "(параллельно %d)",
                            len(batch),
                            self._concurrency,
                        )
                        results.extend(await self._probe_all(session, batch))

                    # Если рабочих меньше, чем «активный + запасные», добираем
                    # ещё одну порцию кандидатов из тех же списков.
                    if len(results) < wanted and len(fresh) > len(batch):
                        extra = fresh[
                            len(batch) : len(batch) + self._max_candidates
                        ]
                        if extra:
                            self.log.info(
                                "Прокси: рабочих %d, добираю ещё %d адресов",
                                len(results),
                                len(extra),
                            )
                            results.extend(await self._probe_all(session, extra))
                else:
                    self.log.info(
                        "Прокси: кэш дал %d рабочих адресов, списки не нужны",
                        len(results),
                    )

            if not results:
                self.log.error(
                    "Прокси: ни один адрес не открыл Discord по HTTPS. "
                    "Попробуйте режим vless или увеличьте max_candidates"
                )
                return None

            best: dict[str, float] = {}
            for latency, url in results:
                previous = best.get(url)
                if previous is None or latency < previous:
                    best[url] = latency
            merged = sorted(
                ((latency, url) for url, latency in best.items()),
                key=lambda item: item[0],
            )

            pool = [url for _latency, url in merged]
            if keep_active and self._proxy_url:
                active = self._proxy_url
                pool = [item for item in pool if item != active]
            else:
                active = pool.pop(0)

            self._proxy_url = active
            self._backups = pool[: self._pool_size]
            self._last_refresh = time.time()
            cache_urls = [
                active,
                *(url for _latency, url in merged if url != active),
            ]
            self._save_proxy_cache(cache_urls)

            best_latency = merged[0][0]
            self.log.info(
                "Прокси: активный %s (~%.0f мс), запасных %d",
                active,
                best_latency,
                len(self._backups),
            )
            if len(self._backups) < self._pool_size:
                self.log.warning(
                    "Прокси: найдено только %d запасных из %d — "
                    "бесплатные прокси нестабильны, при отказе будет новый поиск",
                    len(self._backups),
                    self._pool_size,
                )
            return active

    async def _fetch_text(self, session: aiohttp.ClientSession, url: str) -> str:
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=25)
            ) as response:
                if response.status != 200:
                    return ""
                return await response.text(errors="ignore")
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            self.log.debug("Источник прокси недоступен: %s", url)
            return ""

    @staticmethod
    def _parse_proxy_lines(text: str) -> set[str]:
        found: set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line[0] in "#;/":
                continue
            host = ""
            port = ""
            if "://" in line:
                try:
                    parsed = urlsplit(line)
                    host = parsed.hostname or ""
                    port = str(parsed.port or "")
                except ValueError:
                    continue
            else:
                parts = line.split(":")
                if len(parts) < 2:
                    continue
                host, port = parts[0].strip(), parts[1].strip()
            if not host or not port:
                continue
            try:
                port_number = int(port)
            except ValueError:
                continue
            if not 0 < port_number < 65536:
                continue
            try:
                address = ipaddress.ip_address(host)
                if (
                    address.is_private
                    or address.is_loopback
                    or address.is_reserved
                    or address.is_multicast
                    or address.is_unspecified
                ):
                    continue
            except ValueError:
                # доменное имя — оставляем, проверит тест
                pass
            found.add(f"{host}:{port_number}")
        return found

    async def _probe_all(
        self,
        session: aiohttp.ClientSession,
        candidates: list[str],
        confirm: Optional[int] = None,
    ) -> list[tuple[float, str]]:
        semaphore = asyncio.Semaphore(self._concurrency)
        results: list[tuple[float, str]] = []

        async def worker(host_port: str) -> None:
            async with semaphore:
                proxy_url = f"http://{host_port}"
                latency = await self._test_proxy(
                    proxy_url, session, confirm=confirm
                )
                if latency is not None:
                    results.append((latency, proxy_url))

        await asyncio.gather(*(worker(item) for item in candidates))
        results.sort(key=lambda item: item[0])
        return results

    async def _proxy_health(self) -> None:
        if not self._proxy_url:
            url = await self._refresh_proxy_pool(keep_active=False)
            if url:
                self._apply(url, "restore")
            return

        if await self._test_proxy(self._proxy_url) is not None:
            refresh_minutes = max(
                1, self._int(self._section("proxy"), "refresh_minutes", 30)
            )
            if time.time() - self._last_refresh > refresh_minutes * 60:
                await self._refresh_proxy_pool(keep_active=True, force_sources=True)
            return

        self.log.warning("Прокси: активный %s не отвечает — ротация", self._proxy_url)
        while self._backups:
            candidate = self._backups.pop(0)
            if await self._test_proxy(candidate) is not None:
                self._apply(candidate, "rotate")
                return
            self.log.warning("Прокси: запасной %s тоже не отвечает", candidate)

        self.log.warning("Прокси: запасные закончились — ищу новые")
        url = await self._refresh_proxy_pool(keep_active=False)
        if url:
            self._apply(url, "rescan")

    # -- режим Zapret (обход DPI) ------------------------------------------

    @staticmethod
    def _is_windows_admin() -> bool:
        if os.name != "nt":
            return False
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _sudo_ok(self) -> bool:
        """Проверяет, доступен ли sudo без запроса пароля (результат кэшируется)."""
        if self._sudo_checked is not None:
            return self._sudo_checked
        if os.name == "nt" or os.geteuid() == 0:
            self._sudo_checked = True
            return True
        try:
            result = subprocess.run(
                ["sudo", "-n", "true"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            self._sudo_checked = result.returncode == 0
        except Exception:
            self._sudo_checked = False
        return self._sudo_checked

    def _root_prefix(self) -> Optional[list[str]]:
        if os.name == "nt":
            return [] if self._is_windows_admin() else None
        if os.geteuid() == 0:
            return []
        return ["sudo", "-n"] if self._sudo_ok() else None

    async def _run_privileged(
        self, args: list[str], timeout: int = 20
    ) -> tuple[int, str]:
        prefix = self._root_prefix()
        if prefix is None:
            return 1, "нет прав root"
        try:
            proc = await asyncio.create_subprocess_exec(
                *prefix,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except FileNotFoundError as exc:
            return 127, str(exc)
        try:
            output, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return 124, "timeout"
        return proc.returncode or 0, (output or b"").decode("utf-8", "ignore")

    @staticmethod
    def _default_interface() -> str:
        if os.name == "nt":
            return ""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            match = re.search(r"dev\s+(\S+)", result.stdout)
            if match:
                return match.group(1)
        except Exception:
            pass
        try:
            for name in os.listdir("/sys/class/net"):
                if name != "lo":
                    return name
        except OSError:
            pass
        return ""

    @staticmethod
    def _nfqws_libs_ok() -> bool:
        if os.name == "nt" or sys.platform == "darwin":
            return True
        try:
            result = subprocess.run(
                ["ldconfig", "-p"], capture_output=True, text=True, timeout=10
            )
            return "libnetfilter_queue" in result.stdout
        except Exception:
            return True

    def _find_zapret(self) -> Optional[tuple[Path, Path]]:
        """Ищет стратегию и исполняемый файл ядра Zapret.

        Возвращает (файл стратегии .bat, путь к nfqws/winws) или None.
        """
        zapret_cfg = self._section("zapret")
        explicit_dir = str(zapret_cfg.get("base_dir") or "").strip()
        candidates: list[Path] = []
        if explicit_dir:
            path = Path(explicit_dir).expanduser()
            if not path.is_absolute():
                path = self.base_dir / path
            candidates.append(path)
        candidates.extend([self.base_dir / "zapret", self.base_dir / "bin" / "zapret"])
        for parent in (self.base_dir, self.base_dir.parent, Path.home()):
            try:
                for child in sorted(parent.glob("zapret*")):
                    if child.is_dir():
                        candidates.append(child)
            except OSError:
                pass

        exe_name = "winws.exe" if os.name == "nt" else "nfqws"
        custom_exe = str(zapret_cfg.get("core_path") or "").strip()
        if custom_exe:
            exe = Path(custom_exe).expanduser()
            if not exe.is_absolute():
                exe = self.base_dir / exe
            if exe.exists():
                strategy = self._find_strategy(exe.parent)
                if strategy:
                    return strategy, exe

        seen: set[Path] = set()
        for directory in candidates:
            try:
                directory = directory.resolve()
            except OSError:
                pass
            if directory in seen or not directory.exists():
                continue
            seen.add(directory)
            strategy = self._find_strategy(directory)
            if strategy is None:
                continue
            exe = directory / exe_name
            if not exe.exists():
                nested = list(directory.rglob(exe_name))
                if not nested:
                    continue
                exe = nested[0]
            return strategy, exe
        return None

    def _find_strategy(self, directory: Path) -> Optional[Path]:
        zapret_cfg = self._section("zapret")
        configured = str(zapret_cfg.get("strategy") or "").strip()
        if configured:
            path = Path(configured)
            if not path.is_absolute():
                for base in (directory, self.base_dir):
                    if (base / path).exists():
                        return base / path
            elif path.exists():
                return path
        for name in ("general.bat", "general_alt.bat", "discord.bat"):
            try:
                for candidate in sorted(directory.rglob(name)):
                    return candidate
            except OSError:
                pass
        return None

    @staticmethod
    def _read_bat_command(path: Path) -> str:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""
        joined: list[str] = []
        buffer = ""
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("::"):
                continue
            low = line.lower()
            if low.startswith(("@", "chcp", "call ", "set ", "cd ", "echo")):
                continue
            if line.endswith("^"):
                buffer += line[:-1] + " "
                continue
            buffer += line
            joined.append(buffer)
            buffer = ""
        if buffer:
            joined.append(buffer)
        command = " ".join(joined)
        base = str(path.parent)
        command = command.replace("%~dp0", base + os.sep)
        command = command.replace("%BIN%", base + os.sep + "bin" + os.sep)
        command = command.replace("%LISTS%", base + os.sep + "lists" + os.sep)
        command = command.replace("%GameFilterTCP%", "")
        command = command.replace("%GameFilterUDP%", "")
        command = re.sub(r'start\s+"[^"]*"\s*(/[A-Za-z]+\s+)*', "", command, flags=re.I)
        command = re.sub(r'"[^"]*winws\.exe"\s*', "", command, flags=re.I)
        # После удаления GameFilter остаются висящие запятые в списках портов.
        command = re.sub(r",{2,}", ",", command)
        command = re.sub(r",(?=\s|$)", "", command)
        return command

    def _parse_nfqws_strategy(self, path: Path) -> tuple[list[str], list[list[str]]]:
        """Превращает Windows-стратегию .bat в nft-правила и аргументы nfqws."""
        command = self._read_bat_command(path)
        parts = [part.strip() for part in re.split(r"--new\b", command) if part.strip()]
        nft_rules: list[str] = []
        params_list: list[list[str]] = []
        for part in parts:
            match = re.search(r"--filter-(tcp|udp)=([0-9,\-]+)", part)
            if not match:
                continue
            proto, ports = match.group(1), match.group(2)
            if not re.fullmatch(r"[0-9,\-]+", ports):
                continue
            tokens = [token for token in re.split(r"\s+", part) if token]
            params: list[str] = []
            skip_next = False
            for token in tokens:
                if skip_next:
                    skip_next = False
                    continue
                if token.startswith(("--filter-", "--wf-")):
                    if "=" not in token:
                        skip_next = True
                    continue
                params.append(token.replace('"', ""))
            if not params:
                continue
            queue = len(nft_rules)
            nft_rules.append(
                f"{proto} dport {{ {ports} }} counter queue num {queue} bypass"
            )
            params_list.append(params)
        return nft_rules, params_list

    def _parse_winws_args(self, path: Path) -> list[str]:
        command = self._read_bat_command(path)
        tokens = [token.replace('"', "") for token in re.split(r"\s+", command) if token]
        args: list[str] = []
        for token in tokens:
            low = token.lower()
            if not token or low == "start" or "winws.exe" in low:
                continue
            args.append(token)
        return args

    async def _nft_script(self, script: str, timeout: int = 20) -> tuple[int, str]:
        """Выполняет ``nft -f -`` через sudo -n, без запуска shell.

        Так в sudoers достаточно разрешить только /usr/sbin/nft, nfqws и pkill,
        не давая пользователю произвольный root-shell.
        """
        prefix = self._root_prefix()
        if prefix is None:
            return 1, "нет прав root"
        try:
            proc = await asyncio.create_subprocess_exec(
                *prefix,
                "nft",
                "-f",
                "-",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except FileNotFoundError as exc:
            return 127, str(exc)
        try:
            output, _ = await asyncio.wait_for(
                proc.communicate(script.encode("utf-8")), timeout=timeout
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return 124, "timeout"
        return proc.returncode or 0, (output or b"").decode("utf-8", "ignore")

    async def _zapret_cleanup_rules(self) -> None:
        if os.name == "nt":
            return
        if not (os.geteuid() == 0 or self._sudo_ok()):
            return
        await self._nft_script("delete table inet zapretunix\n", timeout=10)
        self._zapret_nft_rules = []

    def _nfqws_supported(self, exe: Path) -> set[str]:
        """Возвращает набор опций, которые понимает данный nfqws."""
        if self._nfqws_opts is not None:
            return self._nfqws_opts
        options: set[str] = set()
        try:
            result = subprocess.run(
                [str(exe), "--help"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            options = set(
                re.findall(r"--[a-z0-9][a-z0-9-]*", result.stdout + result.stderr)
            )
        except Exception:
            self.log.debug(
                "Zapret: не удалось получить список опций nfqws", exc_info=True
            )
        self._nfqws_opts = options
        return options

    def _prepare_nfqws_params(self, params: list[str], exe: Path) -> list[str]:
        """Готовит аргументы nfqws под конкретную версию ядра.

        Windows-стратегии Flowseal используют опции winws, которых нет в nfqws
        (например, --dpi-desync-fake-discord), и ссылаются на отсутствующие
        пользовательские списки. Неподдерживаемые опции отбрасываются,
        пустые user-списки создаются, остальные битые пути пропускаются.
        """
        supported = self._nfqws_supported(exe)
        file_options = {
            "--hostlist",
            "--hostlist-exclude",
            "--ipset",
            "--ipset-exclude",
        }
        result: list[str] = []
        for token in params:
            name, sep, value = token.partition("=")
            if sep and name.startswith("--"):
                if supported and name not in supported:
                    continue
                if name in file_options and value:
                    path = Path(value)
                    if not path.exists():
                        if "user" in path.name.lower():
                            try:
                                path.parent.mkdir(parents=True, exist_ok=True)
                                path.touch()
                            except OSError:
                                continue
                        else:
                            continue
            result.append(token)
        return result

    async def _apply_zapret_strategy(
        self, strategy: Path, exe: Path, interface: str
    ) -> bool:
        nft_rules, params_list = self._parse_nfqws_strategy(strategy)
        if not nft_rules:
            self.log.warning("Zapret: в стратегии %s нет правил", strategy.name)
            return False

        await self._zapret_cleanup_rules()
        script_lines = [
            "add table inet zapretunix",
            "add chain inet zapretunix output "
            "{ type filter hook output priority 0 ; }",
        ]
        for rule in nft_rules:
            script_lines.append(
                f'add rule inet zapretunix output oifname "{interface}" '
                f'{rule} comment "krim-zapret"'
            )
        code, out = await self._nft_script("\n".join(script_lines) + "\n")
        if code != 0:
            self.log.error("Zapret: nft: %s", out.strip()[:300])
            await self._zapret_cleanup_rules()
            return False
        self._zapret_nft_rules = list(nft_rules)

        for queue, params in enumerate(params_list):
            prepared = self._prepare_nfqws_params(params, exe)
            if not prepared:
                continue
            code, out = await self._run_privileged(
                [str(exe), "--daemon", f"--qnum={queue}", *prepared], timeout=20
            )
            if code != 0:
                self.log.error(
                    "Zapret: nfqws qnum=%d код %s: %s",
                    queue,
                    code,
                    out.strip()[:300],
                )
                await self._stop_zapret()
                return False

        await asyncio.sleep(1.5)
        if not await self._test_direct():
            self.log.warning(
                "Zapret: стратегия %s не открыла Discord", strategy.name
            )
            await self._stop_zapret()
            return False
        self._zapret_desc = f"Zapret ({strategy.stem}, iface {interface})"
        self.log.info("Zapret: стратегия %s работает", strategy.name)
        return True

    def _zapret_strategies(self, strategy: Path) -> list[Path]:
        configured = self._find_strategy(strategy.parent)
        result: list[Path] = []
        if configured is not None:
            result.append(configured)
        try:
            for path in sorted(strategy.parent.rglob("general*.bat")):
                if path not in result:
                    result.append(path)
        except OSError:
            pass
        limit = max(1, self._int(self._section("zapret"), "max_strategies", 4))
        return result[:limit]

    async def _start_zapret_linux(self) -> Optional[str]:
        found = self._find_zapret()
        if not found:
            self.log.error(
                "Zapret: не найден nfqws/стратегия. Укажите network.zapret.base_dir "
                "в config.json или положите папку zapret рядом с ботом."
            )
            return None
        strategy, exe = found

        if os.geteuid() != 0 and not self._sudo_ok():
            self.log.error(
                "Zapret: нужны права root. Запустите бота через sudo "
                "(sudo venv/bin/python Krim_logs.py) либо разрешите nft и nfqws "
                "без пароля в /etc/sudoers.d (см. PROXY_SETUP.md)."
            )
            return None
        if not shutil.which("nft"):
            self.log.error(
                "Zapret: не найден nft. Установите пакеты: "
                "sudo apt install nftables libnetfilter-queue1"
            )
            return None
        if not self._nfqws_libs_ok():
            self.log.error(
                "Zapret: nfqws не запускается — нет libnetfilter_queue.so. "
                "Установите: sudo apt install libnetfilter-queue1 nftables"
            )
            return None

        interface = (
            str(self._section("zapret").get("interface") or "").strip()
            or self._default_interface()
        )
        if not interface or not re.fullmatch(r"[A-Za-z0-9_.:@\-]+", interface):
            self.log.error("Zapret: не удалось определить сетевой интерфейс")
            return None
        self._zapret_interface = interface

        strategies = self._zapret_strategies(strategy)
        for index, candidate in enumerate(strategies, 1):
            self.log.info(
                "Zapret: стратегия %s (%d/%d)", candidate.name, index, len(strategies)
            )
            if await self._apply_zapret_strategy(candidate, exe, interface):
                return DIRECT_MODE
        self.log.error("Zapret: ни одна стратегия не открыла Discord")
        return None

    async def _start_zapret_windows(self) -> Optional[str]:
        if not self._is_windows_admin():
            self.log.error(
                "Zapret: нужны права администратора. Запустите бота от имени "
                "администратора."
            )
            return None
        found = self._find_zapret()
        if not found:
            self.log.error(
                "Zapret: не найден winws.exe/стратегия. Укажите network.zapret.base_dir."
            )
            return None
        strategy, exe = found
        args = self._parse_winws_args(strategy)
        if not args:
            self.log.error("Zapret: не удалось разобрать стратегию %s", strategy.name)
            return None

        kwargs: dict[str, Any] = {}
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        try:
            proc = await asyncio.create_subprocess_exec(
                str(exe),
                *args,
                cwd=str(strategy.parent),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                **kwargs,
            )
        except OSError as exc:
            self.log.error("Zapret: не удалось запустить winws: %s", exc)
            return None
        self._zapret_procs = [proc]
        await asyncio.sleep(2.0)
        if proc.returncode is not None or not await self._test_direct():
            self.log.warning("Zapret: winws не открыл Discord")
            await self._stop_zapret()
            return None
        self._zapret_desc = f"Zapret ({strategy.stem}, WinDivert)"
        self.log.info("Zapret: стратегия %s работает", strategy.name)
        return DIRECT_MODE

    async def _start_zapret(self) -> Optional[str]:
        self._mode = "zapret"
        self._zapret_active = False
        self._zapret_desc = ""
        if os.name == "nt":
            url = await self._start_zapret_windows()
        else:
            url = await self._start_zapret_linux()
        if url:
            self._zapret_active = True
        return url

    async def _stop_zapret(self) -> None:
        for proc in self._zapret_procs:
            if proc.returncode is None:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
        self._zapret_procs = []
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/IM", "winws.exe", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
            except Exception:
                pass
        elif os.geteuid() == 0 or self._sudo_ok():
            await self._run_privileged(["pkill", "-x", "nfqws"], timeout=10)
            await self._zapret_cleanup_rules()
        self._zapret_active = False

    async def _zapret_health(self) -> None:
        if await self._test_direct():
            return
        self.log.warning("Zapret: Discord снова недоступен — перезапуск обхода")
        await self._stop_zapret()
        url = await self._start_zapret()
        if url:
            self._apply(url, "restart")
            return
        await self._fallback_from("zapret")

    # -- общий watchdog и применение ---------------------------------------

    async def _watchdog(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._health_interval)
                break
            except asyncio.TimeoutError:
                pass
            try:
                if self._mode == "vless":
                    await self._vless_health()
                elif self._mode == "proxy":
                    await self._proxy_health()
                elif self._mode == "zapret":
                    await self._zapret_health()
            except asyncio.CancelledError:
                raise
            except Exception:
                self.log.exception("Ошибка проверки сетевого обхода")

    def _apply(self, url: Optional[str], reason: str) -> None:
        direct = url == DIRECT_MODE
        target = None if direct else url
        changed = target != self._proxy_url or direct != self._zapret_active
        self._proxy_url = target
        self._zapret_active = direct
        if self._client is not None:
            try:
                self._client.http.proxy = target
            except Exception:
                self.log.exception("Не удалось обновить прокси в discord.py")
            if changed:
                self._schedule_reconnect()
        if changed:
            if direct:
                self.log.info(
                    "Сетевой обход переключён (%s): %s", reason, self.describe()
                )
            else:
                self.log.info("Сетевой обход переключён (%s): %s", reason, url)

    def _schedule_reconnect(self) -> None:
        client = self._client
        if client is None:
            return
        websocket = getattr(client, "ws", None)
        if websocket is None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self._close_websocket(websocket))

    async def _close_websocket(self, websocket: Any) -> None:
        try:
            if not getattr(websocket, "closed", False):
                await websocket.close(code=4000, message=b"netbypass rotation")
                self.log.info(
                    "WebSocket закрыт, discord.py переподключится через новый прокси"
                )
        except Exception:
            self.log.debug("Не удалось закрыть WebSocket", exc_info=True)
