"""
netbypass.py — обход блокировок Discord для Krim Logs.

Поддерживаются два независимых режима, переключаемых в config.json:

  network.mode = "vless"
      Берёт VLESS-подписку (файл рядом с ботом или URL), при необходимости
      скачивает Xray-core, поднимает локальный HTTP-прокси 127.0.0.1:<port>
      и гоняет весь трафик discord.py через него. Конфиги из подписки
      перебираются до первого рабочего; при падении туннеля происходит
      ротация на следующий конфиг.

  network.mode = "proxy"
      На старте скачивает публичные списки прокси, проверяет их строго по
      HTTPS (CONNECT + валидный TLS до discord.com), сортирует по скорости и
      держит активный сервер + N запасных (по умолчанию 4). При отказе
      активного прокси бот переключается на запасной, а пул пополняется.

Наружу отдаётся один HTTP-прокси URL. discord.py 2.x передаёт его и в REST
(`HTTPClient.request`), и в WebSocket (`HTTPClient.ws_connect`), поэтому
менеджер просто выставляет `client.http.proxy`.

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
        score = 0
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
        }

    def attach_client(self, client: Any) -> None:
        """Привязывает discord.py-клиент, чтобы менеджер мог менять прокси."""
        self._client = client
        try:
            client.http.proxy = self._proxy_url
        except Exception:
            self.log.debug("Не удалось сразу выставить прокси в клиенте", exc_info=True)

    async def start(self) -> Optional[str]:
        """Поднимает выбранный режим. Возвращает URL HTTP-прокси или None."""
        if not self.enabled:
            self.log.info("Сетевой обход отключён (network.enabled=false)")
            return None

        self._stop.clear()
        mode = str(self.config.get("mode", "vless")).strip().lower()
        self.log.info("Сетевой обход включён, режим: %s", mode)

        url: Optional[str] = None
        try:
            if mode == "vless":
                url = await self._start_vless()
            elif mode == "proxy":
                url = await self._start_proxy()
            else:
                self.log.error(
                    "Неизвестный network.mode=%r (ожидается 'vless' или 'proxy')", mode
                )
        except Exception:
            self.log.exception("Ошибка запуска режима %s", mode)

        fallback = str(self.config.get("fallback", "proxy")).strip().lower()
        if not url and fallback in ("proxy", "vless") and fallback != mode:
            self.log.warning(
                "Режим %s не поднялся — пробую резервный режим %s", mode, fallback
            )
            try:
                url = (
                    await self._start_proxy()
                    if fallback == "proxy"
                    else await self._start_vless()
                )
            except Exception:
                self.log.exception("Резервный режим %s не поднялся", fallback)

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
    ) -> Optional[float]:
        """Проверяет прокси запросом к Discord по HTTPS. Возвращает мс или None.

        confirm — сколько последовательных запросов должен выдержать прокси.
        Для пула бесплатных прокси двух проверок достаточно, чтобы отсеять
        сервера, которые отдают ровно один ответ и сразу умирают.
        """
        attempts = self._verify_attempts if confirm is None else max(1, confirm)
        own_session = session is None
        if own_session:
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self._test_timeout),
                connector=aiohttp.TCPConnector(force_close=True),
            )
        try:
            latency: Optional[float] = None
            for _ in range(attempts):
                current = await self._single_proxy_request(proxy_url, session)
                if current is None:
                    return None
                if latency is None:
                    latency = current
            return latency
        finally:
            if own_session:
                await session.close()

    async def _single_proxy_request(
        self, proxy_url: str, session: aiohttp.ClientSession
    ) -> Optional[float]:
        try:
            started = time.perf_counter()
            timeout = aiohttp.ClientTimeout(total=self._test_timeout)
            async with session.get(
                self._test_url,
                proxy=proxy_url,
                timeout=timeout,
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
            latency = await self._test_proxy(proxy_url, confirm=1)
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
        if await self._test_proxy(self._proxy_url) is not None:
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

        self.log.error("VLESS: рабочих конфигов нет — перехожу на пул HTTPS-прокси")
        self._mode = "proxy"
        new_url = await self._refresh_proxy_pool(keep_active=False)
        if new_url:
            self._apply(new_url, "fallback")

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

        fetched_parts: list[str] = []
        for url in dict.fromkeys(subscription_urls):
            fetched = await self._fetch_subscription(url)
            if not fetched:
                continue
            fetched_parts.append(fetched)
            try:
                self._cache_file.parent.mkdir(parents=True, exist_ok=True)
                self._cache_file.write_text(fetched, encoding="utf-8")
            except OSError:
                pass

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

        return text

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
            except asyncio.CancelledError:
                raise
            except Exception:
                self.log.exception("Ошибка проверки сетевого обхода")

    def _apply(self, url: Optional[str], reason: str) -> None:
        changed = url != self._proxy_url
        self._proxy_url = url
        if self._client is not None:
            try:
                self._client.http.proxy = url
            except Exception:
                self.log.exception("Не удалось обновить прокси в discord.py")
            if changed:
                self._schedule_reconnect()
        if changed:
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
