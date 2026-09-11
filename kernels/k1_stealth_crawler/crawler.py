"""
kernels/k1_stealth_crawler/crawler.py — Stealth HTTP Crawler + Playwright Fallback
Autor: Luis Sánchez — BLACK LEVIATAN v29

Estrategia dual:
  1. aiohttp (rápido, ligero) — Primera opción
  2. Playwright "undetected" — Fallback automático si aiohttp recibe 403/429
"""
from __future__ import annotations
import asyncio
import logging
import random
import re
import time
from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

if TYPE_CHECKING:
    from bl_config import BLConfig
    from core.event_bus import EventBus
    from core.vigilante_v2 import VigilanteV2

log = logging.getLogger("bl.k1")

try:
    from kernels.k1_stealth_crawler.rust_core import bl_crawler as _rust
    RUST_AVAILABLE = True
    log.info("K1 Rust core: activo")
except ImportError:
    RUST_AVAILABLE = False
    log.debug("K1 Rust core no compilado — usando Python puro")


@dataclass
class CrawlResult:
    url:          str
    status:       int
    body:         str
    headers:      dict
    latency_ms:   float
    via_playwright: bool = False
    error:        Optional[str] = None
    links:        list[str] = None

    def __post_init__(self):
        if self.links is None:
            self.links = []


class TokenBucket:
    """Rate limiter tipo token bucket. Thread-safe para asyncio."""

    def __init__(self, rate: float, capacity: float) -> None:
        self._rate      = rate
        self._capacity  = capacity
        self._tokens    = capacity
        self._last_fill = time.monotonic()
        self._lock      = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_fill
            self._tokens = min(
                self._capacity,
                self._tokens + elapsed * self._rate
            )
            self._last_fill = now
            while self._tokens < tokens:
                wait = (tokens - self._tokens) / self._rate
                await asyncio.sleep(wait)
                now = time.monotonic()
                elapsed = now - self._last_fill
                self._tokens = min(
                    self._capacity,
                    self._tokens + elapsed * self._rate,
                )
                self._last_fill = now
            self._tokens -= tokens


class UserAgentPool:
    """Pool de User-Agents realistas con perfiles de dispositivo."""

    AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    ]

    def get(self) -> str:
        return random.choice(self.AGENTS)


class StealthCrawler:
    """
    K1: Crawler sigiloso con doble motor y circuit breaker integrado.
    """

    def __init__(
        self,
        config:    "BLConfig",
        bus:       "EventBus",
        vigilante: "VigilanteV2",
    ) -> None:
        self._config    = config
        self._bus       = bus
        self._vigilante = vigilante
        self._ua_pool   = UserAgentPool()
        self._bucket    = TokenBucket(
            rate=1.0 / config.evasion.rate_limit_delay,
            capacity=5.0,
        )
        self._session:  Optional[aiohttp.ClientSession] = None
        self._playwright = None
        self._pw_browser = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = TCPConnector(
                limit=50,
                limit_per_host=5,
                ssl=False,
                enable_cleanup_closed=True,
            )
            timeout = ClientTimeout(total=30, connect=10)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
            )
        return self._session

    def _build_headers(self) -> dict:
        return {
            "User-Agent":       self._ua_pool.get(),
            "Accept":           "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language":  "en-US,en;q=0.5",
            "Accept-Encoding":  "gzip, deflate, br",
            "DNT":              "1",
            "Connection":       "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest":   "document",
            "Sec-Fetch-Mode":   "navigate",
            "Sec-Fetch-Site":   "none",
        }

    async def get(self, url: str, module_name: str = "k1") -> CrawlResult:
        """
        Petición GET con fallback automático a Playwright si aiohttp recibe 403/429.
        Incluye per-host gate + Retry-After propagation.
        """
        host = urlparse(url).hostname or ""
        # Rate limiting + circuit breaker per-host
        if not await self._vigilante.gate(module_name, host):
            return CrawlResult(url=url, status=0, body="", headers={},
                               latency_ms=0, error="Circuit breaker open")

        await self._bucket.acquire()

        proxy = self._get_proxy()

        # Intento 1: aiohttp
        result = await self._fetch_aiohttp(url, proxy)

        # Notificar al vigilante con host+headers para Retry-After
        await self._bus.publish(f"module.{module_name}.http_response", {
            "module":      module_name,
            "url":         url,
            "host":        host,
            "status_code": result.status,
            "headers":     result.headers,
        })

        if result.status in (403, 429, 503, 425) or result.error:
            log.debug("K1: aiohttp bloqueado (%d), intentando Playwright: %s", result.status, url)
            result = await self._fetch_playwright(url)

        if result.status < 400:
            self._vigilante.record_success(module_name, result.status, host)
            result.links = self._extract_links(url, result.body)
        else:
            self._vigilante.record_failure(module_name, result.status, f"HTTP {result.status}", host, result.headers)

        return result

    async def _fetch_aiohttp(self, url: str, proxy: Optional[str]) -> CrawlResult:
        t0 = time.monotonic()
        session = await self._get_session()
        try:
            async with session.get(
                url,
                headers=self._build_headers(),
                proxy=proxy,
                allow_redirects=True,
                max_redirects=5,
            ) as resp:
                body = await resp.text(errors="replace")
                return CrawlResult(
                    url=str(resp.url),
                    status=resp.status,
                    body=body,
                    headers=dict(resp.headers),
                    latency_ms=(time.monotonic() - t0) * 1000,
                )
        except aiohttp.ClientError as exc:
            return CrawlResult(
                url=url, status=0, body="", headers={},
                latency_ms=(time.monotonic() - t0) * 1000,
                error=str(exc),
            )
        except asyncio.TimeoutError:
            return CrawlResult(
                url=url, status=0, body="", headers={},
                latency_ms=(time.monotonic() - t0) * 1000,
                error="Timeout",
            )

    async def _fetch_playwright(self, url: str) -> CrawlResult:
        """Fallback con Playwright en modo stealth."""
        t0 = time.monotonic()
        try:
            from playwright.async_api import async_playwright
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-blink-features=AutomationControlled",
                        "--disable-dev-shm-usage",
                    ],
                )
                ctx = await browser.new_context(
                    user_agent=self._ua_pool.get(),
                    viewport={"width": 1920, "height": 1080},
                    java_script_enabled=True,
                    ignore_https_errors=True,
                )
                # Ocultar flags de automatización
                await ctx.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    window.chrome = {runtime: {}};
                """)
                page = await ctx.new_page()
                resp = await page.goto(url, wait_until="networkidle", timeout=30000)
                body = await page.content()
                status = resp.status if resp else 0
                headers = dict(resp.headers) if resp else {}
                await browser.close()
                return CrawlResult(
                    url=url, status=status, body=body, headers=headers,
                    latency_ms=(time.monotonic() - t0) * 1000,
                    via_playwright=True,
                )
        except Exception as exc:
            log.debug("Playwright falló para %s: %s", url, exc)
            return CrawlResult(
                url=url, status=0, body="", headers={},
                latency_ms=(time.monotonic() - t0) * 1000,
                error=f"Playwright: {exc}",
                via_playwright=True,
            )

    def _extract_links(self, base_url: str, html: str) -> list[str]:
        """Extrae y normaliza hrefs del HTML."""
        links = re.findall(r'href=["\']([^"\']+)["\']', html, re.I)
        base = urlparse(base_url)
        result = []
        for link in links:
            if link.startswith(("http://", "https://")):
                result.append(link)
            elif link.startswith("/"):
                result.append(f"{base.scheme}://{base.netloc}{link}")
            elif not link.startswith(("#", "mailto:", "javascript:", "tel:")):
                result.append(urljoin(base_url, link))
        return list(set(result))

    def _get_proxy(self) -> Optional[str]:
        pool = self._config.evasion.proxy_pool
        if not pool or not self._config.evasion.proxy_rotation:
            return None
        return random.choice(pool)

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
