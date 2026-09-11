"""
kernels/k6_evasion_mesh/evasion.py — Proxy Pool + Tor Rotation + UA Adaptive Backoff
Autor: Luis Sánchez — BLACK LEVIATAN v29

K6 se activa SÓLO cuando el Vigilante detecta bloqueo WAF.
No corre todo el tiempo — es el mecanismo de recuperación.
"""
from __future__ import annotations
import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from bl_config import BLConfig
    from core.event_bus import EventBus
    from core.state_manager import StateManager

log = logging.getLogger("bl.k6")

USER_AGENTS_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
]


@dataclass
class ProxyStats:
    url:          str
    successes:    int   = 0
    failures:     int   = 0
    last_used:    float = 0.0
    banned:       bool  = False

    @property
    def success_rate(self) -> float:
        total = self.successes + self.failures
        return self.successes / total if total > 0 else 1.0

    @property
    def score(self) -> float:
        """Puntaje para selección inteligente: más exitoso + menos usado reciente."""
        recency_penalty = max(0, time.time() - self.last_used) / 600  # 10 min
        return self.success_rate + min(recency_penalty, 0.5)


class ProxyPool:
    """
    Pool de proxies SOCKS5/HTTP con selección inteligente.
    Aprende cuáles proxies funcionan mejor por target.
    """

    def __init__(self, proxies: list[str]) -> None:
        self._pool: list[ProxyStats] = [ProxyStats(url=p) for p in proxies]
        self._idx  = 0

    def get_best(self) -> Optional[str]:
        """Selecciona el mejor proxy disponible por score."""
        available = [p for p in self._pool if not p.banned]
        if not available:
            return None
        best = max(available, key=lambda p: p.score)
        best.last_used = time.time()
        return best.url

    def get_random(self) -> Optional[str]:
        """Selección aleatoria ponderada."""
        available = [p for p in self._pool if not p.banned]
        if not available:
            return None
        weights = [max(0.1, p.success_rate) for p in available]
        chosen = random.choices(available, weights=weights, k=1)[0]
        chosen.last_used = time.time()
        return chosen.url

    def record_success(self, proxy_url: str) -> None:
        for p in self._pool:
            if p.url == proxy_url:
                p.successes += 1
                break

    def record_failure(self, proxy_url: str) -> None:
        for p in self._pool:
            if p.url == proxy_url:
                p.failures += 1
                if p.failures >= 5 and p.success_rate < 0.2:
                    p.banned = True
                    log.warning("K6: Proxy baneado por alta tasa de fallos: %s", proxy_url)
                break

    def rotate_next(self) -> Optional[str]:
        """Round-robin básico."""
        available = [p for p in self._pool if not p.banned]
        if not available:
            return None
        self._idx = (self._idx + 1) % len(available)
        proxy = available[self._idx]
        proxy.last_used = time.time()
        return proxy.url

    @property
    def stats(self) -> dict:
        return {
            "total":     len(self._pool),
            "active":    sum(1 for p in self._pool if not p.banned),
            "banned":    sum(1 for p in self._pool if p.banned),
            "avg_rate":  sum(p.success_rate for p in self._pool) / len(self._pool) if self._pool else 0,
        }


class TorCircuitManager:
    """
    Gestiona circuitos Tor vía stem library.
    Rota el circuito cada N peticiones para cambiar IP de salida.
    Solo activo si tor_enabled=True en config.
    """

    def __init__(self, control_port: int = 9051, password: str = "") -> None:
        self._port     = control_port
        self._password = password
        self._controller = None
        self._request_count = 0

    async def connect(self) -> bool:
        try:
            import stem
            from stem.control import Controller
            loop = asyncio.get_event_loop()
            self._controller = await loop.run_in_executor(
                None,
                lambda: Controller.from_port(port=self._port)
            )
            if self._password:
                self._controller.authenticate(password=self._password)
            else:
                self._controller.authenticate()
            log.info("K6: Tor controller conectado en puerto %d", self._port)
            return True
        except Exception as exc:
            log.warning("K6: Tor no disponible: %s", exc)
            return False

    async def renew_circuit(self) -> None:
        if not self._controller:
            return
        try:
            from stem import Signal
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self._controller.signal(Signal.NEWNYM)
            )
            await asyncio.sleep(2)  # Tor necesita ~2s para establecer nuevo circuito
            log.info("K6: Nuevo circuito Tor establecido")
        except Exception as exc:
            log.warning("K6: No se pudo renovar circuito: %s", exc)

    def should_renew(self, requests_since_last: int, threshold: int) -> bool:
        return requests_since_last >= threshold

    async def disconnect(self) -> None:
        if self._controller:
            try:
                self._controller.close()
            except Exception:
                pass


class AdaptiveBackoff:
    """
    Backoff exponencial con jitter aleatorio.
    Escala el delay según el nivel de bloqueo percibido.
    """

    def __init__(self, base: float = 2.0, cap: float = 60.0, jitter: float = 0.3) -> None:
        self._base   = base
        self._cap    = cap
        self._jitter = jitter
        self._level  = 0    # 0 = normal, aumenta con cada bloqueo

    def escalate(self) -> None:
        self._level = min(self._level + 1, 6)   # máximo nivel 6 → ~64s base

    def de_escalate(self) -> None:
        self._level = max(self._level - 1, 0)

    async def wait(self) -> float:
        delay = min(self._base ** self._level, self._cap)
        jitter = delay * self._jitter * (random.random() * 2 - 1)
        actual = max(0.5, delay + jitter)
        await asyncio.sleep(actual)
        return actual

    @property
    def current_delay(self) -> float:
        return min(self._base ** self._level, self._cap)


class EvasionMesh:
    """
    K6: Malla de evasión completa.
    Se activa vía evento del bus cuando Vigilante detecta bloqueo WAF.
    """

    def __init__(
        self,
        config:  "BLConfig",
        bus:     "EventBus",
        state:   "StateManager",
    ) -> None:
        self._config   = config
        self._bus      = bus
        self._state    = state
        self._active   = False

        # Componentes
        self._proxy_pool  = ProxyPool(config.evasion.proxy_pool or [])
        self._tor         = TorCircuitManager(config.evasion.tor_control_port)
        self._backoff     = AdaptiveBackoff(
            base=config.evasion.backoff_base,
            jitter=config.evasion.jitter_factor,
        )
        self._ua_idx      = 0
        self._requests_since_circuit = 0
        self._task:       Optional[asyncio.Task] = None

    async def start(self) -> None:
        if self._config.evasion.tor_enabled:
            await self._tor.connect()
        self._bus.subscribe("evasion.activate",     self._on_activate)
        self._bus.subscribe("evasion.deactivated",  self._on_deactivate)
        log.info("K6 Evasion Mesh en standby")

    async def stop(self) -> None:
        self._active = False
        await self._tor.disconnect()
        if self._task:
            self._task.cancel()

    async def activate(self) -> None:
        """Activa el modo evasión completo."""
        if self._active:
            return
        self._active = True
        self._backoff.escalate()
        log.warning("K6: Evasión activa — escalando contramedidas")

        # Rotar UA inmediatamente
        if self._config.evasion.rotate_user_agents:
            new_ua = self._next_ua()
            log.info("K6: UA rotado → %s...", new_ua[:40])

        # Rotar proxy
        if self._proxy_pool.stats["active"] > 0:
            proxy = self._proxy_pool.get_best()
            await self._bus.publish("evasion.proxy_selected", {"proxy": proxy})
            from core.state_manager import Action
            self._state.dispatch(Action.PROXY_ROTATED, {})

        # Renovar circuito Tor si está activo
        if self._config.evasion.tor_enabled:
            await self._tor.renew_circuit()

        # Esperar backoff
        wait = await self._backoff.wait()
        log.info("K6: Backoff aplicado: %.1fs", wait)

        await self._bus.publish("evasion.ready", {
            "ua_rotated":    self._config.evasion.rotate_user_agents,
            "proxy_active":  self._proxy_pool.stats["active"] > 0,
            "tor_renewed":   self._config.evasion.tor_enabled,
            "backoff_s":     wait,
        })

    async def _on_activate(self, event) -> None:
        await self.activate()

    async def _on_deactivate(self, event) -> None:
        self._active = False
        self._backoff.de_escalate()

    def get_current_ua(self) -> str:
        return USER_AGENTS_POOL[self._ua_idx % len(USER_AGENTS_POOL)]

    def _next_ua(self) -> str:
        self._ua_idx = (self._ua_idx + 1) % len(USER_AGENTS_POOL)
        return USER_AGENTS_POOL[self._ua_idx]

    def get_proxy(self) -> Optional[str]:
        if not self._config.evasion.proxy_rotation:
            return None
        return self._proxy_pool.get_best()

    def record_request_result(self, proxy: Optional[str], success: bool, status: int) -> None:
        if proxy:
            if success:
                self._proxy_pool.record_success(proxy)
                self._backoff.de_escalate()
            else:
                self._proxy_pool.record_failure(proxy)
                if status in (403, 429):
                    self._backoff.escalate()

        self._requests_since_circuit += 1
        if self._tor.should_renew(
            self._requests_since_circuit,
            self._config.evasion.tor_renew_every
        ):
            asyncio.create_task(self._tor.renew_circuit())
            self._requests_since_circuit = 0

    @property
    def is_active(self) -> bool:
        return self._active

    def status(self) -> dict:
        return {
            "active":          self._active,
            "proxy_pool":      self._proxy_pool.stats,
            "tor_enabled":     self._config.evasion.tor_enabled,
            "current_backoff": self._backoff.current_delay,
            "current_ua":      self.get_current_ua()[:40],
        }
