"""
core/vigilante_v2.py — FSM + Circuit Breakers + Backpressure + WAF Evasion Triggers
Autor: Luis Sánchez — BLACK LEVIATAN v29

El Vigilante es el watchdog del sistema. Observa cada módulo/kernel y toma
decisiones de resiliencia: pausa, reintento exponencial, activar K6, etc.
"""
from __future__ import annotations
import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from core.event_bus import EventBus, Priority
from core.state_manager import StateManager, Action

log = logging.getLogger("bl.vigilante")


# ──────────────────────────────────────────────
# Estados de la FSM del Vigilante
# ──────────────────────────────────────────────
class VState(Enum):
    IDLE      = auto()
    MONITORING= auto()
    THROTTLED = auto()   # Rate limit detectado
    BLOCKED   = auto()   # WAF block (403/429 repetidos)
    EVADING   = auto()   # K6 activo resolviendo bloqueo
    RECOVERING= auto()   # Backoff antes de reintento
    SHUTDOWN  = auto()


# ──────────────────────────────────────────────
# Circuit Breaker por módulo
# ──────────────────────────────────────────────
class CBState(Enum):
    CLOSED   = "closed"    # Normal — peticiones fluyen
    OPEN     = "open"      # Cortado — peticiones rechazadas
    HALF_OPEN= "half_open" # Probando — permite una petición de prueba


@dataclass
class CircuitBreaker:
    """
    Implementación estándar del patrón Circuit Breaker.
    Un CB por módulo que hace peticiones externas.
    """
    name:             str
    failure_threshold:int   = 5      # fallos consecutivos para abrir
    success_threshold:int   = 2      # éxitos en half-open para cerrar
    timeout:          float = 60.0   # segundos antes de ir a half-open
    
    _state:           CBState  = field(default=CBState.CLOSED, init=False)
    _failures:        int      = field(default=0, init=False)
    _successes:       int      = field(default=0, init=False)
    _last_failure:    float    = field(default=0.0, init=False)
    _total_trips:     int      = field(default=0, init=False)

    @property
    def state(self) -> CBState: return self._state

    @property
    def is_open(self) -> bool:
        if self._state == CBState.OPEN:
            if time.time() - self._last_failure >= self.timeout:
                self._state = CBState.HALF_OPEN
                log.info("CB %s → HALF_OPEN (probando recuperación)", self.name)
                return False
            return True
        return False

    def record_success(self) -> None:
        if self._state == CBState.HALF_OPEN:
            self._successes += 1
            if self._successes >= self.success_threshold:
                self._state    = CBState.CLOSED
                self._failures = 0
                self._successes= 0
                log.info("CB %s → CLOSED (recuperado)", self.name)
        elif self._state == CBState.CLOSED:
            self._failures = max(0, self._failures - 1)

    def record_failure(self, reason: str = "") -> bool:
        """Returns True si el circuito acaba de abrirse."""
        self._failures   += 1
        self._last_failure = time.time()
        
        if self._state in (CBState.CLOSED, CBState.HALF_OPEN):
            if self._failures >= self.failure_threshold:
                self._state    = CBState.OPEN
                self._total_trips += 1
                log.warning("CB %s ABIERTO tras %d fallos. Razón: %s",
                            self.name, self._failures, reason)
                return True
        return False

    def to_dict(self) -> dict:
        return {
            "name":         self.name,
            "state":        self._state.value,
            "failures":     self._failures,
            "total_trips":  self._total_trips,
        }


# ──────────────────────────────────────────────
# Backpressure Manager
# ──────────────────────────────────────────────
class BackpressureManager:
    """
    Controla la velocidad de envío de requests según señales del sistema.
    Usa un algoritmo de ventana deslizante para detectar rate limits.
    """
    def __init__(self, base_delay: float = 1.0, jitter: float = 0.3) -> None:
        self._base_delay   = base_delay
        self._jitter       = jitter
        self._current_mult = 1.0
        self._window:      list[tuple[float, int]] = []   # (timestamp, status_code)
        self._window_size  = 100

    def record_response(self, status_code: int) -> None:
        self._window.append((time.time(), status_code))
        if len(self._window) > self._window_size:
            self._window.pop(0)
        self._adjust_multiplier()

    def _adjust_multiplier(self) -> None:
        if len(self._window) < 10:
            return
        recent = [s for _, s in self._window[-20:]]
        rate_limit_ratio = recent.count(429) / len(recent)
        forbidden_ratio  = recent.count(403) / len(recent)

        if rate_limit_ratio > 0.3:
            self._current_mult = min(8.0, self._current_mult * 2.0)
        elif forbidden_ratio > 0.2:
            self._current_mult = min(4.0, self._current_mult * 1.5)
        elif rate_limit_ratio < 0.05 and forbidden_ratio < 0.05:
            self._current_mult = max(1.0, self._current_mult * 0.9)

    async def wait(self) -> None:
        import random
        delay = self._base_delay * self._current_mult
        jitter = delay * self._jitter * (random.random() * 2 - 1)
        await asyncio.sleep(max(0.1, delay + jitter))

    @property
    def current_delay(self) -> float:
        return self._base_delay * self._current_mult


# ──────────────────────────────────────────────
# Vigilante v2 — FSM principal
# ──────────────────────────────────────────────
class VigilanteV2:
    """
    Watchdog del sistema. Escucha eventos del bus y toma decisiones:
    - Detecta bloques de WAF y activa K6
    - Gestiona circuit breakers por módulo
    - Controla backpressure del crawler
    - Emite alertas al dashboard
    """

    def __init__(self, bus: EventBus, state: StateManager, config) -> None:
        self._bus      = bus
        self._state    = state
        self._config   = config
        self._fsm      = VState.IDLE
        self._cbs:     dict[str, CircuitBreaker] = {}
        self._bpm      = BackpressureManager(
            base_delay=config.evasion.rate_limit_delay,
            jitter=config.evasion.jitter_factor,
        )
        self._task:    Optional[asyncio.Task] = None
        self._waf_detections: list[float] = []   # timestamps de detecciones WAF

    # ── Cycle de vida ─────────────────────────
    async def start(self) -> None:
        self._fsm = VState.MONITORING
        # Suscribirse a eventos relevantes
        self._bus.subscribe("module.*.http_response", self._on_http_response)
        self._bus.subscribe("module.*.error",         self._on_module_error)
        self._bus.subscribe("evasion.circuit_open",   self._on_circuit_open)
        self._bus.subscribe("system.shutdown",        self._on_shutdown)
        self._task = asyncio.create_task(self._monitor_loop(), name="vigilante")
        log.info("Vigilante v2 activo — FSM: MONITORING")

    async def stop(self) -> None:
        self._fsm = VState.SHUTDOWN
        if self._task:
            self._task.cancel()
            try: await self._task
            except asyncio.CancelledError: pass

    # ── API pública para módulos ───────────────
    def get_circuit_breaker(self, module_name: str) -> CircuitBreaker:
        if module_name not in self._cbs:
            self._cbs[module_name] = CircuitBreaker(
                name=module_name,
                failure_threshold=self._config.evasion.max_retries + 2,
                timeout=60.0,
            )
        return self._cbs[module_name]

    def is_allowed(self, module_name: str) -> bool:
        cb = self.get_circuit_breaker(module_name)
        return not cb.is_open

    async def gate(self, module_name: str) -> bool:
        """
        Punto de entrada para módulos antes de hacer una petición.
        Returns False si el módulo debe esperar/abortar.
        """
        cb = self.get_circuit_breaker(module_name)
        if cb.is_open:
            return False
        await self._bpm.wait()
        return True

    def record_success(self, module_name: str, status_code: int) -> None:
        cb = self.get_circuit_breaker(module_name)
        cb.record_success()
        self._bpm.record_response(status_code)

    def record_failure(self, module_name: str, status_code: int, reason: str = "") -> None:
        cb = self.get_circuit_breaker(module_name)
        opened = cb.record_failure(reason)
        self._bpm.record_response(status_code)
        if opened:
            self._state.dispatch(Action.CIRCUIT_BREAK, {"module": module_name})

    # ── Callbacks del bus ─────────────────────
    async def _on_http_response(self, event) -> None:
        data = event.data
        module = data.get("module", "unknown")
        code   = data.get("status_code", 200)

        if code in (403, 429):
            self._waf_detections.append(time.time())
            # Limpiar detecciones > 5 min
            now = time.time()
            self._waf_detections = [t for t in self._waf_detections if now - t < 300]

            # Si 5+ bloqueos en 5 minutos → activar modo evasión
            if len(self._waf_detections) >= 5 and self._fsm == VState.MONITORING:
                await self._enter_evasion_mode()

            self.record_failure(module, code, f"HTTP {code}")
        elif code < 400:
            self.record_success(module, code)

    async def _on_module_error(self, event) -> None:
        data   = event.data
        module = data.get("module", "unknown")
        self.record_failure(module, 0, data.get("error", "unknown"))

    async def _on_circuit_open(self, event) -> None:
        log.warning("Circuito abierto detectado: %s", event.data)

    async def _on_shutdown(self, event) -> None:
        await self.stop()

    # ── Evasion trigger ───────────────────────
    async def _enter_evasion_mode(self) -> None:
        if self._fsm == VState.EVADING:
            return
        self._fsm = VState.EVADING
        self._state.dispatch(Action.ENTER_EVASION, {})
        await self._bus.publish("evasion.activate", {
            "reason": "WAF detection threshold reached",
            "detections": len(self._waf_detections),
        }, priority=Priority.HIGH)
        log.warning("⚡ Modo evasión activado — %d bloqueos detectados", len(self._waf_detections))

    async def _exit_evasion_mode(self) -> None:
        self._fsm = VState.MONITORING
        self._waf_detections.clear()
        self._state.dispatch(Action.EXIT_EVASION, {})
        await self._bus.publish("evasion.deactivated", {}, priority=Priority.HIGH)
        log.info("Modo evasión desactivado — sistema normalizado")

    # ── Monitor loop ──────────────────────────
    async def _monitor_loop(self) -> None:
        while self._fsm != VState.SHUTDOWN:
            await asyncio.sleep(5.0)
            if self._fsm == VState.EVADING:
                # Checar si el sistema se ha recuperado
                recent_blocks = [t for t in self._waf_detections if time.time() - t < 60]
                if len(recent_blocks) == 0:
                    await self._exit_evasion_mode()

            # Publicar stats del vigilante
            await self._bus.publish("vigilante.heartbeat", {
                "fsm":          self._fsm.name,
                "circuits":     {n: cb.to_dict() for n, cb in self._cbs.items()},
                "backpressure": round(self._bpm.current_delay, 2),
                "waf_signals":  len(self._waf_detections),
            }, priority=Priority.TELEMETRY)

    # ── Stats ──────────────────────────────────
    @property
    def fsm_state(self) -> str: return self._fsm.name

    def get_all_circuits(self) -> list[dict]:
        return [cb.to_dict() for cb in self._cbs.values()]
