"""
core/event_bus.py — EventBroker Asíncrono con PriorityQueue y Wildcards
Autor: Luis Sánchez — BLACK LEVIATAN v29

Sistema de mensajería interna entre kernels y módulos.
Soporta suscripciones por wildcard (e.g. "module.*", "finding.*").
"""
from __future__ import annotations
import asyncio
import fnmatch
import logging
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional

log = logging.getLogger("bl.event_bus")


class Priority(IntEnum):
    CRITICAL = 0
    HIGH     = 1
    NORMAL   = 2
    LOW      = 3
    TELEMETRY= 4


@dataclass(order=True)
class Event:
    priority:  Priority
    topic:     str     = field(compare=False)
    data:      Any     = field(compare=False)
    timestamp: float   = field(default_factory=time.time, compare=False)
    event_id:  int     = field(default=0, compare=False)

    def matches(self, pattern: str) -> bool:
        return fnmatch.fnmatch(self.topic, pattern)


# Mapa de tópicos con prioridad predeterminada
TOPIC_PRIORITY: dict[str, Priority] = {
    "system.*":       Priority.CRITICAL,
    "circuit.*":      Priority.HIGH,
    "phase.*":        Priority.HIGH,
    "finding.*":      Priority.NORMAL,
    "module.*":       Priority.NORMAL,
    "evasion.*":      Priority.HIGH,
    "storage.*":      Priority.LOW,
    "dashboard.*":    Priority.TELEMETRY,
}


def infer_priority(topic: str) -> Priority:
    for pattern, prio in TOPIC_PRIORITY.items():
        if fnmatch.fnmatch(topic, pattern):
            return prio
    return Priority.NORMAL


# ──────────────────────────────────────────────
# Subscripción individual
# ──────────────────────────────────────────────
@dataclass
class Subscription:
    pattern:  str
    callback: Callable[[Event], Coroutine]
    once:     bool = False   # True = se auto-elimina tras primer disparo
    sub_id:   int  = 0


# ──────────────────────────────────────────────
# EventBus principal
# ──────────────────────────────────────────────
class EventBus:
    """
    Broker asíncrono central. Todos los kernels y módulos lo comparten.
    """

    def __init__(self, max_queue: int = 5000, ring_buffer: int = 500) -> None:
        self._queue: asyncio.PriorityQueue[Event] = asyncio.PriorityQueue(maxsize=max_queue)
        self._subs:  list[Subscription] = []
        self._ring:  list[Event]        = []   # últimos N eventos (ring buffer)
        self._ring_size                  = ring_buffer
        self._counter                    = 0
        self._running                    = False
        self._worker_task: Optional[asyncio.Task] = None
        self._dead_letter: list[Event]  = []   # eventos sin suscriptores

    # ── Ciclo de vida ──────────────────────────
    async def start(self) -> None:
        self._running = True
        self._worker_task = asyncio.create_task(self._dispatch_loop(), name="event_bus")
        log.info("EventBus iniciado")

    async def stop(self) -> None:
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        log.info("EventBus detenido. Dead-letter queue: %d", len(self._dead_letter))

    # ── Publicar ──────────────────────────────
    async def publish(
        self,
        topic:    str,
        data:     Any,
        priority: Optional[Priority] = None,
    ) -> None:
        self._counter += 1
        prio = priority if priority is not None else infer_priority(topic)
        event = Event(
            priority=prio,
            topic=topic,
            data=data,
            event_id=self._counter,
        )
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            log.warning("EventBus queue llena, descartando evento: %s", topic)
            self._dead_letter.append(event)

    def publish_sync(self, topic: str, data: Any, priority: Optional[Priority] = None) -> None:
        """Versión síncrona para llamar desde contextos no-async."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.call_soon_threadsafe(
                    lambda: asyncio.create_task(self.publish(topic, data, priority))
                )
        except RuntimeError:
            pass   # Sin loop disponible, se ignora silenciosamente

    # ── Suscribir ─────────────────────────────
    def subscribe(
        self,
        pattern:  str,
        callback: Callable[[Event], Coroutine],
        once:     bool = False,
    ) -> int:
        """
        Suscribe a un patrón de tópicos. Soporta wildcards:
          "module.*"       → todos los eventos de módulos
          "finding.new"    → sólo findings nuevos
          "*"              → absolutamente todo (usar con cuidado)

        Returns:
            sub_id para poder des-suscribirse después
        """
        sub_id = len(self._subs)
        self._subs.append(Subscription(
            pattern=pattern,
            callback=callback,
            once=once,
            sub_id=sub_id,
        ))
        return sub_id

    def unsubscribe(self, sub_id: int) -> None:
        self._subs = [s for s in self._subs if s.sub_id != sub_id]

    def subscribe_once(self, pattern: str, callback: Callable) -> int:
        return self.subscribe(pattern, callback, once=True)

    # ── Wait for event ─────────────────────────
    async def wait_for(self, pattern: str, timeout: float = 30.0) -> Optional[Event]:
        """Espera hasta que llegue un evento que matchee el patrón."""
        future: asyncio.Future[Event] = asyncio.get_event_loop().create_future()

        async def _resolve(event: Event):
            if not future.done():
                future.set_result(event)

        sub_id = self.subscribe_once(pattern, _resolve)
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            self.unsubscribe(sub_id)
            return None

    # ── Ring buffer (historial) ────────────────
    def get_recent(self, n: int = 50, pattern: str = "*") -> list[Event]:
        return [e for e in self._ring[-n:] if e.matches(pattern)]

    # ── Dispatch loop interno ──────────────────
    async def _dispatch_loop(self) -> None:
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=0.1)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            # Actualizar ring buffer
            self._ring.append(event)
            if len(self._ring) > self._ring_size:
                self._ring.pop(0)

            # Encontrar suscriptores que matcheen
            matched   = [s for s in self._subs if fnmatch.fnmatch(event.topic, s.pattern)]
            to_remove = []

            if not matched:
                # No enviar a DLQ eventos de telemetría o debugging
                if not event.topic.startswith(("dashboard.", "telemetry.", "debug.")):
                    self._dead_letter.append(event)
            else:
                for sub in matched:
                    try:
                        await sub.callback(event)
                    except Exception as exc:
                        log.exception("Error en callback de '%s': %s", sub.pattern, exc)
                    if sub.once:
                        to_remove.append(sub.sub_id)

            # Limpiar one-shot subscriptions
            for sid in to_remove:
                self.unsubscribe(sid)

            self._queue.task_done()

    # ── Stats ──────────────────────────────────
    @property
    def stats(self) -> dict:
        return {
            "total_published":   self._counter,
            "queue_size":        self._queue.qsize(),
            "subscriptions":     len(self._subs),
            "ring_buffer_items": len(self._ring),
            "dead_letter_count": len(self._dead_letter),
        }
