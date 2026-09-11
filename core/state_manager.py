"""
core/state_manager.py — Estado Inmutable con Ring Buffer y Reductor Puro
Autor: Luis Sánchez — BLACK LEVIATAN v29

Arquitectura Redux-like: estado central inmutable, reducción pura.
El estado NUNCA se muta directamente — siempre se crea una copia nueva.
"""
from __future__ import annotations
import copy
import time
from collections import deque
from dataclasses import dataclass, field, replace
from enum import Enum, auto
from typing import Any, Optional


class ScanStatus(Enum):
    IDLE       = auto()
    STARTING   = auto()
    SCANNING   = auto()
    EVADING    = auto()
    PAUSED     = auto()
    COMPLETING = auto()
    DONE       = auto()
    ERROR      = auto()


@dataclass(frozen=True)
class PhaseStatus:
    phase_num:    int
    phase_name:   str
    status:       str    = "pending"   # pending | running | done | failed | skipped
    modules_total:int    = 0
    modules_done: int    = 0
    start_time:   Optional[float] = None
    end_time:     Optional[float] = None
    findings:     int    = 0
    errors:       int    = 0

    @property
    def progress(self) -> float:
        if self.modules_total == 0:
            return 0.0
        return self.modules_done / self.modules_total

    @property
    def elapsed(self) -> float:
        if self.start_time is None:
            return 0.0
        end = self.end_time or time.time()
        return end - self.start_time


@dataclass(frozen=True)
class ScanState:
    """
    Snapshot inmutable del estado completo del sistema.
    Para modificar: usa `StateManager.dispatch(action, payload)`.
    """
    status:          ScanStatus           = ScanStatus.IDLE
    target:          str                  = ""
    scan_id:         str                  = ""
    start_time:      Optional[float]      = None
    end_time:        Optional[float]      = None
    current_phase:   int                  = 0
    phases:          dict[int, PhaseStatus] = field(default_factory=dict)
    total_findings:  int                  = 0
    critical_count:  int                  = 0
    high_count:      int                  = 0
    modules_active:  int                  = 0
    requests_sent:   int                  = 0
    bytes_received:  int                  = 0
    proxy_rotations: int                  = 0
    circuit_breaks:  int                  = 0
    active_module:   str                  = ""
    last_event:      str                  = ""
    error_message:   str                  = ""
    plugins_loaded:  int                  = 0
    risk_score:      float                = 0.0
    metadata:        dict                 = field(default_factory=dict)

    @property
    def elapsed(self) -> float:
        if self.start_time is None:
            return 0.0
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def overall_progress(self) -> float:
        if not self.phases:
            return 0.0
        done = sum(1 for p in self.phases.values() if p.status in ("done", "skipped", "failed"))
        return done / len(self.phases)

    def to_dict(self) -> dict:
        return {
            "status":          self.status.name,
            "target":          self.target,
            "scan_id":         self.scan_id,
            "elapsed":         round(self.elapsed, 2),
            "current_phase":   self.current_phase,
            "total_findings":  self.total_findings,
            "critical_count":  self.critical_count,
            "high_count":      self.high_count,
            "risk_score":      round(self.risk_score, 2),
            "requests_sent":   self.requests_sent,
            "proxy_rotations": self.proxy_rotations,
            "circuit_breaks":  self.circuit_breaks,
            "plugins_loaded":  self.plugins_loaded,
            "progress":        round(self.overall_progress * 100, 1),
            "active_module":   self.active_module,
        }


# ──────────────────────────────────────────────
# Acciones disponibles (tipo Redux)
# ──────────────────────────────────────────────
class Action(Enum):
    INIT_SCAN           = "INIT_SCAN"
    START_SCAN          = "START_SCAN"
    START_PHASE         = "START_PHASE"
    FINISH_PHASE        = "FINISH_PHASE"
    SKIP_PHASE          = "SKIP_PHASE"
    FAIL_PHASE          = "FAIL_PHASE"
    MODULE_START        = "MODULE_START"
    MODULE_DONE         = "MODULE_DONE"
    NEW_FINDING         = "NEW_FINDING"
    REQUEST_SENT        = "REQUEST_SENT"
    BYTES_RECEIVED      = "BYTES_RECEIVED"
    CIRCUIT_BREAK       = "CIRCUIT_BREAK"
    PROXY_ROTATED       = "PROXY_ROTATED"
    ENTER_EVASION       = "ENTER_EVASION"
    EXIT_EVASION        = "EXIT_EVASION"
    PLUGINS_LOADED      = "PLUGINS_LOADED"
    UPDATE_RISK_SCORE   = "UPDATE_RISK_SCORE"
    COMPLETE_SCAN       = "COMPLETE_SCAN"
    ERROR               = "ERROR"
    PAUSE               = "PAUSE"
    RESUME              = "RESUME"


def _reduce(state: ScanState, action: Action, payload: dict) -> ScanState:
    """Reductor puro. Sin efectos secundarios. Sin mutaciones."""

    if action == Action.INIT_SCAN:
        from uuid import uuid4
        phases_init = {
            i: PhaseStatus(phase_num=i, phase_name=payload.get("phase_names", {}).get(i, f"Phase {i}"))
            for i in range(1, 11)
        }
        return replace(
            state,
            status=ScanStatus.STARTING,
            target=payload["target"],
            scan_id=str(uuid4())[:8],
            phases=phases_init,
        )

    elif action == Action.START_SCAN:
        return replace(state, status=ScanStatus.SCANNING, start_time=time.time())

    elif action == Action.START_PHASE:
        n = payload["phase"]
        old_phase = state.phases.get(n, PhaseStatus(n, f"Phase {n}"))
        new_phase = replace(old_phase,
            status="running",
            start_time=time.time(),
            modules_total=payload.get("modules_total", 0),
        )
        return replace(state,
            current_phase=n,
            phases={**state.phases, n: new_phase},
            last_event=f"Phase {n} started",
        )

    elif action == Action.FINISH_PHASE:
        n = payload["phase"]
        old_phase = state.phases.get(n, PhaseStatus(n, f"Phase {n}"))
        new_phase = replace(old_phase,
            status="done",
            end_time=time.time(),
            findings=payload.get("findings", old_phase.findings),
        )
        return replace(state, phases={**state.phases, n: new_phase})

    elif action == Action.SKIP_PHASE:
        n = payload["phase"]
        old_phase = state.phases.get(n, PhaseStatus(n, f"Phase {n}"))
        return replace(state, phases={**state.phases, n: replace(old_phase, status="skipped")})

    elif action == Action.FAIL_PHASE:
        n = payload["phase"]
        old_phase = state.phases.get(n, PhaseStatus(n, f"Phase {n}"))
        new_phase = replace(old_phase, status="failed", end_time=time.time(),
                            errors=old_phase.errors + 1)
        return replace(state, phases={**state.phases, n: new_phase})

    elif action == Action.MODULE_START:
        return replace(state, active_module=payload.get("module", ""))

    elif action == Action.MODULE_DONE:
        n = state.current_phase
        old_phase = state.phases.get(n, PhaseStatus(n, f"Phase {n}"))
        new_phase = replace(old_phase, modules_done=old_phase.modules_done + 1)
        return replace(state,
            phases={**state.phases, n: new_phase},
            modules_active=max(0, state.modules_active - 1),
        )

    elif action == Action.NEW_FINDING:
        sev = payload.get("severity", "INFO")
        return replace(state,
            total_findings=state.total_findings + 1,
            critical_count=state.critical_count + (1 if sev == "CRITICAL" else 0),
            high_count=state.high_count     + (1 if sev == "HIGH" else 0),
        )

    elif action == Action.REQUEST_SENT:
        return replace(state, requests_sent=state.requests_sent + payload.get("count", 1))

    elif action == Action.BYTES_RECEIVED:
        return replace(state, bytes_received=state.bytes_received + payload.get("bytes", 0))

    elif action == Action.CIRCUIT_BREAK:
        return replace(state,
            circuit_breaks=state.circuit_breaks + 1,
            last_event=f"Circuit break: {payload.get('module', '?')}",
        )

    elif action == Action.PROXY_ROTATED:
        return replace(state,
            proxy_rotations=state.proxy_rotations + 1,
            last_event="Proxy rotado",
        )

    elif action == Action.ENTER_EVASION:
        return replace(state, status=ScanStatus.EVADING, last_event="Modo evasión activo")

    elif action == Action.EXIT_EVASION:
        return replace(state, status=ScanStatus.SCANNING, last_event="Evasión resuelta")

    elif action == Action.PLUGINS_LOADED:
        return replace(state, plugins_loaded=payload.get("count", 0))

    elif action == Action.UPDATE_RISK_SCORE:
        return replace(state, risk_score=payload.get("score", state.risk_score))

    elif action == Action.COMPLETE_SCAN:
        return replace(state, status=ScanStatus.DONE, end_time=time.time())

    elif action == Action.ERROR:
        return replace(state,
            status=ScanStatus.ERROR,
            error_message=payload.get("message", "Error desconocido"),
        )

    elif action == Action.PAUSE:
        return replace(state, status=ScanStatus.PAUSED)

    elif action == Action.RESUME:
        return replace(state, status=ScanStatus.SCANNING)

    return state


# ──────────────────────────────────────────────
# StateManager — Wrapper sobre el reductor puro
# ──────────────────────────────────────────────
class StateManager:
    """
    Gestiona el estado global con historial de N snapshots (ring buffer).
    """

    PHASE_NAMES = {
        1:  "Recon",
        2:  "Discovery",
        3:  "Enumeration",
        4:  "Correlation",
        5:  "Breach Intel",
        6:  "Social OSINT",
        7:  "AI Future",
        8:  "Deep OSINT",
        9:  "Historical",
        10: "Cloud Infra",
    }

    def __init__(self, history_size: int = 500) -> None:
        self._state   = ScanState()
        self._history: deque[ScanState] = deque(maxlen=history_size)
        self._listeners: list[Any] = []

    @property
    def state(self) -> ScanState:
        return self._state

    def dispatch(self, action: Action, payload: dict | None = None) -> ScanState:
        payload = payload or {}
        new_state = _reduce(self._state, action, payload)
        if new_state is not self._state:
            self._history.append(self._state)
            self._state = new_state
            for listener in self._listeners:
                try:
                    listener(new_state)
                except Exception:
                    pass
        return new_state

    def subscribe(self, listener) -> None:
        self._listeners.append(listener)

    def get_history(self, n: int = 10) -> list[ScanState]:
        items = list(self._history)
        return items[-n:] if n < len(items) else items

    def snapshot(self) -> dict:
        return self._state.to_dict()
