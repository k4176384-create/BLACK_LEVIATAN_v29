"""
plugins/hooks.py — Sistema de Hooks para Plugins
Autor: Luis Sánchez — BLACK LEVIATAN v29

Los hooks permiten que un plugin ejecute código en momentos específicos
del ciclo de vida del scan sin modificar el orchestrator.

TIPOS DE HOOKS:
  pre_phase       → Antes de que comience una fase
  post_phase      → Después de que termine una fase
  pre_module      → Antes de que corra un módulo específico
  post_module     → Después de que termine un módulo
  on_finding      → Cuando cualquier módulo encuentra algo
  on_error        → Cuando cualquier módulo falla
  on_complete     → Cuando el scan termina
  custom_phase    → Inyectar una fase completamente nueva al DAG
"""
from __future__ import annotations
import asyncio
import logging
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional

log = logging.getLogger("bl.hooks")


class HookType(Enum):
    PRE_PHASE    = "pre_phase"
    POST_PHASE   = "post_phase"
    PRE_MODULE   = "pre_module"
    POST_MODULE  = "post_module"
    ON_FINDING   = "on_finding"
    ON_ERROR     = "on_error"
    ON_COMPLETE  = "on_complete"
    CUSTOM_PHASE = "custom_phase"


@dataclass
class HookRegistration:
    hook_type:   HookType
    callback:    Callable[..., Coroutine]
    plugin_name: str
    phase:       Optional[int]   = None    # Para PRE/POST_PHASE: qué fase
    module_name: Optional[str]   = None    # Para PRE/POST_MODULE: qué módulo
    priority:    int             = 100     # Menor = se ejecuta antes
    hook_id:     int             = field(default=0)

    def matches_phase(self, phase_num: int) -> bool:
        return self.phase is None or self.phase == phase_num

    def matches_module(self, mod_name: str) -> bool:
        return self.module_name is None or self.module_name == mod_name


class HookRegistry:
    """
    Registro central de hooks. El Orchestrator lo consulta en cada
    punto de ciclo de vida para saber qué callbacks ejecutar.
    """

    def __init__(self) -> None:
        self._hooks:   list[HookRegistration] = []
        self._counter: int = 0

    def register(
        self,
        hook_type:   HookType,
        callback:    Callable,
        plugin_name: str,
        phase:       Optional[int]  = None,
        module_name: Optional[str]  = None,
        priority:    int            = 100,
    ) -> int:
        self._counter += 1
        reg = HookRegistration(
            hook_type=hook_type,
            callback=callback,
            plugin_name=plugin_name,
            phase=phase,
            module_name=module_name,
            priority=priority,
            hook_id=self._counter,
        )
        self._hooks.append(reg)
        self._hooks.sort(key=lambda h: h.priority)
        log.debug("Hook registrado: %s.%s (id=%d)", plugin_name, hook_type.value, self._counter)
        return self._counter

    def unregister(self, hook_id: int) -> None:
        self._hooks = [h for h in self._hooks if h.hook_id != hook_id]

    def get_hooks(
        self,
        hook_type:   HookType,
        phase:       Optional[int] = None,
        module_name: Optional[str] = None,
    ) -> list[HookRegistration]:
        return [
            h for h in self._hooks
            if h.hook_type == hook_type
            and h.matches_phase(phase or 0)
            and h.matches_module(module_name or "")
        ]

    async def fire(
        self,
        hook_type:   HookType,
        context:     dict,
        phase:       Optional[int] = None,
        module_name: Optional[str] = None,
    ) -> None:
        hooks = self.get_hooks(hook_type, phase, module_name)
        if not hooks:
            return
        for hook in hooks:
            try:
                await hook.callback(context)
            except Exception as exc:
                log.error(
                    "Error en hook %s.%s: %s",
                    hook.plugin_name, hook_type.value, exc
                )

    @property
    def total_hooks(self) -> int:
        return len(self._hooks)

    def summary(self) -> dict:
        by_type: dict[str, int] = {}
        for h in self._hooks:
            key = h.hook_type.value
            by_type[key] = by_type.get(key, 0) + 1
        return {"total": self.total_hooks, "by_type": by_type}
