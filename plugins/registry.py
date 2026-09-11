"""plugins/registry.py — Registry centralizado de plugins descubiertos."""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from modules.base_module import BaseModule


class PluginRegistry:
    """Registry simple de módulos activos."""

    def __init__(self) -> None:
        self._registry: dict[str, type["BaseModule"]] = {}

    def register(self, name: str, cls: type["BaseModule"]) -> None:
        self._registry[name] = cls

    def get(self, name: str) -> type["BaseModule"] | None:
        return self._registry.get(name)

    def all(self) -> dict[str, type["BaseModule"]]:
        return dict(self._registry)

    def names(self) -> list[str]:
        return list(self._registry.keys())

    def unregister(self, name: str) -> None:
        self._registry.pop(name, None)

    def __len__(self) -> int:
        return len(self._registry)
