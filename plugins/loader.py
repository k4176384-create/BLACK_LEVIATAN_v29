"""
plugins/loader.py — Cargador Automático de Plugins y Módulos
Autor: Luis Sánchez — BLACK LEVIATAN v29

Sistema de auto-descubrimiento que escanea los directorios configurados,
importa dinámicamente las clases que heredan de BaseModule,
y las registra en el PluginRegistry central.

PARA CREAR UN PLUGIN:
  1. Crea una carpeta en plugins/ con el nombre de tu plugin
  2. Dentro, crea un manifest.yaml y un archivo .py con tu clase
  3. Tu clase debe heredar de BaseModule (ver modules/base_module.py)
  4. Reinicia o llama a `loader.discover()` — se carga automáticamente

Ver PLUGIN_GUIDE.md para guía completa con ejemplos.
"""
from __future__ import annotations
import importlib.util
import inspect
import logging
import sys
from pathlib import Path
from typing import Optional, TYPE_CHECKING

import yaml

from modules.base_module import BaseModule

if TYPE_CHECKING:
    from bl_config import BLConfig
    from core.event_bus import EventBus
    from kernels.k3_immortal_storage.storage import ImmortalStorage

log = logging.getLogger("bl.plugin_loader")


class PluginLoadError(Exception):
    """Se lanza cuando un plugin no puede cargarse y strict_mode=True."""


class PluginManifest:
    """Metadatos leídos del manifest.yaml de un plugin."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: dict = {}
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                self._data = yaml.safe_load(f) or {}

    @property
    def name(self)        -> str:       return self._data.get("name", "unnamed")
    @property
    def version(self)     -> str:       return self._data.get("version", "1.0.0")
    @property
    def author(self)      -> str:       return self._data.get("author", "unknown")
    @property
    def description(self) -> str:       return self._data.get("description", "")
    @property
    def enabled(self)     -> bool:      return self._data.get("enabled", True)
    @property
    def entry_point(self) -> Optional[str]: return self._data.get("entry_point")
    @property
    def hooks(self)       -> list[dict]:return self._data.get("hooks", [])
    @property
    def tags(self)        -> list[str]: return self._data.get("tags", [])


class PluginLoader:
    """
    Escanea directorios, importa clases BaseModule y las registra.
    Soporta hot-reload parcial para agregar plugins sin reiniciar.
    """

    def __init__(
        self,
        plugin_dirs:  list[Path],
        module_dirs:  list[Path],
        config:       "BLConfig",
        bus:          "EventBus",
        storage:      "ImmortalStorage",
        strict_mode:  bool = False,
    ) -> None:
        self._plugin_dirs  = plugin_dirs
        self._module_dirs  = module_dirs
        self._config       = config
        self._bus          = bus
        self._storage      = storage
        self._strict       = strict_mode
        self._registry:    dict[str, type[BaseModule]]  = {}
        self._manifests:   dict[str, PluginManifest]    = {}
        self._errors:      dict[str, str]               = {}
        self._instances:   dict[str, BaseModule]        = {}

    # ── Descubrimiento ─────────────────────────
    def discover(self) -> int:
        """
        Escanea todos los directorios y registra módulos/plugins.
        Returns: número de módulos cargados exitosamente.
        """
        count_before = len(self._registry)

        # Cargar módulos del core (modules/)
        for mod_dir in self._module_dirs:
            self._scan_dir(mod_dir, is_plugin=False)

        # Cargar plugins (plugins/)
        for plugin_dir in self._plugin_dirs:
            self._scan_dir(plugin_dir, is_plugin=True)

        loaded = len(self._registry) - count_before
        log.info(
            "Plugin discovery: %d nuevos módulos cargados | Total: %d | Errores: %d",
            loaded, len(self._registry), len(self._errors)
        )
        return loaded

    def _scan_dir(self, base: Path, is_plugin: bool) -> None:
        if not base.exists():
            log.debug("Directorio no encontrado: %s", base)
            return

        # Para módulos del core: buscar en subdirectorios (f01_recon/, etc.)
        # Para plugins: buscar tanto en subdirectorios como en el raíz
        search_paths = list(base.rglob("*.py")) if is_plugin else list(base.rglob("*.py"))

        for py_file in search_paths:
            # Ignorar __init__.py, base_module.py y archivos privados
            if py_file.name.startswith("_") or py_file.name == "base_module.py":
                continue
            if "rust_core" in str(py_file):
                continue

            # Buscar manifest.yaml en el mismo directorio
            manifest_path = py_file.parent / "manifest.yaml"
            manifest = PluginManifest(manifest_path)

            if not manifest.enabled:
                log.debug("Plugin deshabilitado por manifest: %s", py_file.name)
                continue

            self._load_file(py_file, manifest)

    def _load_file(self, path: Path, manifest: PluginManifest) -> None:
        """Importa un archivo .py y registra las clases BaseModule que encuentre."""
        module_name = f"_bl_dyn_{path.stem}_{abs(hash(str(path)))}"

        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                return

            mod = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = mod
            spec.loader.exec_module(mod)

            found = 0
            for attr_name in dir(mod):
                obj = getattr(mod, attr_name)
                if (
                    inspect.isclass(obj)
                    and issubclass(obj, BaseModule)
                    and obj is not BaseModule
                    and obj.NAME != "unnamed"
                ):
                    self._register(obj, manifest)
                    found += 1

            if found == 0:
                log.debug("Sin clases BaseModule en: %s", path.name)

        except Exception as exc:
            err_msg = f"{path}: {exc}"
            self._errors[str(path)] = err_msg
            if self._strict:
                raise PluginLoadError(err_msg) from exc
            else:
                log.warning("Error al cargar plugin %s: %s", path.name, exc)

    def _register(self, cls: type[BaseModule], manifest: PluginManifest) -> None:
        name = cls.NAME
        if name in self._registry:
            log.debug("Módulo '%s' ya registrado, ignorando duplicado", name)
            return
        self._registry[name] = cls
        self._manifests[name] = manifest
        log.debug("✓ Registrado: %s (phase=%s)", name, cls.PHASE.name)

    # ── Instanciación ─────────────────────────
    def instantiate_all(self) -> dict[str, BaseModule]:
        """Crea instancias de todos los módulos registrados."""
        for name, cls in self._registry.items():
            if name not in self._instances:
                try:
                    self._instances[name] = cls(
                        config=self._config,
                        bus=self._bus,
                        storage=self._storage,
                    )
                except Exception as exc:
                    log.error("No se pudo instanciar %s: %s", name, exc)
        return dict(self._instances)

    def get_instance(self, name: str) -> Optional[BaseModule]:
        return self._instances.get(name)

    def get_for_phase(self, phase_num: int) -> list[BaseModule]:
        """Devuelve todas las instancias activas para una fase dada."""
        from modules.base_module import Phase
        target_phase = Phase(phase_num)
        return [
            inst for inst in self._instances.values()
            if inst.PHASE == target_phase and inst.is_enabled
        ]

    # ── Reload caliente ───────────────────────
    def reload_plugin(self, plugin_name: str) -> bool:
        """
        Re-carga un plugin específico sin reiniciar el sistema.
        Útil durante desarrollo para iterar rápido.
        """
        if plugin_name not in self._registry:
            return False
        cls = self._registry.pop(plugin_name, None)
        self._instances.pop(plugin_name, None)
        if cls:
            source_file = inspect.getfile(cls)
            manifest_path = Path(source_file).parent / "manifest.yaml"
            self._load_file(Path(source_file), PluginManifest(manifest_path))
            return plugin_name in self._registry
        return False

    # ── Stats ──────────────────────────────────
    @property
    def registered_names(self) -> list[str]:
        return sorted(self._registry.keys())

    @property
    def total_loaded(self) -> int:
        return len(self._registry)

    @property
    def load_errors(self) -> dict[str, str]:
        return dict(self._errors)

    def summary(self) -> dict:
        from modules.base_module import Phase
        by_phase: dict[int, list[str]] = {}
        for name, cls in self._registry.items():
            p = int(cls.PHASE)
            by_phase.setdefault(p, []).append(name)
        return {
            "total":    self.total_loaded,
            "errors":   len(self._errors),
            "by_phase": by_phase,
        }
