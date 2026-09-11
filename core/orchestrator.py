"""
core/orchestrator.py — Ejecutor del DAG de 10 Fases con Plugin Hooks
Autor: Luis Sánchez — BLACK LEVIATAN v29

Gestiona el ciclo de vida completo del scan:
  1. Inicializa los 6 kernels
  2. Carga módulos y plugins
  3. Ejecuta el DAG fase por fase (con dependencias)
  4. Dispara hooks en cada punto del ciclo de vida
  5. Coordina la exportación al terminar
"""
from __future__ import annotations
import asyncio
import logging
import time
from typing import Optional, TYPE_CHECKING

from core.event_bus import EventBus, Priority
from core.state_manager import StateManager, Action
from core.vigilante_v2 import VigilanteV2
from plugins.hooks import HookRegistry, HookType
from modules.base_module import ModuleResult, Phase

if TYPE_CHECKING:
    from bl_config import BLConfig
    from plugins.loader import PluginLoader
    from kernels.k3_immortal_storage.storage import ImmortalStorage
    from kernels.k4_phantom_dashboard.tui import PhantomDashboard
    from kernels.k5_autonomous_intel.intel import AutonomousIntel
    from kernels.k6_evasion_mesh.evasion import EvasionMesh
    from kernels.k1_stealth_crawler.crawler import StealthCrawler
    from kernels.k2_deep_correlator.correlator import DeepCorrelator

log = logging.getLogger("bl.orchestrator")

# Dependencias del DAG: fase → lista de fases que deben terminar antes
DAG_DEPS: dict[int, list[int]] = {
    1:  [],
    2:  [1],
    3:  [1, 2],
    4:  [1, 2, 3],
    5:  [3],
    6:  [1, 2],
    7:  [4, 5],
    8:  [4, 6],
    9:  [1, 2],
    10: [1, 2, 3],
}

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


class Orchestrator:
    """
    Cerebro del sistema. Ejecuta el DAG respetando dependencias,
    coordina todos los kernels y plugins.
    """

    def __init__(
        self,
        config:    "BLConfig",
        bus:       EventBus,
        state:     StateManager,
        vigilante: VigilanteV2,
        hooks:     HookRegistry,
    ) -> None:
        self._config    = config
        self._bus       = bus
        self._state     = state
        self._vigilante = vigilante
        self._hooks     = hooks

        # Kernels (se asignan en setup)
        self.storage:   Optional["ImmortalStorage"]   = None
        self.dashboard: Optional["PhantomDashboard"]  = None
        self.intel:     Optional["AutonomousIntel"]   = None
        self.evasion:   Optional["EvasionMesh"]       = None
        self.crawler:   Optional["StealthCrawler"]    = None
        self.correlator:Optional["DeepCorrelator"]    = None
        self.loader:    Optional["PluginLoader"]      = None

        self._phase_done:  set[int] = set()
        self._phase_lock:  asyncio.Lock = asyncio.Lock()
        self._results:     dict[str, ModuleResult] = {}
        self._context:     dict = {}    # Contexto compartido entre módulos
        self._running:     bool = False

    # ── Setup de kernels ──────────────────────
    async def setup_kernels(self) -> None:
        log.info("Iniciando kernels...")

        from kernels.k3_immortal_storage.storage import ImmortalStorage
        self.storage = ImmortalStorage(self._config)
        await self.storage.init()

        from kernels.k1_stealth_crawler.crawler import StealthCrawler
        self.crawler = StealthCrawler(self._config, self._bus, self._vigilante)

        from kernels.k2_deep_correlator.correlator import DeepCorrelator
        self.correlator = DeepCorrelator(self._config, self._bus)

        from kernels.k6_evasion_mesh.evasion import EvasionMesh
        self.evasion = EvasionMesh(self._config, self._bus, self._state)
        await self.evasion.start()

        from kernels.k5_autonomous_intel.intel import AutonomousIntel
        self.intel = AutonomousIntel(self._config, self._bus)
        await self.intel.setup()

        from kernels.k4_phantom_dashboard.tui import PhantomDashboard
        self.dashboard = PhantomDashboard(
            self._config, self._bus, self._state, self._vigilante
        )

        log.info("✓ 6 Kernels inicializados")

    # ── Setup de plugins ──────────────────────
    async def setup_plugins(self) -> None:
        from plugins.loader import PluginLoader
        from pathlib import Path

        self.loader = PluginLoader(
            plugin_dirs  = [Path(d) for d in self._config.plugins.plugin_dirs],
            module_dirs  = [Path("modules")],
            config       = self._config,
            bus          = self._bus,
            storage      = self.storage,
            strict_mode  = self._config.plugins.strict_mode,
        )
        count = self.loader.discover()
        self.loader.instantiate_all()
        self._state.dispatch(Action.PLUGINS_LOADED, {"count": count})
        log.info("✓ %d módulos/plugins cargados", count)

        # Suscribir evasion al bus
        self._bus.subscribe("evasion.activate", self._on_evasion_trigger)

    # ── Scan principal ────────────────────────
    async def run_scan(self, target: str) -> dict:
        self._running = True
        self._state.dispatch(Action.INIT_SCAN, {
            "target":      target,
            "phase_names": PHASE_NAMES,
        })
        self._state.dispatch(Action.START_SCAN, {})

        # Iniciar dashboard
        if self.dashboard:
            await self.dashboard.start()

        await self._bus.publish("system.scan_start", {"target": target}, Priority.CRITICAL)

        enabled_phases = self._config.dag.enabled_phases

        try:
            # Ejecutar fases según el DAG
            pending = set(enabled_phases)
            while pending and self._running:
                runnable = [
                    p for p in pending
                    if all(dep in self._phase_done or dep not in enabled_phases
                           for dep in DAG_DEPS.get(p, []))
                ]
                if not runnable:
                    await asyncio.sleep(0.5)
                    continue

                # Ejecutar fases runnable en paralelo (si sus deps están listas)
                tasks = [asyncio.create_task(self._run_phase(p)) for p in runnable]
                await asyncio.gather(*tasks, return_exceptions=True)
                for p in runnable:
                    pending.discard(p)

            # Hook de completado
            await self._hooks.fire(HookType.ON_COMPLETE, {"context": self._context})

            # Intel final
            final_score = await self.intel.compute_final_score(self._results)
            self._state.dispatch(Action.UPDATE_RISK_SCORE, {"score": final_score})

            # Exportar
            await self._export_results(target)

        except asyncio.CancelledError:
            log.warning("Scan cancelado")
        except Exception as exc:
            log.exception("Error crítico en orchestrator: %s", exc)
            self._state.dispatch(Action.ERROR, {"message": str(exc)})
        finally:
            self._state.dispatch(Action.COMPLETE_SCAN, {})
            if self.dashboard:
                await self.dashboard.stop()
            await self._bus.publish("system.scan_done", {}, Priority.CRITICAL)

        return self._context

    async def _run_phase(self, phase_num: int) -> None:
        modules = self.loader.get_for_phase(phase_num) if self.loader else []
        phase_name = PHASE_NAMES.get(phase_num, f"Phase {phase_num}")

        self._state.dispatch(Action.START_PHASE, {
            "phase":         phase_num,
            "modules_total": len(modules),
        })

        # Hook pre-fase
        await self._hooks.fire(HookType.PRE_PHASE, {
            "phase": phase_num, "modules": [m.NAME for m in modules]
        }, phase=phase_num)

        await self._bus.publish(f"phase.{phase_num}.start", {
            "phase":   phase_num,
            "name":    phase_name,
            "modules": len(modules),
        })

        phase_findings = 0
        phase_errors   = 0

        if not modules:
            log.debug("Fase %d '%s': sin módulos activos, saltando", phase_num, phase_name)
            self._state.dispatch(Action.SKIP_PHASE, {"phase": phase_num})
            async with self._phase_lock:
                self._phase_done.add(phase_num)
            return

        # Ejecutar módulos en paralelo con semáforo
        sem = asyncio.Semaphore(self._config.dag.parallel_workers)

        async def run_one(module) -> Optional[ModuleResult]:
            async with sem:
                # Check circuit breaker
                if not self._vigilante.is_allowed(module.NAME):
                    log.warning("CB abierto para %s, saltando", module.NAME)
                    return None

                # Hook pre-módulo
                await self._hooks.fire(HookType.PRE_MODULE, {
                    "module": module.NAME, "phase": phase_num,
                }, module_name=module.NAME)

                self._state.dispatch(Action.MODULE_START, {"module": module.NAME})
                await module.setup()

                t0 = time.time()
                try:
                    result = await asyncio.wait_for(
                        module.run(self._config.target, self._context),
                        timeout=self._config.dag.module_timeout,
                    )
                except asyncio.TimeoutError:
                    result = module.skip(self._config.target, "Timeout")
                    result.add_error(f"Timeout tras {self._config.dag.module_timeout}s")
                except Exception as exc:
                    result = module.make_result(self._config.target)
                    result.add_error(str(exc))
                    await self._hooks.fire(HookType.ON_ERROR, {
                        "module": module.NAME, "error": str(exc)
                    })
                    log.error("Error en módulo %s: %s", module.NAME, exc)

                result.execution_time = time.time() - t0

                # Guardar resultado
                self._results[module.NAME] = result
                await self.storage.save_module_result(result)

                # Emitir findings al bus
                for finding in result.findings:
                    await self._bus.publish("finding.new", finding.to_dict())
                    self._state.dispatch(Action.NEW_FINDING, {"severity": finding.severity.label})

                # Hook post-módulo
                await self._hooks.fire(HookType.POST_MODULE, {
                    "module": module.NAME,
                    "result": result.to_dict(),
                }, module_name=module.NAME)

                self._state.dispatch(Action.MODULE_DONE, {"module": module.NAME})
                await module.teardown()
                return result

        tasks = [run_one(m) for m in modules]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, ModuleResult):
                phase_findings += len(r.findings)
                phase_errors   += len(r.errors)

        # Hook post-fase
        await self._hooks.fire(HookType.POST_PHASE, {
            "phase":    phase_num,
            "findings": phase_findings,
        }, phase=phase_num)

        self._state.dispatch(Action.FINISH_PHASE, {
            "phase":    phase_num,
            "findings": phase_findings,
        })

        await self._bus.publish(f"phase.{phase_num}.done", {
            "phase":    phase_num,
            "findings": phase_findings,
            "errors":   phase_errors,
        })

        async with self._phase_lock:
            self._phase_done.add(phase_num)
        log.info("Fase %d '%s' completada: %d findings", phase_num, phase_name, phase_findings)

    # ── Exportación ───────────────────────────
    async def _export_results(self, target: str) -> None:
        from export import get_exporter
        all_results = [r.to_dict() for r in self._results.values()]
        scan_meta = self._state.snapshot()

        for fmt in self._config.export.formats:
            try:
                exporter = get_exporter(fmt)
                await exporter.export(
                    results=all_results,
                    metadata=scan_meta,
                    target=target,
                    output_dir=self._config.export.output_dir,
                )
                log.info("✓ Exportado: %s", fmt)
            except Exception as exc:
                log.error("Error exportando %s: %s", fmt, exc)

    # ── Evasion trigger ───────────────────────
    async def _on_evasion_trigger(self, event) -> None:
        if self.evasion:
            await self.evasion.activate()

    def stop(self) -> None:
        self._running = False
