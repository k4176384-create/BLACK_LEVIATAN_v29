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

        # Bus y vigilante primero (observabilidad)
        await self._bus.start()
        await self._vigilante.start()

        from kernels.k3_immortal_storage.storage import ImmortalStorage
        self.storage = ImmortalStorage(self._config)
        await self.storage.init()

        from kernels.k1_stealth_crawler.crawler import StealthCrawler
        self.crawler = StealthCrawler(self._config, self._bus, self._vigilante)

        from kernels.k2_deep_correlator.correlator import DeepCorrelator
        self.correlator = DeepCorrelator(self._config, self._bus)
        # Suscribir correlator a findings para auto-grafo
        self._bus.subscribe("finding.new", self._on_finding_for_correlator)

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

        # Checkpoint
        from core.checkpoint import CheckpointManager
        self._checkpoint = CheckpointManager()
        # Queue system
        from core.queue import RetryQueue, PersistentDLQ
        self._retry_queue = RetryQueue()
        self._dlq = PersistentDLQ()

        log.info("✓ 6 Kernels inicializados (bus+vigilante activos)")

    async def _on_finding_for_correlator(self, event) -> None:
        try:
            data = event.data
            # data may be finding dict or wrapped
            f = data.get("finding") if isinstance(data, dict) and "finding" in data else data
            if not isinstance(f, dict): return
            v = f.get("value",""); t = f.get("type","")
            if t.startswith("dns_") or t=="subdomain_ct" or t=="subdomain_brute":
                self.correlator.graph.add_entity(v, "subdomain" if "." in v else "domain")
            elif t=="open_port":
                ip = f.get("metadata",{}).get("ip") or v.split(":")[0]
                if ip: self.correlator.graph.add_entity(ip, "ip")
            elif t=="email_exposed":
                self.correlator.graph.add_entity(v, "email")
        except Exception:
            pass

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
        from core.target import classify_target, sanitize_for_modules, phases_for_target
        tinfo = classify_target(target)
        # Sanitización inteligente
        if tinfo.type.value == "unknown" and tinfo.confidence >= 0.8:
            log.warning("Target UNKNOWN con alta confianza UNKNOWN, solo fase 1: %s warnings=%s", target, tinfo.warnings)
        sanitized = sanitize_for_modules(tinfo)
        self._config.target = sanitized
        self._context["target_info"] = tinfo.__dict__
        self._context["target_raw"] = target
        self._context["target_sanitized"] = sanitized
        log.info("Target clasificado: %s → %s (type=%s conf=%.2f)", target, sanitized, tinfo.type.value, tinfo.confidence)

        # Filtrado inteligente de fases según tipo
        intelligent_phases = phases_for_target(tinfo.type) if hasattr(tinfo.type, "value") else set(range(1,11))
        # Intersect con enabled_phases configuradas (CLI)
        enabled_phases = [p for p in self._config.dag.enabled_phases if p in intelligent_phases]
        if not enabled_phases:
            log.warning("Ninguna fase relevante para tipo %s, forzando fase 1", tinfo.type.value)
            enabled_phases = [1]
        log.info("Fases seleccionadas (inteligente): %s (de %s configuradas)", enabled_phases, self._config.dag.enabled_phases)

        self._running = True
        # Checkpoint new job
        job_id = self._checkpoint.new_job(sanitized) if hasattr(self, "_checkpoint") else "no-ckpt"
        self._context["job_id"] = job_id
        # Storage scan_id = job_id
        try:
            await self.storage.create_scan(job_id, sanitized)
        except Exception as e:
            log.debug("create_scan: %s", e)
        self._state.dispatch(Action.INIT_SCAN, {
            "target":      sanitized,
            "phase_names": PHASE_NAMES,
        })
        self._state.dispatch(Action.START_SCAN, {})

        # Iniciar dashboard
        if self.dashboard:
            await self.dashboard.start()

        # Signal handler
        try:
            from core.signal_handler import GracefulShutdown
            GracefulShutdown(self).install()
        except Exception:
            pass

        await self._bus.publish("system.scan_start", {"target": sanitized, "job_id": job_id, "target_info": tinfo.__dict__}, Priority.CRITICAL)

        # enabled_phases ya filtrado arriba

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

            # Correlator analysis final
            try:
                corr_analysis = await self.correlator.analyze()
                self._context["correlator_analysis"] = corr_analysis
            except Exception as e:
                log.debug("Correlator analyze falló: %s", e)

            # Intel final
            final_score = await self.intel.compute_final_score(self._results)
            self._state.dispatch(Action.UPDATE_RISK_SCORE, {"score": final_score})
            self._context["risk_score"] = final_score

            # Checkpoint save
            try:
                if hasattr(self, "_checkpoint"):
                    self._checkpoint.save(self._phase_done, self._results, self._context, self._state.snapshot())
            except Exception:
                pass

            # Exportar
            await self._export_results(sanitized)
            # Cerrar scan en storage
            try:
                await self.storage.close_scan(job_id, final_score)
            except: pass

        except asyncio.CancelledError:
            log.warning("Scan cancelado")
            try:
                if hasattr(self, "_checkpoint"):
                    self._checkpoint.save(self._phase_done, self._results, self._context, self._state.snapshot())
            except: pass
        except Exception as exc:
            log.exception("Error crítico en orchestrator: %s", exc)
            self._state.dispatch(Action.ERROR, {"message": str(exc)})
        finally:
            self._state.dispatch(Action.COMPLETE_SCAN, {})
            if self.dashboard:
                await self.dashboard.stop()
            await self._bus.publish("system.scan_done", {}, Priority.CRITICAL)
            # Close bus/vigilante
            try:
                await self._bus.stop()
                await self._vigilante.stop()
                if self.storage: await self.storage.close()
                if self.crawler: await self.crawler.close()
                if self.evasion: await self.evasion.stop()
            except: pass

        # Return built report (evidence-driven) instead of raw context
        try:
            return self._build_report(sanitized)
        except:
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
                # Checkpoint incremental
                try:
                    if hasattr(self, "_checkpoint"):
                        self._checkpoint.save(self._phase_done, self._results, self._context, self._state.snapshot())
                except: pass

                # Emitir findings al bus (incluye provenance)
                for finding in result.findings:
                    await self._bus.publish("finding.new", finding.to_dict())
                    self._state.dispatch(Action.NEW_FINDING, {"severity": finding.severity.label})
                # Manejar DLQ si result sin findings pero con errores críticos
                if not result.findings and result.errors and hasattr(self, "_dlq"):
                    from core.queue import QueuedTask, TaskStatus
                    t = QueuedTask(priority=5, task_id=f"{module.NAME}-{phase_num}", module=module.NAME, phase=phase_num, target=self._config.target, attempts=1, last_error="; ".join(result.errors))
                    t.status = TaskStatus.FAILED

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

    def _build_report(self, target: str) -> dict:
        """Construye report unificado para exporters."""
        # Deduplicate findings globally por (type,value)
        seen=set()
        all_findings=[]
        for r in self._results.values():
            for f in r.findings:
                key=(f.type, f.value)
                if key not in seen:
                    seen.add(key); all_findings.append(f.to_dict())
        # Group by phase for legacy exporters
        phases_dict: dict[int, list[dict]] = {}
        for r in self._results.values():
            phases_dict.setdefault(int(r.phase), []).append(r.to_dict())
        phases=[{"phase": k, "results": v, "findings": [f for res in v for f in res["findings"]]} for k,v in sorted(phases_dict.items())]
        # Severity counts correctly using label
        sev_counts={}
        for f in all_findings:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"],0)+1
        return {
            "target": target,
            "job_id": self._context.get("job_id"),
            "target_info": self._context.get("target_info"),
            "phases": phases,
            "module_results": [r.to_dict() for r in self._results.values()],
            "findings": all_findings,
            "total_findings": len(all_findings),
            "severity_counts": sev_counts,
            "total_risk": self._state.state.risk_score,
            "scan_meta": self._state.snapshot(),
            "correlator": self._context.get("correlator_analysis"),
            "context": {k:v for k,v in self._context.items() if k not in ("correlator_analysis",)},
            "summary": {
                "total_findings": len(all_findings),
                "critical": sev_counts.get("CRITICAL",0),
                "high": sev_counts.get("HIGH",0),
                "medium": sev_counts.get("MEDIUM",0),
                "low": sev_counts.get("LOW",0),
                "info": sev_counts.get("INFO",0),
                "modules_run": len(self._results),
                "phases_run": len(phases),
            }
        }

    # ── Exportación ───────────────────────────
    async def _export_results(self, target: str) -> None:
        from export import get_exporter
        report = self._build_report(target)
        for fmt in self._config.export.formats:
            try:
                exporter = get_exporter(fmt)
                await exporter.export(report, self._config.export.output_dir)
                log.info("✓ Exportado: %s", fmt)
            except Exception as exc:
                log.error("Error exportando %s: %s", fmt, exc)

    # ── Evasion trigger ───────────────────────
    async def _on_evasion_trigger(self, event) -> None:
        if self.evasion:
            await self.evasion.activate()

    def stop(self) -> None:
        self._running = False
