"""
plugins/example_plugin/plugin.py — Plugin de ejemplo funcional

Este archivo es una plantilla completa y funcional.
Copia esta estructura para crear tus propios módulos.

Pasos para crear tu módulo:
  1. Copia la carpeta plugins/example_plugin/ con un nuevo nombre
  2. Edita manifest.yaml: cambia name, description, author, phase
  3. Edita plugin.py: cambia NAME, PHASE, DESCRIPTION e implementa run()
  4. Reinicia BLACK LEVIATAN o llama loader.reload_plugin("tu_modulo")
  5. ¡Listo! El módulo aparece automáticamente en el dashboard

Ver PLUGIN_GUIDE.md para documentación completa.
"""
from __future__ import annotations
import asyncio
import time

# Importar las clases base del proyecto
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class ExampleCustomModule(BaseModule):
    """
    Módulo de ejemplo que demuestra el contrato completo de un plugin.
    """

    # ── Metadatos del módulo (OBLIGATORIOS) ─────────────────────────────────
    NAME        = "example_custom_module"     # Identificador único. Sin espacios.
    PHASE       = Phase.RECON                 # Fase del DAG donde se ejecuta (1-10)
    DESCRIPTION = "Módulo de ejemplo — demuestra la API de plugins"
    VERSION     = "1.0.0"
    AUTHOR      = "Tu Nombre Aquí"

    # ── Metadatos opcionales ─────────────────────────────────────────────────
    REQUIRES_API_KEY = False    # True si necesitas una API key
    REQUIRES_TOR     = False    # True si este módulo necesita Tor
    DEPENDENCIES     = []       # Lista de NAMEs de módulos que deben correr antes
    TAGS             = ["example", "custom", "recon"]

    # ── Lógica principal (OBLIGATORIA) ───────────────────────────────────────
    async def run(self, target: str, context: dict) -> ModuleResult:
        """
        Implementa aquí la lógica de tu módulo.

        Args:
            target:  Dominio/IP objetivo. Ej: "example.com", "1.2.3.4"
            context: Datos compartidos entre módulos. Lee y escribe aquí.
                     Ejemplo: context.get("resolved_ips") para IPs de DNS Enum

        Returns:
            ModuleResult con todos los findings que encontraste.

        REGLAS:
          - NUNCA lances excepciones sin atraparlas — usa result.add_error()
          - Emite findings con result.add_finding() por cada hallazgo
          - Guarda datos útiles para otros módulos con self.push_to_context()
          - Respeta los timeouts — el orchestrator cancela tras 120s por default
        """
        result = self.make_result(target)
        t0 = time.time()

        try:
            # ── Ejemplo 1: Leer datos del contexto de fases anteriores ────
            resolved_ips = self.get_from_context(context, "resolved_ips", default=[])
            if not resolved_ips:
                # Si no hay datos necesarios, usa self.skip() para saltar limpiamente
                return self.skip(target, "No hay IPs resueltas del módulo dns_enum")

            # ── Ejemplo 2: Emitir un finding ─────────────────────────────
            for ip in resolved_ips[:3]:
                result.add_finding(
                    type="example_finding",           # Tipo descriptivo del hallazgo
                    value=f"IP encontrada: {ip}",    # El dato en sí
                    severity=Severity.INFO,           # INFO/LOW/MEDIUM/HIGH/CRITICAL
                    confidence=0.9,                   # 0.0-1.0, qué tan seguro estás
                    metadata={                        # Datos adicionales (dict)
                        "ip":     ip,
                        "source": "example_module",
                    },
                    tags=["example", "ip"],           # Tags para filtrado
                )

            # ── Ejemplo 3: Guardar datos para módulos siguientes ──────────
            self.push_to_context(context, "example_processed_ips", resolved_ips)

            # ── Ejemplo 4: Emitir evento al bus ──────────────────────────
            await self.emit("analysis_complete", {"ips_analyzed": len(resolved_ips)})

            # ── Ejemplo 5: Verificar API key ──────────────────────────────
            if self.REQUIRES_API_KEY:
                shodan_key = self.config.api.shodan
                if not shodan_key:
                    result.add_error("Shodan API key requerida: configura BL_API__SHODAN")
                    return result

            # ── Calcular risk score (0.0-10.0) ────────────────────────────
            result.risk_score = 1.5 if result.findings else 0.0

        except Exception as exc:
            # Atrapar TODAS las excepciones y reportarlas limpiamente
            result.add_error(f"Error inesperado: {exc}")

        # SIEMPRE registrar el tiempo de ejecución al final
        result.execution_time = time.time() - t0
        return result

    # ── Métodos opcionales de ciclo de vida ──────────────────────────────────
    async def setup(self) -> None:
        """Inicialización antes del run. Abre conexiones, carga modelos, etc."""
        # Ejemplo: inicializar cliente HTTP persistente
        pass

    async def teardown(self) -> None:
        """Limpieza después del run. Cierra conexiones, libera recursos."""
        pass
