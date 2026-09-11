"""
PLANTILLA — Renombra este archivo y edita los campos marcados con TODO
"""
from __future__ import annotations
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class MiNuevoModulo(BaseModule):                    # TODO: Renombra la clase
    NAME        = "mi_nuevo_modulo"                 # TODO: Identificador único
    PHASE       = Phase.RECON                       # TODO: Fase (RECON=1 hasta CLOUD_INFRA=10)
    DESCRIPTION = "Descripción de mi módulo"        # TODO: Qué hace
    AUTHOR      = "Luis Sánchez"
    TAGS        = ["custom"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            # TODO: Implementa tu lógica aquí
            # Leer contexto previo:
            #   ips = self.get_from_context(context, "resolved_ips", [])
            #
            # Agregar finding:
            #   result.add_finding(
            #       type="mi_hallazgo",
            #       value="valor_del_hallazgo",
            #       severity=Severity.INFO,
            #       confidence=0.9,
            #       metadata={},
            #   )
            #
            # Escribir al contexto:
            #   self.push_to_context(context, "mi_key", mi_dato)
            #
            # Skip limpio:
            #   return self.skip(target, "razón")

            result.risk_score = 0.0
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
