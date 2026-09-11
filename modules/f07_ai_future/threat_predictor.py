"""f07 — Threat Predictor: scoring de riesgo basado en hallazgos acumulados."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class ThreatPredictor(BaseModule):
    NAME        = "threat_predictor"
    PHASE       = Phase.AI_FUTURE
    DESCRIPTION = "Análisis de patrones de riesgo y predicción de vectores de ataque"
    TAGS        = ["ai", "risk", "prediction", "analysis"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            # Analizar datos acumulados del contexto
            open_ports     = context.get("open_ports", [])
            ct_subdomains  = context.get("ct_subdomains", [])
            brute_subs     = context.get("brute_subdomains", [])
            detected_tech  = context.get("detected_tech", [])
            social_profiles= context.get("social_profiles", [])

            total_attack_surface = len(open_ports) + len(ct_subdomains) + len(brute_subs)
            risk_factors = []

            # Factor 1: Superficie de ataque
            if len(open_ports) > 10:
                risk_factors.append(("Superficie de ataque amplia", 3.0,
                    f"{len(open_ports)} puertos abiertos"))
            elif len(open_ports) > 5:
                risk_factors.append(("Múltiples puertos expuestos", 1.5,
                    f"{len(open_ports)} puertos"))

            # Factor 2: Subdominios = más vectores
            all_subs = len(ct_subdomains) + len(brute_subs)
            if all_subs > 50:
                risk_factors.append(("Alta fragmentación de subdomínios", 2.0,
                    f"{all_subs} subdominios"))

            # Factor 3: Stack tecnológico desactualizado
            for tech in detected_tech:
                name = tech.get("name", "").lower()
                if any(old in name for old in ["php/5", "php/7.1", "php/7.2",
                                                "wordpress 4", "jquery 1.", "jquery 2."]):
                    risk_factors.append(("Tecnología desactualizada detectada", 2.5, name))

            # Factor 4: Puertos críticos abiertos
            critical_ports = {21, 23, 3389, 5900, 445, 2375, 6379, 11211}
            critical_open  = [p for p in open_ports if p in critical_ports]
            if critical_open:
                risk_factors.append(("Puertos de alto riesgo abiertos", 4.0,
                    str(critical_open)))

            # Factor 5: Alta exposición en redes sociales
            if len(social_profiles) > 20:
                risk_factors.append(("Alta exposición de personal", 1.0,
                    f"{len(social_profiles)} perfiles"))

            # Calcular risk score compuesto
            total_risk = sum(r[1] for r in risk_factors)
            result.risk_score = min(total_risk, 10.0)

            # Generar findings de predicción
            for factor_name, weight, detail in sorted(risk_factors, key=lambda x: -x[1]):
                sev = (Severity.CRITICAL if weight >= 4 else
                       Severity.HIGH    if weight >= 3 else
                       Severity.MEDIUM  if weight >= 1.5 else
                       Severity.LOW)
                result.add_finding(
                    type="risk_factor",
                    value=factor_name,
                    severity=sev,
                    confidence=0.8,
                    metadata={"detail": detail, "weight": weight},
                    tags=["ai", "risk_factor"],
                )

            # Resumen ejecutivo de vectores probables
            if total_risk > 5:
                result.add_finding(
                    type="attack_surface_summary",
                    value=f"Superficie de ataque ALTA: {len(risk_factors)} factores de riesgo (score: {total_risk:.1f}/10)",
                    severity=Severity.HIGH,
                    confidence=0.75,
                    metadata={
                        "factors":         [r[0] for r in risk_factors],
                        "attack_surface":  total_attack_surface,
                        "open_ports":      open_ports,
                    },
                    tags=["ai", "summary"],
                )

            result.metadata["risk_factors_count"] = len(risk_factors)
            result.metadata["attack_surface"]      = total_attack_surface

        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
