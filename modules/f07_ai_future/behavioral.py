"""f07 — Behavioral Analysis: patrones de comportamiento de infraestructura."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class BehavioralAnalysis(BaseModule):
    NAME        = "behavioral"
    PHASE       = Phase.AI_FUTURE
    DESCRIPTION = "Detecta patrones anómalos: cambios de infra, inconsistencias TTL/geo"
    TAGS        = ["behavioral", "patterns", "anomaly", "ai"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            # Analizar inconsistencias entre datos recolectados
            geo_data      = context.get("geo_data", {})
            whois_data    = context.get("whois_data", {})
            detected_tech = context.get("detected_tech", [])
            resolved_ips  = context.get("resolved_ips", [])

            anomalies = []

            # Anomalía 1: Dominio registrado en país X pero servidor en país Y
            if whois_data and geo_data:
                registrant_country = whois_data.get("country", "").upper()
                server_countries   = {v.get("country", "") for v in geo_data.values()}
                if (registrant_country and server_countries and
                        registrant_country not in server_countries and
                        registrant_country not in ("", "N/A")):
                    anomalies.append({
                        "type":    "geo_mismatch",
                        "detail":  f"Registrado en {registrant_country}, servidor en {server_countries}",
                        "severity": Severity.LOW,
                    })

            # Anomalía 2: Múltiples IPs para el mismo dominio (CDN o posible fast-flux)
            if len(resolved_ips) > 5:
                # Fast-flux DNS = cambio rápido de IPs (usado en botnets/phishing)
                # Heurística: >5 IPs distintas
                anomalies.append({
                    "type":    "multiple_ips",
                    "detail":  f"{len(resolved_ips)} IPs distintas para el dominio",
                    "severity": Severity.LOW,
                })

            # Anomalía 3: Stack tecnológico inconsistente
            tech_types = [t.get("type") for t in detected_tech]
            langs_detected = [t.get("name") for t in detected_tech
                             if t.get("type") == "language"]
            if len(set(langs_detected)) > 3:
                anomalies.append({
                    "type":    "tech_fragmentation",
                    "detail":  f"Múltiples lenguajes detectados: {langs_detected[:5]}",
                    "severity": Severity.INFO,
                })

            # Anomalía 4: Cambios de infraestructura detectados por K2
            migrations = context.get("infrastructure_migrations", [])
            if migrations:
                anomalies.append({
                    "type":    "infra_migration",
                    "detail":  f"{len(migrations)} migraciones de infraestructura detectadas",
                    "severity": Severity.MEDIUM,
                })

            for anomaly in anomalies:
                result.add_finding(
                    type=f"behavioral_{anomaly['type']}",
                    value=anomaly["detail"],
                    severity=anomaly["severity"],
                    confidence=0.7,
                    metadata=anomaly,
                    tags=["behavioral", "anomaly"],
                )

            result.risk_score = min(len(anomalies) * 1.5, 6.0)
            result.metadata["anomalies_count"] = len(anomalies)

        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
