"""f08 — Dark Web Threat Intelligence: búsqueda pasiva en agregadores de inteligencia.

Consulta APIs públicas de threat intelligence que agregan datos de fuentes oscuras.
NO realiza navegación directa: usa APIs legítimas de TI como OTX, BreachWatch, etc.
"""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class DarkwebSearch(BaseModule):
    NAME        = "darkweb_search"
    PHASE       = Phase.DEEP_OSINT
    DESCRIPTION = "Threat intel pasivo: ¿el dominio aparece en indicadores de compromiso públicos?"
    TAGS        = ["threat_intel", "ioc", "darkweb", "osint"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            org_name = target.split(".")[0]

            async with aiohttp.ClientSession(headers={
                "User-Agent": "BLResearch/1.0 ThreatIntelligence",
                "Accept":     "application/json",
            }) as session:

                # 1. OTX AlienVault — IOCs y pulsos de amenaza públicos
                async with session.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/general",
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as resp:
                    if resp.status == 200:
                        data          = await resp.json()
                        pulse_info    = data.get("pulse_info", {})
                        pulse_count   = pulse_info.get("count", 0)
                        pulses        = pulse_info.get("pulses", [])

                        if pulse_count > 0:
                            result.add_finding(
                                type="ioc_pulse_count",
                                value=f"{target} en {pulse_count} pulsos de amenaza (OTX)",
                                severity=Severity.HIGH if pulse_count >= 5 else Severity.MEDIUM,
                                confidence=0.8,
                                metadata={
                                    "source":       "OTX AlienVault",
                                    "pulse_count":  pulse_count,
                                    "sample_pulses": [p.get("name","") for p in pulses[:5]],
                                },
                                tags=["otx", "ioc"],
                            )
                        # Validation (reputación)
                        validation = data.get("validation", [])
                        for v in validation:
                            if v.get("name"):
                                result.add_finding(
                                    type="ioc_validation",
                                    value=f"Validado por: {v.get('name')} — {v.get('source','')}",
                                    severity=Severity.INFO,
                                    confidence=0.7,
                                    tags=["otx", "validation"],
                                )

                # 2. URLScan.io — escaneos previos del dominio
                async with session.get(
                    "https://urlscan.io/api/v1/search/",
                    params={"q": f"domain:{target}", "size": 10},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data    = await resp.json()
                        results = data.get("results", [])
                        total   = data.get("total", 0)
                        if total > 0:
                            # Detectar escaneos recientes desde países sospechosos
                            recent_countries = [
                                r.get("task", {}).get("country", "")
                                for r in results[:5]
                            ]
                            result.add_finding(
                                type="urlscan_history",
                                value=f"{total} escaneos previos en urlscan.io",
                                severity=Severity.INFO,
                                confidence=0.85,
                                metadata={
                                    "total":    total,
                                    "recent":   results[0].get("task", {}).get("time") if results else None,
                                    "source":   "urlscan.io",
                                },
                                tags=["urlscan", "scan_history"],
                            )

                # 3. ThreatFox (abuse.ch) — IOCs de malware
                async with session.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    json={"query": "search_ioc", "search_term": target},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data    = await resp.json()
                        iocs    = data.get("data", []) or []
                        for ioc in iocs[:5]:
                            ioc_type = ioc.get("ioc_type", "")
                            malware  = ioc.get("malware", "")
                            result.add_finding(
                                type="threatfox_ioc",
                                value=f"IOC en ThreatFox: {ioc_type} ({malware})",
                                severity=Severity.CRITICAL,
                                confidence=0.9,
                                metadata={
                                    "ioc_type":    ioc_type,
                                    "malware":     malware,
                                    "threat_type": ioc.get("threat_type"),
                                    "source":      "ThreatFox/abuse.ch",
                                },
                                tags=["threatfox", "malware", "ioc"],
                            )

            result.risk_score = min(result.critical_count * 4 + result.high_count * 2, 10.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
