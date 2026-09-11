"""f08 — Ransomware Leaks: threat intelligence sobre grupos activos y víctimas publicadas."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class RansomwareLeaks(BaseModule):
    NAME        = "ransomware_leaks"
    PHASE       = Phase.DEEP_OSINT
    DESCRIPTION = "Threat intel: ¿el dominio aparece en listas públicas de víctimas de ransomware?"
    TAGS        = ["ransomware", "threat_intel", "victims", "monitoring"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            # ransomware.live — API pública de threat intelligence sobre víctimas de ransomware
            # Datos públicamente disponibles, indexados por investigadores de seguridad
            async with aiohttp.ClientSession(headers={
                "User-Agent": "BLResearch/1.0 SecurityResearch",
                "Accept": "application/json",
            }) as session:
                # Buscar en API pública de ransomware.live
                async with session.get(
                    "https://api.ransomware.live/victims",
                    params={"domain": target},
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        victims = data if isinstance(data, list) else data.get("victims", [])
                        for victim in victims[:10]:
                            group    = victim.get("group", "unknown")
                            domain   = victim.get("website", target)
                            pub_date = victim.get("published", "")
                            country  = victim.get("country", "")
                            result.add_finding(
                                type="ransomware_victim_record",
                                value=f"{domain} víctima de '{group}' ({pub_date})",
                                severity=Severity.CRITICAL,
                                confidence=0.85,
                                metadata={
                                    "group":     group,
                                    "domain":    domain,
                                    "published": pub_date,
                                    "country":   country,
                                    "source":    "ransomware.live (public threat intel)",
                                },
                                tags=["ransomware", "victim", group.lower()],
                            )

                # Verificar también en AlienVault OTX (pulsos públicos)
                org_name = target.split(".")[0]
                async with session.get(
                    f"https://otx.alienvault.com/api/v1/search/pulses/",
                    params={"q": org_name, "limit": 5, "sort": "-modified"},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data   = await resp.json()
                        pulses = data.get("results", [])
                        for pulse in pulses:
                            pulse_name = pulse.get("name", "")
                            tags_list  = pulse.get("tags", [])
                            if any(kw in " ".join(tags_list + [pulse_name]).lower()
                                   for kw in ["ransomware", "breach", "threat", "apt"]):
                                result.add_finding(
                                    type="threat_intel_pulse",
                                    value=pulse_name[:120],
                                    severity=Severity.HIGH,
                                    confidence=0.65,
                                    metadata={
                                        "pulse_id":  pulse.get("id"),
                                        "tags":      tags_list[:10],
                                        "tlp":       pulse.get("tlp"),
                                        "source":    "OTX AlienVault",
                                    },
                                    tags=["otx", "threat_intel"],
                                )

            result.risk_score = min(result.critical_count * 4 + result.high_count * 2, 10.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
