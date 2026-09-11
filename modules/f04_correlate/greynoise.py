"""f04 — GreyNoise: contexto de IPs (scanner, noise, riot)."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class GreyNoise(BaseModule):
    NAME             = "greynoise"
    PHASE            = Phase.CORRELATE
    DESCRIPTION      = "GreyNoise: ¿la IP es un scanner conocido? ¿noise o malicious?"
    REQUIRES_API_KEY = True
    TAGS             = ["greynoise", "ip", "scanner", "noise"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        api_key = self.config.api.greynoise
        if not api_key:
            return self.skip(target, "BL_API__GREYNOISE no configurada")
        try:
            import aiohttp
            ips = context.get("resolved_ips", [])
            if not ips:
                return self.skip(target, "Sin IPs en contexto")

            async with aiohttp.ClientSession() as session:
                for ip in set(ips[:5]):
                    async with session.get(
                        f"https://api.greynoise.io/v3/community/{ip}",
                        headers={"key": api_key},
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            classification = data.get("classification", "unknown")
                            noise   = data.get("noise", False)
                            riot    = data.get("riot", False)
                            name    = data.get("name", "")

                            if classification == "malicious":
                                result.add_finding(
                                    type="greynoise_malicious",
                                    value=f"{ip} clasificada como maliciosa ({name})",
                                    severity=Severity.CRITICAL,
                                    confidence=0.9,
                                    metadata=data,
                                    tags=["greynoise", "malicious"],
                                )
                            elif noise:
                                result.add_finding(
                                    type="greynoise_noise",
                                    value=f"{ip} es un scanner de internet ({name})",
                                    severity=Severity.LOW,
                                    confidence=0.85,
                                    metadata=data,
                                    tags=["greynoise", "scanner"],
                                )
                            elif riot:
                                result.add_finding(
                                    type="greynoise_riot",
                                    value=f"{ip} es servicio legítimo conocido ({name})",
                                    severity=Severity.INFO,
                                    confidence=0.95,
                                    metadata=data,
                                    tags=["greynoise", "riot"],
                                )

            result.risk_score = min(result.critical_count * 4 + 1.0, 10.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
