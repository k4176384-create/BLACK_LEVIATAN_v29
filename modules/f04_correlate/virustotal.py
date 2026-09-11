"""f04 — VirusTotal: reputación de dominio, IPs, URLs y hashes."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class VirusTotal(BaseModule):
    NAME             = "virustotal"
    PHASE            = Phase.CORRELATE
    DESCRIPTION      = "VirusTotal: detecciones de motores AV y reputación de dominio"
    REQUIRES_API_KEY = True
    TAGS             = ["virustotal", "reputation", "malware", "av"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()

        api_key = self.config.api.virustotal
        if not api_key:
            return self.skip(target, "VT_API_KEY no configurada (BL_API__VIRUSTOTAL)")

        try:
            import aiohttp
            base_url = "https://www.virustotal.com/api/v3"
            headers  = {"x-apikey": api_key, "Accept": "application/json"}

            async with aiohttp.ClientSession(headers=headers) as session:
                # Reputación de dominio
                async with session.get(
                    f"{base_url}/domains/{target}",
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        attrs = data.get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        suspicious= stats.get("suspicious", 0)
                        total     = sum(stats.values()) if stats else 0

                        result.metadata["vt_stats"] = stats
                        result.metadata["reputation"] = attrs.get("reputation", 0)

                        if malicious > 0 or suspicious > 0:
                            sev = Severity.CRITICAL if malicious >= 3 else Severity.HIGH
                            result.add_finding(
                                type="vt_malicious_detections",
                                value=f"{malicious}/{total} motores detectaron amenaza",
                                severity=sev,
                                confidence=min(malicious / max(total, 1) + 0.5, 1.0),
                                metadata={
                                    "malicious":  malicious,
                                    "suspicious": suspicious,
                                    "total":      total,
                                    "stats":      stats,
                                },
                                tags=["vt", "malware"],
                            )
                        else:
                            result.add_finding(
                                type="vt_clean",
                                value=f"0/{total} detecciones",
                                severity=Severity.INFO,
                                confidence=0.9,
                                tags=["vt"],
                            )

                        # Categories
                        cats = attrs.get("categories", {})
                        if cats:
                            result.metadata["categories"] = list(set(cats.values()))[:10]

                # Verificar IPs resueltas
                for ip in context.get("resolved_ips", [])[:3]:
                    async with session.get(
                        f"{base_url}/ip_addresses/{ip}",
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as ip_resp:
                        if ip_resp.status == 200:
                            ip_data  = await ip_resp.json()
                            ip_attrs = ip_data.get("data", {}).get("attributes", {})
                            ip_stats = ip_attrs.get("last_analysis_stats", {})
                            ip_mal   = ip_stats.get("malicious", 0)
                            if ip_mal > 0:
                                result.add_finding(
                                    type="vt_ip_malicious",
                                    value=f"IP {ip}: {ip_mal} detecciones",
                                    severity=Severity.HIGH,
                                    confidence=0.85,
                                    metadata={"ip": ip, "stats": ip_stats},
                                    tags=["vt", "ip", "malware"],
                                )

            c = result.critical_count
            h = result.high_count
            result.risk_score = min(c * 4.0 + h * 2.0 + 1.0, 10.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
