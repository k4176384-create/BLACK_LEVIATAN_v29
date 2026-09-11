"""f09 — Cert Stream: monitoreo de registros CT en tiempo real y análisis histórico."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class CertStream(BaseModule):
    NAME        = "cert_stream"
    PHASE       = Phase.HISTORICAL
    DESCRIPTION = "Analiza historial completo de certificados TLS del dominio via crt.sh"
    TAGS        = ["certs", "tls", "ct", "historical"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                # Historial completo de certs con fechas
                async with session.get(
                    "https://crt.sh/",
                    params={"q": target, "output": "json"},
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        certs = await resp.json(content_type=None)
                        issuers: dict[str, int] = {}
                        oldest_date = None
                        newest_date = None
                        wildcard_count = 0

                        for cert in certs[:500]:
                            issuer = cert.get("issuer_name", "")
                            # Acumular estadísticas de emisores
                            for ca in ["Let's Encrypt","DigiCert","Sectigo","GlobalSign",
                                       "GoDaddy","Amazon","Comodo","Google"]:
                                if ca.lower() in issuer.lower():
                                    issuers[ca] = issuers.get(ca, 0) + 1
                                    break
                            else:
                                issuers["Other"] = issuers.get("Other", 0) + 1

                            name = cert.get("name_value", "")
                            if "*." in name:
                                wildcard_count += 1

                            # Fechas
                            not_before = cert.get("not_before", "")
                            if not_before:
                                if oldest_date is None or not_before < oldest_date:
                                    oldest_date = not_before
                                if newest_date is None or not_before > newest_date:
                                    newest_date = not_before

                        result.metadata["total_certs"]     = len(certs)
                        result.metadata["issuers"]         = issuers
                        result.metadata["wildcard_certs"]  = wildcard_count
                        result.metadata["oldest_cert"]     = oldest_date
                        result.metadata["newest_cert"]     = newest_date

                        result.add_finding(
                            type="cert_history_summary",
                            value=f"{len(certs)} certificados históricos encontrados",
                            severity=Severity.INFO,
                            confidence=1.0,
                            metadata=result.metadata,
                            tags=["certs", "history"],
                        )

                        if wildcard_count > 10:
                            result.add_finding(
                                type="excessive_wildcard_certs",
                                value=f"{wildcard_count} certificados wildcard emitidos",
                                severity=Severity.LOW,
                                confidence=0.8,
                                tags=["certs", "wildcard"],
                            )

            result.risk_score = 1.5
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
