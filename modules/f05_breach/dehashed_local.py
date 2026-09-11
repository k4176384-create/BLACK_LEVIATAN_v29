"""f05 — DeHashed: búsqueda en base de datos de brechas (API)."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class DehashedLocal(BaseModule):
    NAME             = "dehashed_local"
    PHASE            = Phase.BREACH
    DESCRIPTION      = "DeHashed API: brechas públicas por dominio"
    REQUIRES_API_KEY = True
    TAGS             = ["dehashed", "breach", "credentials"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        dh_key  = self.config.api.dehashed
        dh_user = self.config.api.dehashed_user
        if not dh_key or not dh_user:
            return self.skip(target, "BL_API__DEHASHED + BL_API__DEHASHED_USER requeridas")
        try:
            import aiohttp
            import base64
            credentials = base64.b64encode(f"{dh_user}:{dh_key}".encode()).decode()

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://api.dehashed.com/search",
                    params={"query": f"domain:{target}", "size": 50},
                    headers={"Authorization": f"Basic {credentials}", "Accept": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        entries = data.get("entries", []) or []
                        total   = data.get("total", 0)
                        result.metadata["total_records"] = total

                        for entry in entries[:30]:
                            email    = entry.get("email", "")
                            username = entry.get("username", "")
                            source   = entry.get("database_name", "unknown breach")
                            has_pw   = bool(entry.get("password") or entry.get("hashed_password"))

                            result.add_finding(
                                type="breach_record",
                                value=f"{email or username} en '{source}'",
                                severity=Severity.CRITICAL if has_pw else Severity.HIGH,
                                confidence=0.9,
                                metadata={
                                    "email":    email,
                                    "username": username,
                                    "source":   source,
                                    "has_password": has_pw,
                                    "ip_address":   entry.get("ip_address", ""),
                                },
                                tags=["breach", "dehashed"],
                            )

                        if total > 50:
                            result.add_finding(
                                type="breach_volume",
                                value=f"Total de {total} registros expuestos en brechas",
                                severity=Severity.CRITICAL,
                                confidence=1.0,
                                metadata={"total": total},
                                tags=["breach", "volume"],
                            )

            result.risk_score = min(result.critical_count * 3.5 + result.high_count * 2, 10.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
