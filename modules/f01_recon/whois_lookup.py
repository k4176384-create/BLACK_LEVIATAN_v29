"""f01 — WHOIS Lookup: registros de dominio, fechas, registrante."""
from __future__ import annotations
import asyncio
import re
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class WhoisLookup(BaseModule):
    NAME        = "whois_lookup"
    PHASE       = Phase.RECON
    DESCRIPTION = "WHOIS: registrante, fechas, nameservers, registrar"
    TAGS        = ["whois", "domain", "registration"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import whois as python_whois
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(None, python_whois.whois, target)

            if data:
                result.metadata = {
                    "registrar":       str(data.registrar or "N/A"),
                    "creation_date":   str(data.creation_date or "N/A"),
                    "expiration_date": str(data.expiration_date or "N/A"),
                    "updated_date":    str(data.updated_date or "N/A"),
                    "name_servers":    [str(n) for n in (data.name_servers or [])],
                    "status":          str(data.status or "N/A"),
                    "org":             str(data.org or "N/A"),
                    "country":         str(data.country or "N/A"),
                    "emails":          list(data.emails or []),
                }

                # Dominio próximo a vencer (< 30 días) → finding
                if data.expiration_date:
                    exp = data.expiration_date
                    if isinstance(exp, list):
                        exp = exp[0]
                    try:
                        import datetime
                        if hasattr(exp, "timestamp"):
                            days_left = (exp - datetime.datetime.now()).days
                            if days_left < 30:
                                result.add_finding(
                                    type="expiring_domain",
                                    value=f"{target} vence en {days_left} días",
                                    severity=Severity.HIGH,
                                    confidence=1.0,
                                    metadata={"days_left": days_left},
                                )
                    except Exception:
                        pass

                # Registrant email → finding de intel
                if data.emails:
                    for email in (data.emails if isinstance(data.emails, list) else [data.emails]):
                        if email:
                            result.add_finding(
                                type="registrant_email",
                                value=str(email),
                                severity=Severity.INFO,
                                confidence=1.0,
                                tags=["whois", "email"],
                            )
                            self.push_to_context(context, "registrant_emails",
                                context.get("registrant_emails", []) + [str(email)])

                result.risk_score = 2.0 if result.findings else 1.0
                self.push_to_context(context, "whois_data", result.metadata)

            await self.emit("complete", result.metadata)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
