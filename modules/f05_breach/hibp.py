"""f05 — Have I Been Pwned: verificar breaches públicos de emails/dominio."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class HIBP(BaseModule):
    NAME             = "hibp"
    PHASE            = Phase.BREACH
    DESCRIPTION      = "Have I Been Pwned: breaches públicos del dominio"
    REQUIRES_API_KEY = True
    TAGS             = ["breach", "hibp", "email"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        api_key = self.config.api.hibp
        if not api_key:
            return self.skip(target, "BL_API__HIBP no configurada (hibp.com)")
        try:
            import aiohttp
            emails = context.get("harvested_emails", [])
            emails += context.get("registrant_emails", [])
            emails = list(set(e for e in emails if target in e))[:20]

            if not emails:
                # Verificar el dominio directamente
                emails = [f"info@{target}", f"admin@{target}", f"contact@{target}"]

            async with aiohttp.ClientSession() as session:
                for email in emails:
                    await asyncio.sleep(1.5)  # HIBP rate limit: 1 req/1.5s
                    async with session.get(
                        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                        headers={
                            "hibp-api-key": api_key,
                            "User-Agent": "BLACK-LEVIATAN-v29-OSINT",
                        },
                        params={"truncateResponse": "false"},
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        if resp.status == 200:
                            breaches = await resp.json()
                            for breach in breaches:
                                data_classes = breach.get("DataClasses", [])
                                has_passwords = "Passwords" in data_classes
                                result.add_finding(
                                    type="breach_found",
                                    value=f"{email} en breach '{breach.get('Name')}'",
                                    severity=Severity.CRITICAL if has_passwords else Severity.HIGH,
                                    confidence=1.0,
                                    metadata={
                                        "email":       email,
                                        "breach":      breach.get("Name"),
                                        "breach_date": breach.get("BreachDate"),
                                        "data_types":  data_classes,
                                        "verified":    breach.get("IsVerified"),
                                    },
                                    tags=["breach", "hibp"],
                                )
                        elif resp.status == 404:
                            result.add_finding(
                                type="no_breach",
                                value=f"{email}: sin breaches conocidos",
                                severity=Severity.INFO,
                                confidence=0.9,
                                tags=["hibp"],
                            )

            result.risk_score = min(result.critical_count * 3 + result.high_count * 2, 10.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
