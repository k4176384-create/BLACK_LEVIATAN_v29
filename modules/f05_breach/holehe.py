"""f05 — Holehe: verificar qué servicios están registrados con un email."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity

# Sitios a verificar con sus métodos de detección (reset password form)
SITES = {
    "Adobe":      ("POST", "https://account.adobe.com/passwd", "email", "code"),
    "Twitter":    ("GET",  "https://api.twitter.com/i/users/email_available.json", "email", "valid"),
    "GitHub":     ("GET",  "https://github.com/signup", "email", ""),
    "Instagram":  ("POST", "https://www.instagram.com/accounts/login/ajax/", "email", ""),
}


class Holehe(BaseModule):
    NAME        = "holehe"
    PHASE       = Phase.BREACH
    DESCRIPTION = "Detección de cuentas registradas en servicios populares"
    TAGS        = ["holehe", "email", "accounts", "registration"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            # Intentar usar holehe si está instalado
            emails = list(set(
                context.get("harvested_emails", []) +
                context.get("registrant_emails", [])
            ))[:10]

            if not emails:
                return self.skip(target, "Sin emails para verificar")

            try:
                import holehe.core as hc
                import holehe.modules as hm

                loop = asyncio.get_event_loop()
                for email in emails:
                    try:
                        modules = hm.get_functions(hc)
                        data = []
                        async with asyncio.timeout(60):
                            await hc.holehe_core(email, modules, data)
                        for entry in data:
                            if entry.get("exists"):
                                result.add_finding(
                                    type="account_found",
                                    value=f"{email} en {entry.get('name')}",
                                    severity=Severity.MEDIUM,
                                    confidence=0.85,
                                    metadata={
                                        "email":   email,
                                        "service": entry.get("name"),
                                        "ratelimit": entry.get("ratelimit", False),
                                    },
                                    tags=["holehe", "account"],
                                )
                    except Exception as exc:
                        result.add_error(f"holehe {email}: {exc}")

            except ImportError:
                # Fallback: verificación manual simplificada
                import aiohttp
                sem = asyncio.Semaphore(5)
                for email in emails[:5]:
                    async with sem:
                        # Verificación vía password reset de GitHub (método público)
                        try:
                            async with aiohttp.ClientSession() as s:
                                async with s.post(
                                    "https://github.com/sessions/forgot_password",
                                    data={"email": email},
                                    timeout=aiohttp.ClientTimeout(total=10),
                                ) as resp:
                                    if "We'll send you an email" in await resp.text():
                                        result.add_finding(
                                            type="account_found",
                                            value=f"{email} registrado en GitHub",
                                            severity=Severity.LOW,
                                            confidence=0.7,
                                            metadata={"email": email, "service": "GitHub"},
                                            tags=["account", "github"],
                                        )
                        except Exception:
                            pass

            result.risk_score = min(len(result.findings) * 0.5 + 1.0, 6.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
