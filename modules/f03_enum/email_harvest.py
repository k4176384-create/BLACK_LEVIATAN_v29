"""f03 — Email Harvest: scraping de emails desde web y cabeceras de dominio."""
from __future__ import annotations
import asyncio
import re
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class EmailHarvest(BaseModule):
    NAME        = "email_harvest"
    PHASE       = Phase.ENUM
    DESCRIPTION = "Recolecta emails expuestos en páginas web y contactos públicos"
    TAGS        = ["email", "harvest", "osint"]

    EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    SKIP_DOMAINS = frozenset(["example.com","test.com","sentry.io","w3.org",
                               "schema.org","jquery.com","google.com"])
    PAGES = ["", "/contact", "/about", "/team", "/about-us", "/contact-us"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        emails_found: set[str] = set()
        try:
            import aiohttp
            sem = asyncio.Semaphore(5)

            async def scrape(path: str) -> None:
                async with sem:
                    url = f"https://{target}{path}"
                    try:
                        async with aiohttp.ClientSession() as session:
                            async with session.get(
                                url,
                                timeout=aiohttp.ClientTimeout(total=15),
                                ssl=False,
                                allow_redirects=True,
                            ) as resp:
                                if resp.status == 200:
                                    text = await resp.text(errors="replace")
                                    for m in self.EMAIL_RE.finditer(text):
                                        email = m.group().lower()
                                        domain = email.split("@")[1]
                                        if domain not in self.SKIP_DOMAINS:
                                            emails_found.add(email)
                    except Exception:
                        pass

            await asyncio.gather(*[scrape(p) for p in self.PAGES])

            for email in sorted(emails_found):
                is_target_domain = email.endswith(f"@{target}")
                result.add_finding(
                    type="email_exposed",
                    value=email,
                    severity=Severity.LOW if is_target_domain else Severity.INFO,
                    confidence=0.9,
                    tags=["email", "harvest"],
                )

            self.push_to_context(context, "harvested_emails", list(emails_found))
            result.metadata["count"] = len(emails_found)
            result.risk_score = min(len(emails_found) * 0.4 + 1.0, 6.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
