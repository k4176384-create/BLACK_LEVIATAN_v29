"""f06 — LinkedIn OSINT: empleados, tecnologías y estructura de la empresa."""
from __future__ import annotations
import asyncio
import re
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class LinkedinOsint(BaseModule):
    NAME        = "linkedin_osint"
    PHASE       = Phase.SOCIAL
    DESCRIPTION = "LinkedIn (datos públicos vía Google): empleados, tecnologías usadas"
    TAGS        = ["linkedin", "employees", "social", "osint"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            org_name = target.split(".")[0]

            async with aiohttp.ClientSession(headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
            }) as session:
                # Google dork para perfiles de LinkedIn (sólo datos públicos indexados)
                queries = [
                    f'site:linkedin.com/in "{org_name}"',
                    f'site:linkedin.com/company "{org_name}"',
                ]
                for query in queries:
                    async with session.get(
                        "https://html.duckduckgo.com/html/",
                        params={"q": query},
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        if resp.status == 200:
                            html = await resp.text()
                            links = re.findall(
                                r'href="(https://[a-z\.]+linkedin\.com/(?:in|company)/[^"&]+)"',
                                html
                            )
                            names = re.findall(
                                r'class="result__title">([^<]+)<', html
                            )
                            for link in set(links[:15]):
                                is_employee = "/in/" in link
                                result.add_finding(
                                    type="linkedin_employee" if is_employee else "linkedin_company",
                                    value=link,
                                    severity=Severity.INFO,
                                    confidence=0.7,
                                    metadata={"url": link, "is_employee": is_employee},
                                    tags=["linkedin", "social"],
                                )

                result.metadata["profiles_found"] = len(result.findings)
                result.risk_score = min(len(result.findings) * 0.2 + 1.0, 4.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
