"""f05 — Paste Monitor: buscar el dominio en Pastebin/pastebins públicos."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class PasteMonitor(BaseModule):
    NAME        = "paste_monitor"
    PHASE       = Phase.BREACH
    DESCRIPTION = "Busca el dominio en pastebins públicos (leaks, credentials)"
    TAGS        = ["paste", "leak", "pastebin", "credentials"]

    SEARCH_ENGINES = [
        "https://psbdmp.ws/api/v3/search/{target}",         # psb dump (indexa pastes)
        "https://publicwww.com/websites/{target}/",          # publicwww
    ]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            import re

            async with aiohttp.ClientSession() as session:
                # psbdmp.ws — indexa Pastebin públicos
                try:
                    async with session.get(
                        f"https://psbdmp.ws/api/v3/search/{target}",
                        timeout=aiohttp.ClientTimeout(total=20),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            pastes = data.get("data", [])
                            for paste in pastes[:20]:
                                paste_id   = paste.get("id", "")
                                paste_tags = paste.get("tags", "")
                                # Pastes con palabras clave de credenciales
                                cred_keywords = ["password","credential","leak","hack",
                                                 "dump","breach","combo","list"]
                                is_sensitive = any(kw in paste_tags.lower() for kw in cred_keywords)
                                result.add_finding(
                                    type="paste_found",
                                    value=f"https://pastebin.com/{paste_id}",
                                    severity=Severity.HIGH if is_sensitive else Severity.MEDIUM,
                                    confidence=0.7,
                                    metadata={
                                        "paste_id":  paste_id,
                                        "tags":      paste_tags,
                                        "sensitive": is_sensitive,
                                    },
                                    tags=["paste", "leak"],
                                )
                except Exception as exc:
                    result.add_error(f"psbdmp: {exc}")

                # DuckDuckGo search para pastebins (sin JS requerido)
                try:
                    async with session.get(
                        "https://html.duckduckgo.com/html/",
                        params={"q": f'site:pastebin.com "{target}"'},
                        timeout=aiohttp.ClientTimeout(total=15),
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"},
                    ) as resp:
                        if resp.status == 200:
                            html = await resp.text()
                            paste_links = re.findall(
                                r'href="(https://pastebin\.com/[a-zA-Z0-9]+)"', html
                            )
                            for link in set(paste_links[:10]):
                                if not any(link in f.value for f in result.findings):
                                    result.add_finding(
                                        type="paste_indexed",
                                        value=link,
                                        severity=Severity.MEDIUM,
                                        confidence=0.6,
                                        tags=["paste"],
                                    )
                except Exception as exc:
                    result.add_error(f"DDG paste: {exc}")

            medium_count = sum(1 for f in result.findings if f.severity == Severity.MEDIUM)
            result.risk_score = min(result.high_count * 2.5 + medium_count * 1.0 + 1.0, 9.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
