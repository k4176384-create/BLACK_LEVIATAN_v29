"""f06 — Reddit OSINT: menciones, threads y sentimiento público."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class RedditOsint(BaseModule):
    NAME        = "reddit"
    PHASE       = Phase.SOCIAL
    DESCRIPTION = "Reddit: menciones del dominio, sentiment, incidentes reportados"
    TAGS        = ["reddit", "social", "mentions", "sentiment"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            org_name = target.split(".")[0]

            subreddits_to_search = [
                "netsec","cybersecurity","hacking","sysadmin",
                "devops","technology","privacy","DataBreaches",
            ]

            async with aiohttp.ClientSession(headers={
                "User-Agent": "BLResearch/1.0 OSINT Tool (security research)"
            }) as session:
                # Buscar menciones via pushshift/reddit search
                async with session.get(
                    "https://www.reddit.com/search.json",
                    params={"q": target, "sort": "new", "limit": 25, "type": "link"},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data    = await resp.json()
                        posts   = data.get("data", {}).get("children", [])
                        for post in posts:
                            p        = post.get("data", {})
                            title    = p.get("title", "")
                            url      = p.get("url", "")
                            score    = p.get("score", 0)
                            sub      = p.get("subreddit", "")
                            # Detectar posts negativos (incidentes, brechas)
                            negative_kw = ["breach","hack","leak","compromise","down",
                                           "outage","security","incident","fraud"]
                            is_negative = any(kw in title.lower() for kw in negative_kw)
                            result.add_finding(
                                type="reddit_mention",
                                value=title[:120],
                                severity=Severity.MEDIUM if is_negative else Severity.INFO,
                                confidence=0.8,
                                metadata={
                                    "url":       f"https://reddit.com{p.get('permalink', '')}",
                                    "score":     score,
                                    "subreddit": sub,
                                    "negative":  is_negative,
                                },
                                tags=["reddit", "mention"],
                            )

                # Verificar r/DataBreaches específicamente
                async with session.get(
                    "https://www.reddit.com/r/DataBreaches/search.json",
                    params={"q": org_name, "restrict_sr": "on", "limit": 10},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data  = await resp.json()
                        posts = data.get("data", {}).get("children", [])
                        for post in posts:
                            p = post.get("data", {})
                            result.add_finding(
                                type="data_breach_mention",
                                value=p.get("title", "")[:120],
                                severity=Severity.HIGH,
                                confidence=0.75,
                                metadata={
                                    "url":   f"https://reddit.com{p.get('permalink', '')}",
                                    "score": p.get("score", 0),
                                },
                                tags=["reddit", "breach"],
                            )

            result.risk_score = min(result.high_count * 2.5 + len(result.findings) * 0.2 + 1.0, 7.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
