"""f01 — robots.txt y sitemap.xml: endpoints ocultos y estructura del sitio."""
from __future__ import annotations
import asyncio
import re
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class RobotsSitemap(BaseModule):
    NAME        = "robots_sitemap"
    PHASE       = Phase.RECON
    DESCRIPTION = "robots.txt + sitemap.xml: descubrir endpoints y directorios"
    TAGS        = ["robots", "sitemap", "discovery"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            base = f"https://{target}"
            interesting_paths = []

            async with aiohttp.ClientSession() as session:
                # robots.txt
                try:
                    async with session.get(
                        f"{base}/robots.txt",
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False,
                    ) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            disallowed = re.findall(r"Disallow:\s*(.+)", content, re.I)
                            sitemaps   = re.findall(r"Sitemap:\s*(.+)", content, re.I)

                            for path in disallowed:
                                path = path.strip()
                                if path and path != "/":
                                    interesting_paths.append(path)
                                    sev = Severity.INFO
                                    if any(kw in path.lower() for kw in
                                           ["admin","backup","private","secret","api","internal"]):
                                        sev = Severity.MEDIUM
                                    result.add_finding(
                                        type="robots_disallowed",
                                        value=path,
                                        severity=sev,
                                        confidence=1.0,
                                        tags=["robots", "path"],
                                    )
                            for sm in sitemaps:
                                result.add_finding(
                                    type="sitemap_url",
                                    value=sm.strip(),
                                    severity=Severity.INFO,
                                    confidence=1.0,
                                    tags=["sitemap"],
                                )
                except Exception as exc:
                    result.add_error(f"robots.txt: {exc}")

                # sitemap.xml
                try:
                    async with session.get(
                        f"{base}/sitemap.xml",
                        timeout=aiohttp.ClientTimeout(total=10),
                        ssl=False,
                    ) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            urls = re.findall(r"<loc>([^<]+)</loc>", content)
                            result.metadata["sitemap_urls"] = len(urls)
                            result.add_finding(
                                type="sitemap_found",
                                value=f"{len(urls)} URLs en sitemap.xml",
                                severity=Severity.INFO,
                                confidence=1.0,
                                metadata={"sample": urls[:10]},
                            )
                except Exception as exc:
                    result.add_error(f"sitemap.xml: {exc}")

            self.push_to_context(context, "discovered_paths", interesting_paths)
            result.risk_score = min(result.high_count * 2 + len(interesting_paths) * 0.3, 8.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
