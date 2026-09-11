"""f09 — Wayback Machine Deep: páginas eliminadas, versiones antiguas, endpoints históricos."""
from __future__ import annotations
import asyncio
import re
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class WaybackDeep(BaseModule):
    NAME        = "wayback_deep"
    PHASE       = Phase.HISTORICAL
    DESCRIPTION = "Wayback Machine: endpoints históricos, config expuesta, versiones antiguas"
    TAGS        = ["wayback", "historical", "archive", "web"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                # CDX API — inventario completo de snapshots
                async with session.get(
                    "http://web.archive.org/cdx/search/cdx",
                    params={
                        "url":       f"*.{target}/*",
                        "output":    "json",
                        "limit":     200,
                        "collapse":  "urlkey",
                        "filter":    "statuscode:200",
                        "fl":        "original,statuscode,timestamp,mimetype",
                    },
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        rows = await resp.json()
                        sensitive_patterns = [
                            r'\.env$', r'\.git/', r'backup', r'\.sql', r'\.bak',
                            r'config\.', r'admin/', r'wp-config', r'database',
                            r'credentials', r'secret', r'private', r'\.key$',
                            r'phpinfo', r'\.conf$',
                        ]
                        for row in rows[1:]:   # Skip header
                            if len(row) < 4:
                                continue
                            url, status, ts, mime = row[0], row[1], row[2], row[3]
                            for pattern in sensitive_patterns:
                                if re.search(pattern, url.lower()):
                                    # Formatear timestamp
                                    year = ts[:4] if ts else "?"
                                    result.add_finding(
                                        type="historical_sensitive_path",
                                        value=url,
                                        severity=Severity.HIGH,
                                        confidence=0.8,
                                        metadata={
                                            "archived_year": year,
                                            "mime":          mime,
                                            "wayback_url":   f"https://web.archive.org/web/{ts}/{url}",
                                        },
                                        tags=["wayback", "sensitive", "historical"],
                                    )
                                    break

                # Buscar versiones antiguas del robots.txt
                async with session.get(
                    "http://archive.org/wayback/available",
                    params={"url": f"{target}/robots.txt"},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        snap = data.get("archived_snapshots", {}).get("closest", {})
                        if snap.get("available"):
                            result.add_finding(
                                type="historical_robots_txt",
                                value=snap.get("url", ""),
                                severity=Severity.INFO,
                                confidence=0.9,
                                metadata={"timestamp": snap.get("timestamp"),
                                          "status":    snap.get("status")},
                                tags=["wayback", "robots"],
                            )

            result.risk_score = min(result.high_count * 2.5 + len(result.findings) * 0.2, 8.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
