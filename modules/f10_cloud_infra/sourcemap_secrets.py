"""f10 — Sourcemap Secrets: secrets en archivos .map de JavaScript."""
from __future__ import annotations
import asyncio
import json
import re
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class SourcemapSecrets(BaseModule):
    NAME        = "sourcemap_secrets"
    PHASE       = Phase.CLOUD_INFRA
    DESCRIPTION = "Detecta secrets y código fuente expuesto en JavaScript source maps"
    TAGS        = ["sourcemap", "javascript", "secrets", "web"]

    SECRET_PATTERNS = {
        "aws_key":   r"AKIA[0-9A-Z]{16}",
        "api_key":   r"(?i)api[_-]?key\s*[=:]\s*['\"]([a-zA-Z0-9_\-]{20,50})['\"]",
        "private_key": r"-----BEGIN (RSA |EC |)PRIVATE KEY-----",
        "jwt":       r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        "github_pat":r"ghp_[a-zA-Z0-9]{36}",
        "stripe":    r"sk_live_[0-9a-zA-Z]{24,}",
        "password":  r"(?i)password\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        "conn_string":r"(?i)(mongodb|postgresql|mysql|redis)://[^\s\"'<>]+",
    }

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            # Obtener el HTML principal y buscar archivos .js con sourcemaps
            js_files: list[str] = []
            base = f"https://{target}"

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    base, timeout=aiohttp.ClientTimeout(total=15), ssl=False
                ) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        js_refs = re.findall(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html)
                        for js_url in js_refs[:20]:
                            if js_url.startswith("http"):
                                js_files.append(js_url)
                            elif js_url.startswith("/"):
                                js_files.append(f"{base}{js_url}")
                            else:
                                js_files.append(f"{base}/{js_url}")

                # Por cada archivo .js, buscar sourcemap embebido o enlazado
                sem = asyncio.Semaphore(5)

                async def analyze_js(js_url: str) -> None:
                    async with sem:
                        try:
                            async with session.get(
                                js_url, timeout=aiohttp.ClientTimeout(total=10), ssl=False
                            ) as resp:
                                if resp.status != 200:
                                    return
                                content = await resp.text()

                                # Buscar sourceMappingURL
                                map_match = re.search(
                                    r"//# sourceMappingURL=(.+\.map)", content
                                )
                                if map_match:
                                    map_url = map_match.group(1)
                                    if not map_url.startswith("http"):
                                        base_js = "/".join(js_url.split("/")[:-1])
                                        map_url = f"{base_js}/{map_url}"

                                    async with session.get(
                                        map_url, timeout=aiohttp.ClientTimeout(total=10), ssl=False
                                    ) as map_resp:
                                        if map_resp.status == 200:
                                            map_content = await map_resp.text()
                                            # ¡Source map expuesto! Analizar código fuente
                                            result.add_finding(
                                                type="sourcemap_exposed",
                                                value=map_url,
                                                severity=Severity.HIGH,
                                                confidence=1.0,
                                                metadata={"js_file": js_url,
                                                          "size_kb": len(map_content) // 1024},
                                                tags=["sourcemap", "js"],
                                            )
                                            # Buscar secrets en el source map
                                            for sec_type, pattern in self.SECRET_PATTERNS.items():
                                                matches = re.findall(pattern, map_content)
                                                for match in matches[:3]:
                                                    snip = match if isinstance(match, str) else match[0]
                                                    result.add_finding(
                                                        type=f"sourcemap_secret_{sec_type}",
                                                        value=f"Secret '{sec_type}' en {map_url}",
                                                        severity=Severity.CRITICAL,
                                                        confidence=0.8,
                                                        metadata={
                                                            "type":    sec_type,
                                                            "map_url": map_url,
                                                            "snippet": snip[:40] + "...",
                                                        },
                                                        tags=["sourcemap", "secret", sec_type],
                                                    )

                                # Buscar secrets en el JS directamente
                                for sec_type, pattern in self.SECRET_PATTERNS.items():
                                    matches = re.findall(pattern, content)
                                    for match in matches[:2]:
                                        snip = match if isinstance(match, str) else match[0]
                                        result.add_finding(
                                            type=f"js_hardcoded_{sec_type}",
                                            value=f"Hardcoded {sec_type} en {js_url}",
                                            severity=Severity.CRITICAL,
                                            confidence=0.75,
                                            metadata={"js_url": js_url, "type": sec_type},
                                            tags=["js", "secret", sec_type],
                                        )
                        except Exception:
                            pass

                await asyncio.gather(*[analyze_js(js) for js in js_files])

            result.risk_score = min(result.critical_count * 4 + result.high_count * 2, 10.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
