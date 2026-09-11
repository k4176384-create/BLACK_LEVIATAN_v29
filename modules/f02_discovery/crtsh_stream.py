"""f02 — crt.sh: Certificados SSL/TLS y subdominios del CT log."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class CrtshStream(BaseModule):
    NAME        = "crtsh_stream"
    PHASE       = Phase.DISCOVERY
    DESCRIPTION = "Certificate Transparency Logs via crt.sh — sin API key"
    TAGS        = ["crt", "ssl", "subdomains", "certificates"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            subdomains: set[str] = set()

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://crt.sh/",
                    params={"q": f"%.{target}", "output": "json"},
                    timeout=aiohttp.ClientTimeout(total=30),
                    headers={"Accept": "application/json"},
                ) as resp:
                    if resp.status == 200:
                        entries = await resp.json(content_type=None)
                        for entry in entries:
                            name = entry.get("name_value", "")
                            issuer = entry.get("issuer_name", "")
                            for sub in name.split("\n"):
                                sub = sub.strip().lstrip("*.")
                                if sub and sub.endswith(target) and sub != target:
                                    subdomains.add(sub)

                            # Certificados wildcard → posible ataque de subdomain takeover
                            if "*." in name:
                                result.add_finding(
                                    type="wildcard_cert",
                                    value=name,
                                    severity=Severity.LOW,
                                    confidence=0.9,
                                    metadata={"issuer": issuer},
                                    tags=["cert", "wildcard"],
                                )

            for sub in sorted(subdomains)[:200]:  # límite razonable
                result.add_finding(
                    type="subdomain_ct",
                    value=sub,
                    severity=Severity.INFO,
                    confidence=0.95,
                    tags=["subdomain", "crt"],
                )

            self.push_to_context(context, "ct_subdomains", list(subdomains))
            result.metadata = {"unique_subdomains": len(subdomains)}
            result.risk_score = min(len(subdomains) * 0.1 + 1.0, 6.0)

        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
