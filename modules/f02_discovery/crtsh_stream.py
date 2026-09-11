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
                                # Validación: filtrar emails, espacios, CN=, y verificar FQDN
                                if not sub or "@" in sub or " " in sub or "CN=" in sub or "," in sub:
                                    continue
                                # Debe ser FQDN válido y terminar en target
                                if sub and sub.endswith(target) and sub != target:
                                    # Labels 1-63 chars, no empezar con -
                                    import re
                                    if re.match(r"^(?!-)[A-Za-z0-9.-]{1,253}$", sub):
                                        subdomains.add(sub.lower())

                            # Certificados wildcard → sanitizar valor (sin newline)
                            if "*." in name:
                                clean_name = name.replace("\n"," ").strip()[:200]
                                result.add_finding(
                                    type="wildcard_cert",
                                    value=clean_name,
                                    severity=Severity.LOW,
                                    confidence=0.9,
                                    metadata={"issuer": issuer},
                                    tags=["cert", "wildcard"],
                                )

            from core.validation import validate_finding, confidence_engine
            from modules.base_module import ValidationState
            for sub in sorted(subdomains)[:200]:
                val = validate_finding("subdomain_ct", sub, {})
                vs = ValidationState.OBSERVED if val["validation_state"]=="OBSERVED" else ValidationState.INFERRED
                conf = confidence_engine("crtsh", 0.95, 0)
                result.add_finding(
                    type="subdomain_ct",
                    value=sub,
                    severity=Severity.INFO,
                    confidence=conf,
                    tags=["subdomain", "crt"],
                    validation_state=vs,
                    provenance={"source": "crt.sh", "source_type": "ct_log", "method": "crtsh_stream"},
                    limitations=val["limitations"],
                )

            self.push_to_context(context, "ct_subdomains", list(subdomains))
            result.metadata = {"unique_subdomains": len(subdomains)}
            result.risk_score = min(len(subdomains) * 0.1 + 1.0, 6.0)

        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
