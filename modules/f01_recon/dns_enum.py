"""f01 — DNS Enum: A, AAAA, MX, TXT, NS, CNAME, SOA, SPF/DMARC."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class DnsEnum(BaseModule):
    NAME        = "dns_enum"
    PHASE       = Phase.RECON
    DESCRIPTION = "DNS: todos los records + detección de misconfigs SPF/DMARC"
    TAGS        = ["dns", "records", "spf", "dmarc"]

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        ips: list[str] = []
        try:
            import dns.resolver
            import dns.exception
            resolver = dns.resolver.Resolver()
            resolver.timeout       = 5
            resolver.lifetime      = 10
            resolver.nameservers   = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

            for rtype in self.RECORD_TYPES:
                try:
                    answers = resolver.resolve(target, rtype)
                    for rdata in answers:
                        val = str(rdata)
                        result.add_finding(
                            type=f"dns_{rtype.lower()}",
                            value=val,
                            severity=Severity.INFO,
                            confidence=1.0,
                            tags=["dns", rtype.lower()],
                        )
                        if rtype == "A":
                            ips.append(val)
                        # SPF check
                        if rtype == "TXT" and "v=spf1" in val.lower():
                            if "+all" in val or "?all" in val:
                                result.add_finding(
                                    type="spf_misconfiguration",
                                    value=f"SPF permissive: {val[:120]}",
                                    severity=Severity.HIGH,
                                    confidence=0.95,
                                    tags=["spf", "email_security"],
                                )
                            else:
                                self.push_to_context(context, "has_spf", True)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                        dns.exception.Timeout, Exception):
                    pass

            # DMARC check
            try:
                dmarc_answers = resolver.resolve(f"_dmarc.{target}", "TXT")
                for rdata in dmarc_answers:
                    val = str(rdata)
                    if "v=DMARC1" in val:
                        self.push_to_context(context, "has_dmarc", True)
                        if "p=none" in val:
                            result.add_finding(
                                type="dmarc_weak",
                                value=f"DMARC p=none (no acción): {val[:120]}",
                                severity=Severity.MEDIUM,
                                confidence=0.9,
                                tags=["dmarc", "email_security"],
                            )
            except Exception:
                result.add_finding(
                    type="no_dmarc",
                    value=f"No hay registro DMARC para {target}",
                    severity=Severity.MEDIUM,
                    confidence=0.95,
                    tags=["dmarc", "email_security"],
                )

            # Guardar IPs en contexto para módulos posteriores
            if ips:
                self.push_to_context(context, "resolved_ips", ips)
                result.metadata["ips"] = ips

            risk = 0.0
            if result.critical_count > 0: risk = 8.0
            elif result.high_count > 0:   risk = 6.0
            elif len(result.findings) > 5:risk = 3.0
            else:                          risk = 1.5
            result.risk_score = risk

        except ImportError:
            result.add_error("dnspython no instalado: pip install dnspython")
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
