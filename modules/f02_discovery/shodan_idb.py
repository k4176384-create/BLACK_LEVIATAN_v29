"""f02 — Shodan InternetDB (free, sin API key) + Shodan API si disponible."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class ShodanIdb(BaseModule):
    NAME        = "shodan_idb"
    PHASE       = Phase.DISCOVERY
    DESCRIPTION = "Shodan InternetDB (free) + Shodan Search API (opcional)"
    TAGS        = ["shodan", "idb", "ports", "vulnerabilities"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            ips = context.get("resolved_ips", [])
            if not ips:
                import socket
                try:
                    ips = [socket.gethostbyname(target)]
                except Exception:
                    return self.skip(target, "Sin IPs disponibles")

            async with aiohttp.ClientSession() as session:
                for ip in set(ips[:5]):
                    # Shodan InternetDB — completamente gratuito
                    try:
                        async with session.get(
                            f"https://internetdb.shodan.io/{ip}",
                            timeout=aiohttp.ClientTimeout(total=15),
                        ) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                ports  = data.get("ports", [])
                                vulns  = data.get("vulns", [])
                                cpes   = data.get("cpes", [])
                                tags   = data.get("tags", [])
                                hostnames = data.get("hostnames", [])

                                for port in ports:
                                    sev = Severity.INFO
                                    if port in (21, 23, 3389, 5900, 445, 139):
                                        sev = Severity.HIGH
                                    elif port in (22, 80, 443, 8080, 8443):
                                        sev = Severity.LOW
                                    result.add_finding(
                                        type="open_port",
                                        value=f"{ip}:{port}",
                                        severity=sev,
                                        confidence=0.95,
                                        metadata={"ip": ip, "port": port},
                                        tags=["port", "shodan"],
                                    )

                                for vuln in vulns:
                                    result.add_finding(
                                        type="cve_detected",
                                        value=vuln,
                                        severity=Severity.CRITICAL if "9." in str(vuln)
                                                 else Severity.HIGH,
                                        confidence=0.8,
                                        metadata={"ip": ip, "cve": vuln},
                                        tags=["cve", "vuln"],
                                    )

                                for hostname in hostnames:
                                    context.setdefault("shodan_hostnames", []).append(hostname)

                                result.metadata[ip] = {
                                    "ports": ports, "vulns": vulns,
                                    "cpes": cpes, "tags": tags,
                                }
                    except Exception as exc:
                        result.add_error(f"InternetDB {ip}: {exc}")

                # Shodan Search API (si hay key)
                shodan_key = self.config.api.shodan
                if shodan_key:
                    try:
                        async with session.get(
                            f"https://api.shodan.io/shodan/host/{ips[0]}",
                            params={"key": shodan_key},
                            timeout=aiohttp.ClientTimeout(total=15),
                        ) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                result.metadata["shodan_full"] = {
                                    "org":      data.get("org"),
                                    "os":       data.get("os"),
                                    "country":  data.get("country_name"),
                                    "asn":      data.get("asn"),
                                    "ports":    data.get("ports", []),
                                }
                    except Exception as exc:
                        result.add_error(f"Shodan API: {exc}")

            c_count = result.critical_count
            h_count = result.high_count
            result.risk_score = min(c_count * 3 + h_count * 1.5 + 1.0, 10.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
