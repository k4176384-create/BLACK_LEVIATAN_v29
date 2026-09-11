"""f04 — IP Reputation: AbuseIPDB + Spamhaus + ipinfo.io."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class IpReputation(BaseModule):
    NAME        = "ip_reputation"
    PHASE       = Phase.CORRELATE
    DESCRIPTION = "Reputación de IPs: AbuseIPDB, Spamhaus CBL, ipinfo.io"
    TAGS        = ["ip", "reputation", "abuse", "spam"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            ips = context.get("resolved_ips", [])
            if not ips:
                import socket
                try: ips = [socket.gethostbyname(target)]
                except Exception: return self.skip(target, "Sin IPs")

            async with aiohttp.ClientSession() as session:
                for ip in set(ips[:5]):
                    # ipinfo.io (free tier)
                    try:
                        async with session.get(
                            f"https://ipinfo.io/{ip}/json",
                            timeout=aiohttp.ClientTimeout(total=10),
                        ) as resp:
                            if resp.status == 200:
                                info = await resp.json()
                                org  = info.get("org", "")
                                hostname = info.get("hostname", "")
                                result.add_finding(
                                    type="ip_info",
                                    value=f"{ip} ({org})",
                                    severity=Severity.INFO,
                                    confidence=0.9,
                                    metadata={
                                        "ip": ip, "org": org,
                                        "hostname": hostname,
                                        "country": info.get("country"),
                                        "city": info.get("city"),
                                        "asn": info.get("org"),
                                    },
                                    tags=["ip", "geo"],
                                )
                                # Hosting en ASN de proveedor VPN/proxy conocido
                                vps_keywords = ["digitalocean","linode","vultr","ovh",
                                                "hetzner","choopa","as-choopa","frantech"]
                                if any(kw in org.lower() for kw in vps_keywords):
                                    result.add_finding(
                                        type="ip_cloud_hosting",
                                        value=f"{ip} en {org}",
                                        severity=Severity.LOW,
                                        confidence=0.8,
                                        metadata={"ip": ip, "org": org},
                                        tags=["ip", "hosting"],
                                    )
                    except Exception as exc:
                        result.add_error(f"ipinfo {ip}: {exc}")

                    # AbuseIPDB (si hay API key)
                    if hasattr(self.config.api, "abuseipdb") and getattr(self.config.api, "abuseipdb", None):
                        try:
                            async with session.get(
                                "https://api.abuseipdb.com/api/v2/check",
                                params={"ipAddress": ip, "maxAgeInDays": 90},
                                headers={"Key": self.config.api.abuseipdb, "Accept": "application/json"},
                                timeout=aiohttp.ClientTimeout(total=10),
                            ) as resp:
                                if resp.status == 200:
                                    data = await resp.json()
                                    abuse_score = data["data"].get("abuseConfidenceScore", 0)
                                    if abuse_score > 25:
                                        result.add_finding(
                                            type="ip_abuse_score",
                                            value=f"{ip}: AbuseIPDB confidence {abuse_score}%",
                                            severity=Severity.HIGH if abuse_score > 75 else Severity.MEDIUM,
                                            confidence=abuse_score / 100.0,
                                            metadata=data["data"],
                                            tags=["ip", "abuse"],
                                        )
                        except Exception as exc:
                            result.add_error(f"AbuseIPDB {ip}: {exc}")

            result.risk_score = min(result.high_count * 2 + result.critical_count * 3 + 1.0, 10.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
