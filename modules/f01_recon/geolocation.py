"""f01 — Geolocalización de IPs vía ip-api.com (free, no key)."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class Geolocation(BaseModule):
    NAME        = "geolocation"
    PHASE       = Phase.RECON
    DESCRIPTION = "Geolocalización: IP → País, AS, ISP, hosting provider"
    TAGS        = ["geo", "ip", "asn"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            ips = context.get("resolved_ips", [])
            if not ips:
                # Resolver el target directamente
                import socket
                try:
                    ips = [socket.gethostbyname(target)]
                except Exception:
                    return self.skip(target, "Sin IPs para geolocalizar")

            async with aiohttp.ClientSession() as session:
                for ip in set(ips[:10]):   # máximo 10 IPs por scan
                    try:
                        async with session.get(
                            f"http://ip-api.com/json/{ip}",
                            timeout=aiohttp.ClientTimeout(total=10),
                        ) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                if data.get("status") == "success":
                                    geo = {
                                        "ip":       ip,
                                        "country":  data.get("country"),
                                        "city":     data.get("city"),
                                        "isp":      data.get("isp"),
                                        "org":      data.get("org"),
                                        "asn":      data.get("as"),
                                        "lat":      data.get("lat"),
                                        "lon":      data.get("lon"),
                                        "timezone": data.get("timezone"),
                                    }
                                    result.add_finding(
                                        type="ip_geolocation",
                                        value=f"{ip} → {data.get('city')}, {data.get('country')}",
                                        severity=Severity.INFO,
                                        confidence=0.9,
                                        metadata=geo,
                                        tags=["geo", "ip"],
                                    )
                                    # Detectar hosting en país de alto riesgo
                                    high_risk_countries = {"RU","CN","KP","IR","BY"}
                                    if data.get("countryCode") in high_risk_countries:
                                        result.add_finding(
                                            type="high_risk_country_hosting",
                                            value=f"IP {ip} alojada en {data.get('country')}",
                                            severity=Severity.MEDIUM,
                                            confidence=0.7,
                                            metadata=geo,
                                        )
                                    context.setdefault("geo_data", {})[ip] = geo
                    except Exception as exc:
                        result.add_error(f"Geo {ip}: {exc}")

            result.risk_score = 2.0 + (result.high_count * 1.5)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
