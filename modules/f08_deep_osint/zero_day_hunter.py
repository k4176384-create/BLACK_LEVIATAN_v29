"""f08 — Zero Day Hunter: correlación de CVEs con el stack tecnológico detectado."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class ZeroDayHunter(BaseModule):
    NAME        = "zero_day_hunter"
    PHASE       = Phase.DEEP_OSINT
    DESCRIPTION = "CVE correlation: mapea tecnologías detectadas contra CVEs públicos (NVD)"
    TAGS        = ["cve", "nvd", "vulnerabilities", "correlation"]

    CVSS_THRESHOLDS = {"critical": 9.0, "high": 7.0, "medium": 4.0}

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            detected_tech = context.get("detected_tech", [])
            if not detected_tech:
                return self.skip(target, "Sin tecnologías detectadas en fases previas")

            # Construir queries de búsqueda para NVD (NIST National Vulnerability Database)
            cpe_queries: list[str] = []
            for tech in detected_tech[:15]:
                name = tech.get("name", "").lower().strip()
                if name and len(name) > 2:
                    # Extrae versión si está disponible (e.g., "WordPress 6.4")
                    import re
                    ver_match = re.search(r'[\d]+\.[\d]+(?:\.[\d]+)?', name)
                    base_name = re.sub(r'[\d\.\/]+', '', name).strip()
                    if base_name:
                        cpe_queries.append((base_name, ver_match.group() if ver_match else None))

            async with aiohttp.ClientSession() as session:
                checked = set()
                for product_name, version in cpe_queries[:10]:
                    if product_name in checked:
                        continue
                    checked.add(product_name)

                    await asyncio.sleep(0.6)   # NVD rate limit: 5 req/30s sin API key
                    params = {
                        "keywordSearch": product_name,
                        "resultsPerPage": 10,
                    }
                    if version:
                        params["versionStart"] = version
                    known_false_positives = ["gws", "gwsync", "gwscripts"]
                    if product_name.lower() in known_false_positives:
                        continue

                    try:
                        async with session.get(
                            "https://services.nvd.nist.gov/rest/json/cves/2.0",
                            params=params,
                            timeout=aiohttp.ClientTimeout(total=20),
                            headers={"Accept": "application/json"},
                        ) as resp:
                            if resp.status == 200:
                                data  = await resp.json()
                                vulns = data.get("vulnerabilities", [])
                                for vuln in vulns[:5]:
                                    cve  = vuln.get("cve", {})
                                    cve_id = cve.get("id", "")
                                    desc_list = cve.get("descriptions", [])
                                    description = next(
                                        (d["value"] for d in desc_list if d.get("lang") == "en"),
                                        "Sin descripción"
                                    )
                                    metrics = cve.get("metrics", {})
                                    cvss_score = 0.0
                                    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                                        if key in metrics and metrics[key]:
                                            cvss_score = metrics[key][0].get(
                                                "cvssData", {}
                                            ).get("baseScore", 0.0)
                                            break

                                    desc_lower = description.lower()
                                    if product_name.lower() == "gws" and ("gwscripts" in desc_lower or "gwsync" in desc_lower or "sap crm" in desc_lower or "linux kernel" in desc_lower or "amdgpu" in desc_lower):
                                        continue
                                    if cvss_score >= self.CVSS_THRESHOLDS["medium"]:
                                        sev = (Severity.CRITICAL if cvss_score >= 9.0 else
                                               Severity.HIGH     if cvss_score >= 7.0 else
                                               Severity.MEDIUM)
                                        result.add_finding(
                                            type="cve_correlated",
                                            value=f"{cve_id} (CVSS {cvss_score}) → {product_name}",
                                            severity=sev,
                                            confidence=0.7,
                                            metadata={
                                                "cve_id":      cve_id,
                                                "cvss":        cvss_score,
                                                "product":     product_name,
                                                "version":     version,
                                                "description": description[:300],
                                                "nvd_url":     f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                                            },
                                            tags=["cve", "vuln", product_name],
                                        )
                    except asyncio.TimeoutError:
                        result.add_error(f"NVD timeout para {product_name}")
                    except Exception as exc:
                        result.add_error(f"NVD {product_name}: {exc}")

            result.risk_score = min(result.critical_count * 3 + result.high_count * 2 + 1.5, 10.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
