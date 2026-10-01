"""f10 — Cloud Bucket Hunt: enumeración de buckets públicos expuestos (S3, Azure, GCS)."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity

# Permutaciones comunes para nombres de buckets
BUCKET_SUFFIXES = [
    "", "-backup", "-dev", "-staging", "-prod", "-assets", "-static",
    "-media", "-data", "-files", "-uploads", "-images", "-logs",
    "-archive", "-public", "-cdn", "-web", "-api", "-config",
]


class CloudBucketHunt(BaseModule):
    NAME        = "cloud_bucket_hunt"
    PHASE       = Phase.CLOUD_INFRA
    DESCRIPTION = "Detecta buckets S3/Azure/GCS públicos accidentalmente expuestos"
    TAGS        = ["cloud", "s3", "azure", "gcs", "bucket", "misconfiguration"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            org_name    = target.split(".")[0].replace("-", "").replace("_", "")
            bucket_names = [f"{org_name}{suf}" for suf in BUCKET_SUFFIXES]
            # Agregar variaciones con guiones
            bucket_names += [f"{org_name}-{suf.lstrip('-')}" for suf in BUCKET_SUFFIXES if suf]

            sem = asyncio.Semaphore(20)

            async def check_s3(name: str) -> None:
                async with sem:
                    url = f"https://{name}.s3.amazonaws.com"
                    try:
                        async with aiohttp.ClientSession() as s:
                            async with s.get(
                                url,
                                timeout=aiohttp.ClientTimeout(total=8),
                                ssl=False,
                            ) as resp:
                                if resp.status == 200:
                                    # Bucket público con listing activo
                                    content = await resp.text()
                                    result.add_finding(
                                        type="s3_bucket_public",
                                        value=url,
                                        severity=Severity.CRITICAL,
                                        confidence=0.95,
                                        metadata={"bucket": name, "provider": "AWS S3",
                                                  "listing": "enabled"},
                                        tags=["s3", "cloud", "misconfiguration"],
                                    )
                                elif resp.status == 403:
                                    # Bucket existe pero acceso restringido — verificar ownership
                                    target_base = target.split(".")[0].lower()
                                    if target_base in name.lower():
                                        result.add_finding(
                                            type="s3_bucket_exists",
                                            value=url,
                                            severity=Severity.LOW,
                                            confidence=0.85,
                                            metadata={"bucket": name, "provider": "AWS S3",
                                                      "status": "access_denied"},
                                            tags=["s3", "cloud"],
                                        )
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        pass

            async def check_gcs(name: str) -> None:
                async with sem:
                    url = f"https://storage.googleapis.com/{name}"
                    try:
                        async with aiohttp.ClientSession() as s:
                            async with s.get(
                                url, timeout=aiohttp.ClientTimeout(total=8), ssl=False
                            ) as resp:
                                if resp.status == 200:
                                    result.add_finding(
                                        type="gcs_bucket_public",
                                        value=url,
                                        severity=Severity.CRITICAL,
                                        confidence=0.9,
                                        metadata={"bucket": name, "provider": "GCS"},
                                        tags=["gcs", "cloud", "misconfiguration"],
                                    )
                    except Exception:
                        pass

            async def check_azure(name: str) -> None:
                async with sem:
                    url = f"https://{name}.blob.core.windows.net/{name}"
                    try:
                        async with aiohttp.ClientSession() as s:
                            async with s.get(
                                url, timeout=aiohttp.ClientTimeout(total=8), ssl=False
                            ) as resp:
                                if resp.status in (200, 400):   # 400 = container exists
                                    result.add_finding(
                                        type="azure_blob_exists",
                                        value=f"https://{name}.blob.core.windows.net",
                                        severity=Severity.MEDIUM if resp.status == 400
                                                 else Severity.CRITICAL,
                                        confidence=0.8,
                                        metadata={"bucket": name, "provider": "Azure Blob"},
                                        tags=["azure", "cloud"],
                                    )
                    except Exception:
                        pass

            # Ejecutar verificaciones en paralelo
            tasks = []
            for name in set(bucket_names[:30]):   # límite razonable
                tasks.append(check_s3(name))
                tasks.append(check_gcs(name))
                tasks.append(check_azure(name))

            await asyncio.gather(*tasks)

            result.risk_score = min(result.critical_count * 4 + result.medium_count * 1.5, 10.0) \
                if hasattr(result, 'medium_count') else min(result.critical_count * 4, 10.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
