"""f10 — Tech Fingerprint Deep: análisis profundo de stack con headers de seguridad."""
from __future__ import annotations
import asyncio
import re
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class TechFingerprintDeep(BaseModule):
    NAME        = "tech_fingerprint_deep"
    PHASE       = Phase.CLOUD_INFRA
    DESCRIPTION = "Análisis profundo: security headers, CORS, CSP, Subresource Integrity"
    TAGS        = ["security_headers", "csp", "cors", "hsts", "tech"]

    REQUIRED_HEADERS = {
        "strict-transport-security": ("HSTS ausente", Severity.HIGH),
        "x-content-type-options":    ("X-Content-Type-Options ausente", Severity.MEDIUM),
        "x-frame-options":           ("Clickjacking protection ausente", Severity.MEDIUM),
        "content-security-policy":   ("CSP ausente", Severity.HIGH),
        "referrer-policy":           ("Referrer-Policy ausente", Severity.LOW),
        "permissions-policy":        ("Permissions-Policy ausente", Severity.LOW),
    }

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                for scheme in ("https", "http"):
                    try:
                        async with session.get(
                            f"{scheme}://{target}",
                            timeout=aiohttp.ClientTimeout(total=20),
                            ssl=False,
                            allow_redirects=True,
                        ) as resp:
                            headers    = {k.lower(): v for k, v in resp.headers.items()}
                            html       = await resp.text(errors="replace")
                            final_url  = str(resp.url)

                            # HTTP → HTTPS redirect check
                            if scheme == "http" and "https" not in final_url.lower():
                                result.add_finding(
                                    type="no_https_redirect",
                                    value="No redirige HTTP → HTTPS",
                                    severity=Severity.HIGH,
                                    confidence=0.95,
                                    tags=["https", "redirect"],
                                )

                            if scheme == "https":
                                # Security headers check
                                for hdr, (message, sev) in self.REQUIRED_HEADERS.items():
                                    if hdr not in headers:
                                        result.add_finding(
                                            type="missing_security_header",
                                            value=message,
                                            severity=sev,
                                            confidence=1.0,
                                            metadata={"missing_header": hdr},
                                            tags=["security_headers"],
                                        )
                                    else:
                                        # Verificar valores peligrosos
                                        val = headers[hdr]
                                        if hdr == "strict-transport-security":
                                            max_age = re.search(r"max-age=(\d+)", val)
                                            if max_age and int(max_age.group(1)) < 15768000:
                                                result.add_finding(
                                                    type="weak_hsts",
                                                    value=f"HSTS max-age muy corto: {val}",
                                                    severity=Severity.LOW,
                                                    confidence=0.9,
                                                    tags=["hsts"],
                                                )
                                        elif hdr == "content-security-policy":
                                            if "unsafe-inline" in val or "unsafe-eval" in val:
                                                result.add_finding(
                                                    type="weak_csp",
                                                    value=f"CSP con unsafe-inline/eval: {val[:200]}",
                                                    severity=Severity.MEDIUM,
                                                    confidence=0.9,
                                                    tags=["csp"],
                                                )

                                # CORS check
                                cors = headers.get("access-control-allow-origin", "")
                                if cors == "*":
                                    result.add_finding(
                                        type="cors_wildcard",
                                        value="CORS Access-Control-Allow-Origin: * (wildcard)",
                                        severity=Severity.MEDIUM,
                                        confidence=1.0,
                                        metadata={"cors_header": cors},
                                        tags=["cors"],
                                    )

                                # Cookie security
                                for cookie_hdr in resp.cookies.values():
                                    if not cookie_hdr.get("secure"):
                                        result.add_finding(
                                            type="cookie_no_secure",
                                            value=f"Cookie '{cookie_hdr.key}' sin flag Secure",
                                            severity=Severity.MEDIUM,
                                            confidence=0.9,
                                            tags=["cookie", "security"],
                                        )
                                    if not cookie_hdr.get("httponly"):
                                        result.add_finding(
                                            type="cookie_no_httponly",
                                            value=f"Cookie '{cookie_hdr.key}' sin flag HttpOnly",
                                            severity=Severity.MEDIUM,
                                            confidence=0.9,
                                            tags=["cookie", "security"],
                                        )
                            break  # Si https funcionó, no necesitamos http
                    except Exception:
                        if scheme == "https":
                            continue   # Intentar http

            result.risk_score = min(result.high_count * 2 + result.medium_count_val * 1.0, 8.0) \
                if False else min(result.high_count * 2 + len(result.findings) * 0.3, 8.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
