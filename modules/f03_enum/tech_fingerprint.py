"""f03 — Tech Fingerprint: stack tecnológico, frameworks, CMS, CDN."""
from __future__ import annotations
import asyncio
import re
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity

TECH_SIGNATURES = {
    # Headers HTTP
    "headers": {
        "x-powered-by":  lambda v: ("powered_by", v, Severity.INFO),
        "server":        lambda v: ("web_server", v, Severity.INFO),
        "x-generator":   lambda v: ("generator", v, Severity.INFO),
        "x-drupal-cache":lambda v: ("cms", "Drupal", Severity.INFO),
        "x-varnish":     lambda v: ("cache", "Varnish", Severity.INFO),
        "cf-ray":        lambda v: ("cdn", "Cloudflare", Severity.INFO),
        "x-amz-cf-id":   lambda v: ("cdn", "AWS CloudFront", Severity.INFO),
    },
    # Cookies
    "cookies": {
        "PHPSESSID":    ("language", "PHP"),
        "JSESSIONID":   ("language", "Java/JVM"),
        "ASP.NET_SessionId": ("framework", "ASP.NET"),
        "laravel_session": ("framework", "Laravel"),
        "django_session": ("framework", "Django"),
        "rack.session": ("framework", "Ruby/Rack"),
    },
    # HTML patterns
    "html": {
        r'wp-content|wordpress':          ("cms", "WordPress"),
        r'Joomla!|/components/com_':      ("cms", "Joomla"),
        r'drupal\.settings|drupalSettings':("cms", "Drupal"),
        r'<meta name="generator" content="([^"]+)"': ("generator", None),
        r'React\.createElement|__NEXT_DATA__': ("framework", "React/Next.js"),
        r'ng-version=|angular\.js':       ("framework", "Angular"),
        r'__vue__|Vue\.js':               ("framework", "Vue.js"),
        r'jquery[\-\.]([\d\.]+)\.min':    ("library", "jQuery"),
        r'bootstrap[\-\.]([\d\.]+)\.min': ("library", "Bootstrap"),
        r'data-shopify':                  ("ecommerce", "Shopify"),
        r'Magento':                       ("ecommerce", "Magento"),
    }
}


class TechFingerprint(BaseModule):
    NAME        = "tech_fingerprint"
    PHASE       = Phase.ENUM
    DESCRIPTION = "Stack tecnológico: CMS, frameworks, CDN, lenguajes"
    TAGS        = ["tech", "fingerprint", "wappalyzer"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        detected: list[dict] = []
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{target}",
                    timeout=aiohttp.ClientTimeout(total=20),
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    headers = dict(resp.headers)
                    html    = await resp.text(errors="replace")
                    cookies = {c.key: c.value for c in resp.cookies.values()}

                    # Analizar headers
                    for hdr, detect_fn in TECH_SIGNATURES["headers"].items():
                        val = headers.get(hdr) or headers.get(hdr.title())
                        if val:
                            tech_type, tech_name, sev = detect_fn(val)
                            detected.append({"type": tech_type, "name": tech_name or val})
                            # Versiones en Server header = divulgación de info
                            version_match = re.search(r"[\d\.]+", val)
                            final_sev = Severity.LOW if version_match else sev
                            result.add_finding(
                                type=f"tech_{tech_type}",
                                value=f"{tech_name or val}",
                                severity=final_sev,
                                confidence=0.95,
                                metadata={"header": hdr, "value": val},
                                tags=["tech", tech_type],
                            )

                    # Analizar cookies
                    for cookie_name, (tech_type, tech_name) in TECH_SIGNATURES["cookies"].items():
                        if cookie_name in cookies:
                            detected.append({"type": tech_type, "name": tech_name})
                            result.add_finding(
                                type=f"tech_{tech_type}",
                                value=tech_name,
                                severity=Severity.INFO,
                                confidence=0.9,
                                metadata={"cookie": cookie_name},
                                tags=["tech", tech_type],
                            )

                    # Analizar HTML
                    for pattern, (tech_type, tech_name) in TECH_SIGNATURES["html"].items():
                        m = re.search(pattern, html, re.I)
                        if m:
                            name = tech_name or (m.group(1) if m.lastindex else m.group())
                            detected.append({"type": tech_type, "name": name})
                            result.add_finding(
                                type=f"tech_{tech_type}",
                                value=str(name)[:80],
                                severity=Severity.INFO,
                                confidence=0.85,
                                metadata={"pattern": pattern[:50]},
                                tags=["tech", tech_type],
                            )

            self.push_to_context(context, "detected_tech", detected)
            result.metadata["tech_count"] = len(detected)
            result.risk_score = min(len(detected) * 0.2 + 1.0, 4.0)
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
