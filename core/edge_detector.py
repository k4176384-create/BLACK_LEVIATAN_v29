"""
core/edge_detector.py — Detección de infraestructura intermedia (CDN/EDGE/WAF)
Diferencia TARGET vs EDGE vs ORIGIN.
"""
from __future__ import annotations
import re

CDN_SIGNATURES = {
    "cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "cname": "cloudflare", "asn": "AS13335", "ips": ["104.", "172.66.", "162.159."]},
    "cloudfront": {"headers": ["x-amz-cf-id", "x-cache"], "cname": "cloudfront", "asn": "AMAZON"},
    "fastly": {"headers": ["x-served-by", "x-cache"], "cname": "fastly"},
    "akamai": {"headers": ["x-akamai"], "cname": "akamai"},
    "sucuri": {"headers": ["x-sucuri-id"], "cname": "sucuri"},
}
WAF_HEADERS = ["cf-ray", "x-sucuri-id", "x-waf", "x-amz-waf"]

def detect_edge(headers: dict, cname: str = "", asn: str = "", ip: str = "") -> dict:
    """
    Retorna {is_edge: bool, provider: str|None, confidence: float, evidence: {}, limitations: str}
    """
    headers_lc = {k.lower(): v for k,v in (headers or {}).items()}
    evidence=[]
    provider=None
    conf=0.0
    # Header detection
    for prov, sig in CDN_SIGNATURES.items():
        for h in sig.get("headers", []):
            if h in headers_lc:
                evidence.append(f"header:{h}={headers_lc[h][:40]}")
                provider=prov
                conf=max(conf, 0.85)
        if cname and sig.get("cname") and sig["cname"] in cname.lower():
            evidence.append(f"cname:{cname}")
            provider=prov
            conf=max(conf, 0.92)
        if asn and sig.get("asn") and sig["asn"].lower() in asn.lower():
            evidence.append(f"asn:{asn}")
            provider=prov
            conf=max(conf, 0.80)
        if ip and any(ip.startswith(p) for p in sig.get("ips", [])):
            evidence.append(f"ip:{ip} in {prov} range")
            provider=prov
            conf=max(conf, 0.78)
    # WAF
    is_waf = any(h in headers_lc for h in WAF_HEADERS)
    if is_waf:
        evidence.append("waf header presente")
        conf=min(1.0, conf+0.05)
    is_edge = provider is not None or conf>=0.75
    limitations=""
    if is_edge and not cname and not asn:
        limitations="Sin CNAME/ASN, solo headers — no se puede confirmar ORIGIN exposure"
    elif not is_edge:
        limitations="No se detectó CDN/WAF, pero ausencia de evidencia ≠ ausencia de EDGE"
    return {"is_edge": is_edge, "provider": provider, "confidence": round(conf,2), "evidence": evidence, "is_waf": is_waf, "limitations": limitations}

def classify_ip_context(ip: str, headers: dict, asn: str) -> str:
    """Retorna TARGET|EDGE|UNKNOWN"""
    det = detect_edge(headers, asn=asn, ip=ip)
    if det["is_edge"]:
        return "EDGE"
    if det["provider"]:
        return "EDGE"
    return "UNKNOWN"  # no inventar
