"""
core/validation.py — ValidationEngine + ConfidenceEngine
"""
from __future__ import annotations
import re, time

# Source reliability priors (0-1)
SOURCE_RELIABILITY = {
    "dns": 0.95, "whois": 0.90, "crtsh": 0.88, "shodan": 0.85, "virustotal": 0.92,
    "http_header": 0.60, "html_pattern": 0.65, "banner_grab": 0.90, "geoip": 0.80,
    "ddg": 0.60, "paste": 0.65,
}

def confidence_engine(source: str, evidence_quality: float, corroboration: int, freshness_days: float = 0) -> float:
    """
    confidence = source_reliability * evidence_quality * corroboration_factor * freshness
    No produce números bonitos arbitrarios — cada factor explicable.
    """
    sr = SOURCE_RELIABILITY.get(source, 0.70)
    corr_factor = min(1.0, 0.7 + corroboration*0.15)  # 0 corrobor=0.7, 1=0.85, 2=1.0
    # Freshness decay: half-life 365d
    import math
    fresh = math.exp(-freshness_days/365) if freshness_days else 1.0
    fresh = max(0.5, fresh) # OSINT envejecido pero no 0
    conf = sr * evidence_quality * corr_factor * fresh
    return round(max(0.1, min(1.0, conf)), 3)

def validate_finding(finding_type: str, value: str, metadata: dict) -> dict:
    """
    Retorna {validation_state, confidence_adjust, limitations, corroboration}
    """
    # Ejemplo: open_port sin banner + high_risk port → bajar confianza
    if finding_type=="open_port":
        has_banner = metadata.get("has_banner", False)
        is_high = metadata.get("port") in {21,23,445,3389,5900,2375,9200,27017}
        if is_high and not has_banner:
            return {"validation_state": "INFERRED", "confidence": 0.5, "limitations": "Puerto crítico sin banner — posible anycast/CDN. Requiere SYN corroboration.", "corroboration": []}
        elif has_banner:
            return {"validation_state": "OBSERVED", "confidence": 0.95, "limitations": "", "corroboration": ["banner"]}
        else:
            return {"validation_state": "OBSERVED", "confidence": 0.75, "limitations": "", "corroboration": []}
    if finding_type.startswith("tech_"):
        # Header-based fingerprint
        hdr = metadata.get("header")
        if hdr in ("cf-ray","x-amz-cf-id"):
            return {"validation_state": "INFERRED", "confidence": 0.75, "limitations": "CDN header no confirma origin stack", "corroboration": []}
        return {"validation_state": "INFERRED", "confidence": 0.85, "limitations": "Firma puede venir de CDN/proxy/template", "corroboration": []}
    if finding_type=="subdomain_ct":
        # Validate FQDN
        if "@" in value or " " in value or "CN=" in value:
            return {"validation_state": "CONTRADICTED", "confidence": 0.2, "limitations": "Valor contiene @/espacio/CN — contaminación de CT log", "corroboration": []}
        return {"validation_state": "OBSERVED", "confidence": 0.95, "limitations": "", "corroboration": []}
    return {"validation_state": "UNVERIFIED", "confidence": 0.7, "limitations": "Sin validación específica", "corroboration": []}
