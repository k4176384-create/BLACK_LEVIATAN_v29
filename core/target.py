"""
core/target.py — Target Sanitization, Normalization & Classification

Clasifica input ambiguo en tipos discretos con confianza.
Implementa regla: preferir UNKNOWN sobre routing incorrecto.

Soporta:
  - domain / subdomain
  - IPv4 / IPv6
  - URL con path/query/fragment/port
  - email
  - username (@handle)
  - phone / wallet / hash (heurístico)
  - Unicode / IDN / punycode / homógrafos / whitespace invisible
"""
from __future__ import annotations
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional
from urllib.parse import urlparse

class TargetType(Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    URL = "url"
    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    WALLET = "wallet"
    HASH = "hash"
    ASN = "asn"
    UNKNOWN = "unknown"

@dataclass
class TargetInfo:
    raw: str
    normalized: str
    type: TargetType
    confidence: float  # 0.0-1.0
    bare_domain: str = ""  # example.com sin www/sub
    host: str = ""  # host canónico
    port: Optional[int] = None
    path: str = ""
    query: str = ""
    fragment: str = ""
    is_punycode: bool = False
    has_port: bool = False
    warnings: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

# ── Regex helpers ──────────────────────────────────────────
RE_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
RE_USERNAME = re.compile(r"^@?[A-Za-z0-9_.\-]{2,39}$")
RE_PHONE = re.compile(r"^\+?[\d\s\-\(\)]{7,20}$")
RE_HASH_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_HASH_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_HASH_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_ASN = re.compile(r"^AS\d{1,10}$", re.I)
RE_WALLET_BTC = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$")
RE_WALLET_ETH = re.compile(r"^0x[a-fA-F0-9]{40}$")
INVISIBLE_RE = re.compile(r"[\u200b\u200c\u200d\ufeff\u00a0]")

DOMAIN_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

def _strip_invisible(s: str) -> tuple[str, bool]:
    """Remueve zero-width y NBSP, reporta si había."""
    cleaned = INVISIBLE_RE.sub("", s)
    # También strip whitespace amplio
    cleaned = cleaned.strip()
    # Normalize Unicode NFKC
    cleaned = unicodedata.normalize("NFKC", cleaned)
    had = cleaned != s
    return cleaned, had

def _idna_decode(host: str) -> tuple[str, bool]:
    """Intentar decodificar punycode -> unicode, detectar homógrafos."""
    is_puny = "xn--" in host.lower()
    try:
        decoded = host.encode("ascii").decode("idna")
        return decoded, is_puny
    except Exception:
        return host, is_puny

def _is_valid_domain(host: str) -> bool:
    if len(host) > 253:
        return False
    # debe tener al menos un punto y TLD 2+ chars
    if "." not in host:
        return False
    labels = host.split(".")
    for lab in labels:
        if not lab or len(lab) > 63:
            return False
        if not DOMAIN_LABEL_RE.match(lab):
            return False
    # TLD no numérico
    tld = labels[-1]
    if tld.isdigit():
        return False
    if len(tld) < 2:
        return False
    return True

def _extract_host_port(raw: str) -> tuple[str, Optional[int], str]:
    """Extrae host:port de URL o bare host."""
    # Si tiene scheme, usar urlparse
    if "://" in raw:
        parsed = urlparse(raw if "://" in raw else "https://" + raw)
        host = parsed.hostname or ""
        port = parsed.port
        return host, port, parsed.path + (f"?{parsed.query}" if parsed.query else "") + (f"#{parsed.fragment}" if parsed.fragment else "")
    # Bare: "example.com:8080/path?q=1"
    # Split port
    host_part = raw.split("/")[0].split("?")[0].split("#")[0]
    if ":" in host_part and not host_part.startswith("["):
        # possible host:port, but ensure port numeric
        maybe_host, maybe_port = host_part.rsplit(":", 1)
        if maybe_port.isdigit() and 1 <= int(maybe_port) <= 65535:
            # Check if maybe_host looks like IP or domain
            return maybe_host, int(maybe_port), raw[len(host_part):]
    return host_part, None, raw[len(host_part):]

def classify_target(raw_input: str) -> TargetInfo:
    """
    Clasifica y normaliza un target OSINT.

    Returns TargetInfo con type y confidence.
    Si confidence <0.6 → UNKNOWN preferido sobre adivinanza.
    """
    raw = raw_input
    cleaned, had_invisible = _strip_invisible(raw_input)
    warnings = []
    if had_invisible:
        warnings.append("Caracteres invisibles/whitespace removidos")
    if not cleaned:
        return TargetInfo(raw=raw, normalized="", type=TargetType.UNKNOWN, confidence=1.0, warnings=["Input vacío tras sanitizar"])

    lower = cleaned.lower()

    # ── 1. Email ──────────────────────────────────────────
    if "@" in cleaned and RE_EMAIL.match(cleaned):
        # Email válido: split domain check
        domain_part = cleaned.split("@", 1)[1]
        if _is_valid_domain(domain_part):
            # punycode check
            _, is_puny = _idna_decode(domain_part)
            info = TargetInfo(
                raw=raw, normalized=lower, type=TargetType.EMAIL, confidence=0.98,
                host=domain_part, bare_domain=domain_part, is_punycode=is_puny, warnings=warnings
            )
            if is_puny:
                warnings.append("Dominio email en punycode (posible homógrafo)")
            info.warnings = warnings
            return info

    # ── 2. URL con scheme ─────────────────────────────────
    if re.match(r"^https?://", lower):
        try:
            parsed = urlparse(cleaned)
            host = parsed.hostname or ""
            port = parsed.port
            # need to idna decode host
            decoded_host, is_puny = _idna_decode(host)
            bare = host.lower().lstrip("www.") if host else ""
            # Validate host
            try:
                ipaddress.ip_address(host)
                # Host es IP -> tipo URL pero host es IP
                return TargetInfo(
                    raw=raw, normalized=cleaned.lower().rstrip("/"), type=TargetType.URL, confidence=0.95,
                    host=host, bare_domain=host, port=port, path=parsed.path, query=parsed.query,
                    fragment=parsed.fragment, has_port=port is not None, is_punycode=is_puny, warnings=warnings
                )
            except ValueError:
                pass
            if host and _is_valid_domain(host):
                return TargetInfo(
                    raw=raw, normalized=cleaned.lower().rstrip("/"), type=TargetType.URL, confidence=0.97,
                    host=host.lower(), bare_domain=host.lower().removeprefix("www."), port=port, path=parsed.path,
                    query=parsed.query, fragment=parsed.fragment, has_port=port is not None, is_punycode=is_puny, warnings=warnings
                )
            else:
                return TargetInfo(raw=raw, normalized=cleaned.lower(), type=TargetType.UNKNOWN, confidence=0.9, warnings=warnings+["URL host inválido"])
        except Exception as e:
            warnings.append(f"URL parse error: {e}")

    # ── 3. IP ─────────────────────────────────────────────
    try:
        ip = ipaddress.ip_address(cleaned)
        if isinstance(ip, ipaddress.IPv4Address):
            return TargetInfo(raw=raw, normalized=str(ip), type=TargetType.IPV4, confidence=0.99, host=str(ip), bare_domain=str(ip), warnings=warnings)
        else:
            return TargetInfo(raw=raw, normalized=str(ip), type=TargetType.IPV6, confidence=0.99, host=str(ip), bare_domain=str(ip), warnings=warnings)
    except ValueError:
        pass

    # ── 4. Bare host:port / host/path handling ────────────
    # Detect if contains "/" "?" "#" ":" — treat as URL-ish
    if any(c in cleaned for c in ["/*", "/"]):  # quick
        # Re-parse as url with dummy scheme
        if "/" in cleaned or "?" in cleaned or "#" in cleaned:
            # Try to interpret as URL without scheme
            try:
                # urlparse needs scheme
                parsed = urlparse("https://" + cleaned)
                host = parsed.hostname or ""
                if host and _is_valid_domain(host):
                    port = parsed.port
                    decoded, is_puny = _idna_decode(host)
                    # If has path/query -> classify as URL, else DOMAIN
                    has_path = bool(parsed.path and parsed.path != "/") or bool(parsed.query) or bool(parsed.fragment)
                    if has_path or port:
                        return TargetInfo(
                            raw=raw, normalized=("https://" + cleaned).lower().rstrip("/"), type=TargetType.URL, confidence=0.85,
                            host=host.lower(), bare_domain=host.lower().removeprefix("www."), port=port, path=parsed.path,
                            query=parsed.query, fragment=parsed.fragment, has_port=port is not None, is_punycode=is_puny, warnings=warnings
                        )
            except Exception:
                pass

    # ── 5. ASN ────────────────────────────────────────────
    if RE_ASN.match(cleaned):
        return TargetInfo(raw=raw, normalized=cleaned.upper(), type=TargetType.ASN, confidence=0.97, host=cleaned.upper(), warnings=warnings)

    # ── 6. Hash ───────────────────────────────────────────
    if RE_HASH_SHA256.match(cleaned) or RE_HASH_SHA1.match(cleaned) or RE_HASH_MD5.match(cleaned):
        return TargetInfo(raw=raw, normalized=lower, type=TargetType.HASH, confidence=0.88, warnings=warnings, metadata={"hash_type": "sha256" if len(cleaned)==64 else "sha1" if len(cleaned)==40 else "md5"})

    # ── 7. Wallet ─────────────────────────────────────────
    if RE_WALLET_ETH.match(cleaned) or RE_WALLET_BTC.match(cleaned):
        return TargetInfo(raw=raw, normalized=cleaned, type=TargetType.WALLET, confidence=0.90, warnings=warnings)

    # ── 8. Phone ──────────────────────────────────────────
    # Only if starts with + and looks like phone (evitar confundir con números)
    if cleaned.startswith("+") and RE_PHONE.match(cleaned) and sum(c.isdigit() for c in cleaned) >= 8:
        return TargetInfo(raw=raw, normalized=cleaned, type=TargetType.PHONE, confidence=0.75, warnings=warnings)

    # ── 9. Username with @ ────────────────────────────────
    if cleaned.startswith("@") and RE_USERNAME.match(cleaned):
        return TargetInfo(raw=raw, normalized=lower, type=TargetType.USERNAME, confidence=0.80, host=lower.lstrip("@"), warnings=warnings)

    # ── 10. Domain / Subdomain ────────────────────────────
    # Pre-clean: strip port if present and trailing slash
    host, port, _rest = _extract_host_port(cleaned)
    host_lower = host.lower()
    # Remove trailing dot
    host_lower = host_lower.rstrip(".")
    # IDNA
    decoded_host, is_puny = _idna_decode(host_lower)
    # Homoglyph warning: if original had non-ascii but decoded differs
    if is_puny:
        warnings.append("Punycode detectado (posible homógrafo IDN)")
    # Check domain validity
    if _is_valid_domain(host_lower):
        # Determine subdomain vs domain: count labels >2 → subdomain
        # Heuristic: if starts with www → subdomain, but bare domain is without first label if 3+ labels
        # Simpler: 2 labels → domain, 3+ → subdomain
        labels = host_lower.split(".")
        # Effective domain: last 2 labels (ignora TLD compuesto como co.uk — aceptable heurístico)
        bare = ".".join(labels[-2:]) if len(labels) >=2 else host_lower
        if len(labels) == 2:
            return TargetInfo(raw=raw, normalized=host_lower, type=TargetType.DOMAIN, confidence=0.95, host=host_lower, bare_domain=bare, port=port, has_port=port is not None, is_punycode=is_puny, warnings=warnings)
        elif len(labels) > 2:
            # www.example.com → still domain-like, but classify as SUBDOMAIN
            # Confidence slightly lower for deep subdomains
            conf = 0.93 if labels[0]=="www" else 0.92
            return TargetInfo(raw=raw, normalized=host_lower, type=TargetType.SUBDOMAIN, confidence=conf, host=host_lower, bare_domain=bare, port=port, has_port=port is not None, is_punycode=is_puny, warnings=warnings)
        else:
            return TargetInfo(raw=raw, normalized=host_lower, type=TargetType.UNKNOWN, confidence=0.6, warnings=warnings)

    # ── 11. Bare username (sin @) — solo si no parece dominio ──
    if RE_USERNAME.match(cleaned) and "." not in cleaned and len(cleaned) >=3:
        # Evitar colisión con palabras comunes; confidence baja
        return TargetInfo(raw=raw, normalized=lower, type=TargetType.USERNAME, confidence=0.55, warnings=warnings+["Username sin @, baja confianza"])

    # ── 12. Unknown ───────────────────────────────────────
    return TargetInfo(raw=raw, normalized=lower, type=TargetType.UNKNOWN, confidence=0.85, warnings=warnings+["No se pudo clasificar con suficiente confianza"])

def sanitize_for_modules(info: TargetInfo) -> str:
    """
    Retorna el string que los módulos deben usar.
    Para URL → host, para EMAIL → domain part, para DOMAIN/SUBDOMAIN → normalized host.
    """
    if info.type in (TargetType.DOMAIN, TargetType.SUBDOMAIN):
        return info.host
    if info.type == TargetType.URL:
        return info.host
    if info.type == TargetType.EMAIL:
        return info.host  # domain part
    if info.type in (TargetType.IPV4, TargetType.IPV6):
        return info.host
    return info.normalized

# ── Module routing helper ────────────────────────────────
RELEVANT_PHASES: dict[TargetType, set[int]] = {
    TargetType.DOMAIN:    {1,2,3,4,5,6,7,8,9,10},
    TargetType.SUBDOMAIN: {1,2,3,4,7,8,9,10},
    TargetType.IPV4:      {1,2,4,7,8,10},
    TargetType.IPV6:      {1,2,4,7,8,10},
    TargetType.URL:       {1,3,7,10},
    TargetType.EMAIL:     {4,5,6},
    TargetType.USERNAME:  {3,6},
    TargetType.PHONE:     {5,6},
    TargetType.HASH:      {4,8},
    TargetType.WALLET:    {4,8},
    TargetType.ASN:       {1,2,4},
    TargetType.UNKNOWN:   {1},  # solo recon básico, no enumerar indiscriminadamente
}

def phases_for_target(t: TargetType) -> set[int]:
    return RELEVANT_PHASES.get(t, {1})
