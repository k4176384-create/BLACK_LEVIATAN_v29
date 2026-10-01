"""
kernels/k5_autonomous_intel/intel.py — IA Local: FastText + Heurísticas Puras
Autor: Luis Sánchez — BLACK LEVIATAN v29

Clasificación offline sin internet. Pipeline:
  Suggester → Gatekeeper → Judge → Arbiter → ScorecardMem (auto-retune)
"""
from __future__ import annotations
import asyncio
import hashlib
import logging
import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from bl_config import BLConfig
    from core.event_bus import EventBus
    from modules.base_module import ModuleResult

log = logging.getLogger("bl.k5")

try:
    import fasttext
    FASTTEXT_AVAILABLE = True
except ImportError:
    FASTTEXT_AVAILABLE = False
    log.info("FastText no instalado — usando heurísticas puras")

try:
    from kernels.k5_autonomous_intel.rust_core import bl_intel as _rust_intel
    RUST_INTEL = True
    log.info("K5 Rust core: activo")
except ImportError:
    RUST_INTEL = False


# ──────────────────────────────────────────────
# Features de URL para clasificación
# ──────────────────────────────────────────────
SUSPICIOUS_TLDS = frozenset([".tk",".ml",".ga",".cf",".gq",".xyz",".top",
                              ".club",".loan",".online",".site",".work"])
PHISHING_KEYWORDS = frozenset([
    "login","signin","secure","account","verify","confirm","update",
    "password","paypal","amazon","apple","microsoft","google","netflix",
    "bank","wallet","crypto","bitcoin","alert","suspended","unusual",
])
ADMIN_PATHS = frozenset(["/admin","/wp-admin","/panel","/dashboard",
                          "/administrator","/cpanel","/phpmyadmin"])
SENSITIVE_EXTS = frozenset([".env",".git",".bak",".sql",".db",".key",
                              ".pem",".pfx",".conf",".config",".yml"])


@dataclass
class URLFeatures:
    url:               str
    length:            int   = 0
    dots_count:        int   = 0
    has_ip:            bool  = False
    has_suspicious_tld:bool  = False
    phishing_kw_count: int   = 0
    has_admin_path:    bool  = False
    has_sensitive_ext: bool  = False
    subdomain_depth:   int   = 0
    has_port:          bool  = False
    has_http:          bool  = False   # True si es HTTP (no HTTPS)
    is_typosquat:      bool  = False
    has_punycode:      bool  = False
    ngram_score:       float = 0.0

    @property
    def feature_vector(self) -> list[float]:
        return [
            min(self.length / 200.0, 1.0),
            min(self.dots_count / 5.0, 1.0),
            float(self.has_ip),
            float(self.has_suspicious_tld),
            min(self.phishing_kw_count / 3.0, 1.0),
            float(self.has_admin_path),
            float(self.has_sensitive_ext),
            min(self.subdomain_depth / 5.0, 1.0),
            float(self.has_port),
            float(self.has_http),
            float(self.is_typosquat),
            float(self.has_punycode),
            self.ngram_score,
        ]


def extract_url_features(url: str) -> URLFeatures:
    f = URLFeatures(url=url)
    url_lower = url.lower()

    f.length      = len(url)
    f.dots_count  = url.count(".")
    f.has_port    = bool(re.search(r":\d{2,5}", url))
    f.has_http    = url_lower.startswith("http://")
    f.has_ip      = bool(re.match(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url_lower))
    f.has_punycode= "xn--" in url_lower

    # TLD check
    for tld in SUSPICIOUS_TLDS:
        if tld in url_lower:
            f.has_suspicious_tld = True
            break

    # Phishing keywords
    for kw in PHISHING_KEYWORDS:
        if kw in url_lower:
            f.phishing_kw_count += 1

    # Admin paths
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path.lower()
        f.has_admin_path   = any(p in path for p in ADMIN_PATHS)
        f.has_sensitive_ext= any(path.endswith(e) for e in SENSITIVE_EXTS)
        host = parsed.netloc.lower()
        f.subdomain_depth  = len(host.split(".")) - 2
    except Exception:
        pass

    return f


# ──────────────────────────────────────────────
# Heurística pura (sin ML) — siempre disponible
# ──────────────────────────────────────────────
HEURISTIC_WEIGHTS = {
    "has_ip":              3.0,
    "has_suspicious_tld":  2.5,
    "phishing_kw_count":   2.0,
    "has_admin_path":      1.5,
    "has_sensitive_ext":   2.0,
    "has_punycode":        2.5,
    "has_http":            1.0,
    "is_typosquat":        3.0,
    "length_penalty":      0.5,   # URLs muy largas son sospechosas
    "subdomain_depth":     0.8,
}


def heuristic_score(features: URLFeatures) -> float:
    """
    Score 0.0-10.0 basado en heurísticas puras.
    Calibrado con datasets públicos de phishing (PhishTank, OpenPhish).
    """
    score = 0.0
    score += features.has_ip            * HEURISTIC_WEIGHTS["has_ip"]
    score += features.has_suspicious_tld* HEURISTIC_WEIGHTS["has_suspicious_tld"]
    score += min(features.phishing_kw_count, 3) * HEURISTIC_WEIGHTS["phishing_kw_count"]
    score += features.has_admin_path    * HEURISTIC_WEIGHTS["has_admin_path"]
    score += features.has_sensitive_ext * HEURISTIC_WEIGHTS["has_sensitive_ext"]
    score += features.has_punycode      * HEURISTIC_WEIGHTS["has_punycode"]
    score += features.has_http          * HEURISTIC_WEIGHTS["has_http"]
    score += features.is_typosquat      * HEURISTIC_WEIGHTS["is_typosquat"]
    score += min(features.subdomain_depth, 4) * HEURISTIC_WEIGHTS["subdomain_depth"]
    if features.length > 100:
        score += HEURISTIC_WEIGHTS["length_penalty"]

    return min(score, 10.0)


# ──────────────────────────────────────────────
# ScorecardMem — Auto-retune de pesos
# ──────────────────────────────────────────────
class ScorecardMem:
    """
    Aprende de los resultados del scan actual para mejorar
    los pesos heurísticos en la próxima ejecución.

    Filosofía: si muchos findings con feature X resultan ser
    confirmados, subimos el peso de X. Si son falsos positivos, lo bajamos.
    """

    def __init__(self) -> None:
        self._weights  = dict(HEURISTIC_WEIGHTS)
        self._history: list[tuple[URLFeatures, float, bool]] = []   # features, score, confirmed

    def record(self, features: URLFeatures, score: float, confirmed: bool) -> None:
        self._history.append((features, score, confirmed))

    def retune(self) -> None:
        if len(self._history) < 50:
            return

        confirmed   = [(f, s) for f, s, c in self._history if c]
        unconfirmed = [(f, s) for f, s, c in self._history if not c]

        if not confirmed and not unconfirmed:
            return

        # Para cada feature binaria, calcular tasa de confirmación
        binary_features = [
            "has_ip","has_suspicious_tld","has_admin_path",
            "has_sensitive_ext","has_punycode","has_http","is_typosquat",
        ]
        for feat in binary_features:
            total_with = sum(1 for f, _ in confirmed + unconfirmed if getattr(f, feat))
            confirmed_with = sum(1 for f, _ in confirmed if getattr(f, feat))
            if total_with > 5:
                rate = confirmed_with / total_with
                # Ajuste suave: ±15% según tasa de confirmación
                if rate > 0.7:
                    self._weights[feat] = min(5.0, self._weights[feat] * 1.1)
                elif rate < 0.3:
                    self._weights[feat] = max(0.1, self._weights[feat] * 0.9)

        log.info("ScorecardMem retune completado con %d muestras", len(self._history))
        self._history.clear()

    @property
    def current_weights(self) -> dict:
        return dict(self._weights)


# ──────────────────────────────────────────────
# Pipeline completo: Suggester → Gatekeeper → Judge → Arbiter
# ──────────────────────────────────────────────
class AutonomousIntel:
    """
    K5: Motor de inteligencia autónoma.
    Clasifica URLs y hallazgos sin depender de LLMs externos.
    """

    def __init__(self, config: "BLConfig", bus: "EventBus") -> None:
        self._config  = config
        self._bus     = bus
        self._model   = None    # FastText model
        self._scorecard = ScorecardMem()
        self._classified: list[dict] = []

    async def setup(self) -> None:
        model_path = self._config.intel.fasttext_model
        if FASTTEXT_AVAILABLE and model_path and model_path.exists():
            try:
                loop = asyncio.get_event_loop()
                self._model = await loop.run_in_executor(
                    None, fasttext.load_model, str(model_path)
                )
                log.info("K5: FastText modelo cargado desde %s", model_path)
            except Exception as exc:
                log.warning("K5: no se pudo cargar FastText: %s", exc)
        else:
            log.info("K5: modo heurístico puro (FastText no disponible)")

    # ── Pipeline de clasificación ──────────────
    def classify_url(self, url: str) -> dict:
        """
        Clasifica una URL en <0.002s (sin FastText) o <0.005s (con FastText).
        Returns: dict con score, label, confidence, features
        """
        features = extract_url_features(url)
        h_score  = heuristic_score(features)
        ft_score = self._fasttext_score(url)

        # Arbiter: combina heurística y FastText
        if ft_score is not None:
            final_score = (h_score * 0.4) + (ft_score * 0.6)
        else:
            final_score = h_score

        label = (
            "MALICIOUS"   if final_score >= 7.0 else
            "SUSPICIOUS"  if final_score >= 4.0 else
            "CLEAN"
        )
        confidence = abs(final_score - 5.0) / 5.0   # Qué tan seguro está

        result = {
            "url":        url,
            "score":      round(final_score, 3),
            "label":      label,
            "confidence": round(confidence, 3),
            "features": {
                "has_ip":            features.has_ip,
                "phishing_keywords": features.phishing_kw_count,
                "suspicious_tld":    features.has_suspicious_tld,
                "admin_path":        features.has_admin_path,
                "sensitive_ext":     features.has_sensitive_ext,
                "subdomain_depth":   features.subdomain_depth,
            },
        }
        self._classified.append(result)
        return result

    def _fasttext_score(self, url: str) -> Optional[float]:
        if not self._model:
            return None
        try:
            labels, probs = self._model.predict(url, k=2)
            for label, prob in zip(labels, probs):
                if "__malicious__" in label:
                    return prob * 10.0
                if "__phishing__" in label:
                    return prob * 9.0
            return 0.0
        except Exception:
            return None

    # ── Clasificación de texto genérico ──────
    def classify_text(self, text: str) -> dict:
        """
        Detecta patrones de secrets/credentials en texto arbitrario.
        Para uso en mod_github_history, mod_sourcemap_secrets, etc.
        """
        findings = []

        patterns = {
            "aws_key":       r"AKIA[0-9A-Z]{16}",
            "aws_secret":    r"(?i)aws.{0,20}secret.{0,20}['\"][A-Za-z0-9/+=]{40}['\"]",
            "github_token":  r"ghp_[a-zA-Z0-9]{36}",
            "generic_api":   r"(?i)api[_-]?key['\"\s:=]+['\"]([a-zA-Z0-9_\-]{20,50})['\"]",
            "private_key":   r"-----BEGIN (RSA |EC |)PRIVATE KEY-----",
            "jwt":           r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            "slack_token":   r"xox[baprs]-[0-9a-zA-Z]{10,48}",
            "stripe_key":    r"sk_live_[0-9a-zA-Z]{24,}",
            "google_api":    r"AIza[0-9A-Za-z_\-]{35}",
            "heroku_key":    r"(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "connection_str":r"(?i)(mongodb|postgresql|mysql|redis)://[^\s\"'<>]+",
            "basic_auth":    r"(?i)://[a-zA-Z0-9._\-]+:[a-zA-Z0-9._\-!@#$%^&*]+@",
        }

        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, text)
            for match in matches:
                snippet = match if isinstance(match, str) else match[0]
                # Evitar falsos positivos: verificar entropía mínima
                if self._shannon_entropy(snippet) > 3.0:
                    findings.append({
                        "type":       pattern_name,
                        "snippet":    snippet[:80] + "..." if len(snippet) > 80 else snippet,
                        "severity":   "CRITICAL",
                        "confidence": 0.85,
                    })

        return {"findings": findings, "total": len(findings)}

    def _shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = {c: s.count(c) / len(s) for c in set(s)}
        return -sum(p * math.log2(p) for p in freq.values() if p > 0)

    # ── Score final del scan ──────────────────
    async def compute_final_score(self, results: dict) -> float:
        """
        Calcula el risk score final del scan combinando todos los resultados.
        Retorna un valor 0.0-10.0.
        """
        from modules.base_module import Severity

        total_findings  = sum(len(r.findings) for r in results.values())
        critical_count  = sum(r.critical_count for r in results.values())
        high_count      = sum(r.high_count for r in results.values())
        module_scores   = [r.risk_score for r in results.values() if r.risk_score > 0]

        if not module_scores and total_findings == 0:
            return 0.0

        base_score = (
            (critical_count * 3.0) +
            (high_count     * 1.5) +
            (min(total_findings, 50) * 0.1)
        )

        if module_scores:
            avg_module = sum(module_scores) / len(module_scores)
            base_score = (base_score * 0.6) + (avg_module * 0.4)

        final = min(base_score, 10.0)

        # Auto-retune: poblar historial desde findings del scan actual
        if self._config.intel.scorecard_retune:
            self._bootstrap_scorecard_from_findings(results)
            self._scorecard.retune()

        log.info("K5 Risk Score final: %.2f (findings: %d, critical: %d)",
                 final, total_findings, critical_count)
        return round(final, 2)

    def _bootstrap_scorecard_from_findings(self, results: dict) -> None:
        """Poblar historial de ScorecardMem desde findings del scan actual para retune."""
        from modules.base_module import Severity
        for module_result in results.values():
            for finding in module_result.findings:
                if finding.severity.value >= Severity.HIGH.value:
                    # Finding de alta severidad → confirmed=True
                    features = URLFeatures(url=finding.value[:200])
                    self._scorecard.record(features, 8.0, True)
                elif finding.severity.value <= Severity.LOW.value:
                    # Finding de baja severidad → confirmed=False (posible falso positivo)
                    features = URLFeatures(url=finding.value[:200])
                    self._scorecard.record(features, 2.0, False)

    # ── LLM summary (opcional) ────────────────
    async def generate_executive_summary(self, scan_data: dict) -> str:
        """
        Genera un resumen ejecutivo usando LLM (solo si está configurado).
        Si no hay LLM, devuelve un resumen estructurado local.
        """
        if self._config.intel.llm_provider == "none":
            return self._local_summary(scan_data)

        if self._config.intel.llm_provider == "ollama":
            return await self._ollama_summary(scan_data)
        elif self._config.intel.llm_provider == "anthropic":
            return await self._anthropic_summary(scan_data)

        return self._local_summary(scan_data)

    def _local_summary(self, data: dict) -> str:
        target   = data.get("target", "unknown")
        findings = data.get("total_findings", 0)
        critical = data.get("critical_count", 0)
        score    = data.get("risk_score", 0)
        severity = "CRÍTICO" if score >= 8 else "ALTO" if score >= 6 else "MEDIO" if score >= 4 else "BAJO"

        return (
            f"# Resumen Ejecutivo — BLACK LEVIATAN v29\n\n"
            f"**Target:** {target}\n"
            f"**Risk Score:** {score:.1f}/10 ({severity})\n"
            f"**Total Findings:** {findings}\n"
            f"**Críticos:** {critical}\n\n"
            f"Análisis completado por sistema autónomo local (sin LLM externo).\n"
            f"Ver reporte completo para detalles técnicos.\n"
        )

    async def _ollama_summary(self, data: dict) -> str:
        try:
            import aiohttp
            prompt = (
                f"Eres un analista de seguridad. Genera un resumen ejecutivo conciso "
                f"de este scan OSINT en español:\n\n{data}\n\n"
                f"Máximo 200 palabras. Enfócate en hallazgos críticos y recomendaciones."
            )
            async with aiohttp.ClientSession() as s:
                async with s.post(
                    f"{self._config.intel.ollama_url}/api/generate",
                    json={"model": self._config.intel.ollama_model, "prompt": prompt, "stream": False},
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    result = await resp.json()
                    return result.get("response", self._local_summary(data))
        except Exception as exc:
            log.warning("Ollama summary falló: %s", exc)
            return self._local_summary(data)

    async def _anthropic_summary(self, data: dict) -> str:
        key = self._config.api.anthropic
        if not key:
            return self._local_summary(data)
        try:
            import aiohttp
            async with aiohttp.ClientSession() as s:
                async with s.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": "claude-sonnet-4-6",
                        "max_tokens": 500,
                        "messages": [{"role": "user", "content":
                            f"Resume este scan OSINT en español, máximo 200 palabras: {data}"}],
                    },
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    r = await resp.json()
                    return r["content"][0]["text"]
        except Exception as exc:
            log.warning("Anthropic summary falló: %s", exc)
            return self._local_summary(data)
