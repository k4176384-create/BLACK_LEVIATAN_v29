"""
modules/base_module.py — Contrato base para todos los módulos y plugins
Autor: Luis Sánchez — BLACK LEVIATAN v29

PARA DESARROLLADORES DE PLUGINS:
  Hereda de BaseModule, define NAME/PHASE/DESCRIPTION,
  implementa `async def run(target, context) -> ModuleResult`.
  El loader lo descubre automáticamente. Ver PLUGIN_GUIDE.md.
"""
from __future__ import annotations
import time
import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum, Enum
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.event_bus import EventBus
    from kernels.k3_immortal_storage.storage import ImmortalStorage
    from bl_config import BLConfig
    from core.target import TargetType


# ──────────────────────────────────────────────
# Fases del DAG (1-10)
# ──────────────────────────────────────────────
class Phase(IntEnum):
    RECON         = 1
    DISCOVERY     = 2
    ENUM          = 3
    CORRELATE     = 4
    BREACH        = 5
    SOCIAL        = 6
    AI_FUTURE     = 7
    DEEP_OSINT    = 8
    HISTORICAL    = 9
    CLOUD_INFRA   = 10
    CUSTOM        = 99   # Para plugins con fase personalizada


# ──────────────────────────────────────────────
# Severity de un hallazgo
# ──────────────────────────────────────────────
class Severity(IntEnum):
    INFO     = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @property
    def mocha_color(self) -> str:
        return {
            self.INFO:     "#89B4FA",   # blue
            self.LOW:      "#94E2D5",   # teal
            self.MEDIUM:   "#F9E2AF",   # yellow
            self.HIGH:     "#FAB387",   # peach
            self.CRITICAL: "#F38BA8",   # red
        }[self]


# ──────────────────────────────────────────────
# Validation state
# ──────────────────────────────────────────────
class ValidationState(str, Enum):
    OBSERVED     = "OBSERVED"      # Directamente observado (DNS A record, HTTP 200)
    INFERRED     = "INFERRED"      # Inferido con evidencia parcial (tech fingerprint via header)
    CORRELATED   = "CORRELATED"    # Corroborado por 2+ fuentes
    LIKELY       = "LIKELY"        # Alta probabilidad pero no confirmado
    CONFIRMED    = "CONFIRMED"     # Confirmado con múltiples evidencias + validación activa
    UNVERIFIED   = "UNVERIFIED"    # Sin validación (default para hallazgos de API externa)
    CONTRADICTED = "CONTRADICTED"  # Contradicho por otra fuente
    STALE        = "STALE"         # Dato obsoleto (TTL expirado)

class Provenance:
    """Origen reproducible de un hallazgo."""
    def __init__(self, source: str, source_type: str = "module", method: str = "", request: dict | None = None, response: dict | None = None, retrieved_at: float | None = None):
        self.source = source
        self.source_type = source_type
        self.method = method
        self.request = request or {}
        self.response = response or {}
        self.retrieved_at = retrieved_at or time.time()
    def to_dict(self) -> dict:
        return {"source": self.source, "source_type": self.source_type, "method": self.method, "request": self.request, "response": self.response, "retrieved_at": self.retrieved_at}

# ──────────────────────────────────────────────
# Hallazgo individual
# ──────────────────────────────────────────────
@dataclass
class Finding:
    type:        str                         # e.g. "open_port", "exposed_key", "subdomain"
    value:       str                         # El dato hallado
    severity:    Severity = Severity.INFO
    confidence:  float    = 1.0              # 0.0 – 1.0
    source:      str      = ""               # módulo que lo encontró
    metadata:    dict     = field(default_factory=dict)
    timestamp:   float    = field(default_factory=time.time)
    tags:        list[str] = field(default_factory=list)
    # ── Nuevos campos evidence-driven ──────────────────
    validation_state: ValidationState = ValidationState.UNVERIFIED
    evidence:    dict     = field(default_factory=dict)  # {request, response, snippet, headers}
    provenance:  dict     = field(default_factory=dict)  # {source, source_type, method, retrieved_at}
    limitations: str      = ""
    corroboration: list[str] = field(default_factory=list)
    observed_at: float    = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "type":       self.type,
            "value":      self.value,
            "severity":   self.severity.label,
            "confidence": self.confidence,
            "source":     self.source,
            "metadata":   self.metadata,
            "timestamp":  self.timestamp,
            "tags":       self.tags,
            "validation_state": self.validation_state.value if isinstance(self.validation_state, ValidationState) else str(self.validation_state),
            "evidence":   self.evidence,
            "provenance": self.provenance,
            "limitations":self.limitations,
            "corroboration": self.corroboration,
            "observed_at": self.observed_at,
        }


# ──────────────────────────────────────────────
# Resultado de un módulo
# ──────────────────────────────────────────────
@dataclass
class ModuleResult:
    module_name:    str
    phase:          Phase
    target:         str
    findings:       list[Finding] = field(default_factory=list)
    metadata:       dict          = field(default_factory=dict)
    risk_score:     float         = 0.0     # 0.0 – 10.0
    execution_time: float         = 0.0     # segundos
    errors:         list[str]     = field(default_factory=list)
    skipped:        bool          = False
    skip_reason:    str           = ""

    def add_finding(self, **kwargs) -> Finding:
        f = Finding(source=self.module_name, **kwargs)
        self.findings.append(f)
        return f

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def to_dict(self) -> dict:
        return {
            "module":         self.module_name,
            "phase":          int(self.phase),
            "phase_name":     self.phase.name,
            "target":         self.target,
            "findings":       [f.to_dict() for f in self.findings],
            "metadata":       self.metadata,
            "risk_score":     self.risk_score,
            "execution_time": self.execution_time,
            "errors":         self.errors,
            "skipped":        self.skipped,
            "skip_reason":    self.skip_reason,
        }


# ──────────────────────────────────────────────
# CLASE BASE — Hereda de aquí para crear módulos y plugins
# ──────────────────────────────────────────────
class BaseModule(ABC):
    """
    Contrato que deben cumplir todos los módulos y plugins de BLACK LEVIATAN.

    Atributos de clase que DEBES definir en tu subclase:
      NAME        : str  — Identificador único, e.g. "whois_lookup"
      PHASE       : Phase — Fase del DAG donde se ejecuta
      DESCRIPTION : str  — Qué hace el módulo (aparece en el dashboard)
      REQUIRES_API_KEY : bool — Si necesita API key para funcionar
      REQUIRES_TOR     : bool — Si necesita Tor activo
      DEPENDENCIES     : list[str] — NAMEs de módulos que deben correr antes

    Método que DEBES implementar:
      async def run(self, target: str, context: dict) -> ModuleResult
    """

    NAME:             str       = "unnamed"
    PHASE:            Phase     = Phase.RECON
    DESCRIPTION:      str       = ""
    REQUIRES_API_KEY: bool      = False
    REQUIRES_TOR:     bool      = False
    DEPENDENCIES:     list[str] = []
    VERSION:          str       = "1.0.0"
    AUTHOR:           str       = "Luis Sánchez"
    TAGS:             list[str] = []
    INPUT_TYPES:      set       = set()  # TargetType set; vacío = todos
    # Declarativo de capacidades (para scheduler inteligente)
    NETWORK_REQUIRED: bool = True
    RATE_LIMIT_SCOPE: str = "domain"  # global|provider|domain|module

    def __init__(
        self,
        config:   "BLConfig",
        bus:      "EventBus",
        storage:  "ImmortalStorage",
    ) -> None:
        self.config  = config
        self.bus     = bus
        self.storage = storage
        self._enabled = True
        self._result: Optional[ModuleResult] = None

    # ── Ciclo de vida ──────────────────────────
    async def setup(self) -> None:
        """Hook opcional: inicialización antes del run. Sobreescribe si necesitas."""
        pass

    @abstractmethod
    async def run(self, target: str, context: dict) -> ModuleResult:
        """
        Lógica principal del módulo.

        Args:
            target:  Dominio/IP/email objetivo, ya normalizado.
            context: Diccionario compartido entre módulos de la misma fase
                     y fases anteriores. Contiene los resultados acumulados.

        Returns:
            ModuleResult con todos los findings y metadata.
        """
        ...

    async def teardown(self) -> None:
        """Hook opcional: limpieza después del run. Sobreescribe si necesitas."""
        pass

    # ── Helpers para emitir eventos ────────────
    async def emit(self, event_type: str, data: Any) -> None:
        await self.bus.publish(
            f"module.{self.NAME}.{event_type}",
            {"module": self.NAME, "phase": int(self.PHASE), "data": data},
        )

    async def emit_finding(self, finding: Finding) -> None:
        await self.bus.publish(
            "finding.new",
            {"module": self.NAME, "finding": finding.to_dict()},
        )

    # ── Utilidades comunes ─────────────────────
    def make_result(self, target: str) -> ModuleResult:
        """Crea un ModuleResult vacío listo para llenar."""
        return ModuleResult(
            module_name=self.NAME,
            phase=self.PHASE,
            target=target,
        )

    def skip(self, target: str, reason: str) -> ModuleResult:
        """Devuelve un resultado marcado como skipped."""
        r = self.make_result(target)
        r.skipped    = True
        r.skip_reason = reason
        return r

    def needs_api_key(self, key_name: str) -> bool:
        """Verifica si una API key está configurada."""
        return getattr(self.config.api, key_name, None) is not None

    # ── Entrada/salida del contexto ────────────
    def get_from_context(self, context: dict, key: str, default: Any = None) -> Any:
        """Lee datos del contexto acumulado de fases anteriores."""
        return context.get(key, default)

    def push_to_context(self, context: dict, key: str, value: Any) -> None:
        """Escribe en el contexto compartido para fases siguientes."""
        context[key] = value

    # ── Estado del módulo ──────────────────────
    def enable(self)  -> None: self._enabled = True
    def disable(self) -> None: self._enabled = False

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def __repr__(self) -> str:
        return f"<Module {self.NAME} phase={self.PHASE.name} enabled={self._enabled}>"
