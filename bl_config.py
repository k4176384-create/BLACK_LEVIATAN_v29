"""
bl_config.py — Configuración Centralizada BLACK LEVIATAN v29
Autor: Luis Sánchez
Modelo: Pydantic v2 con validación estricta
"""
from __future__ import annotations
import os
from pathlib import Path
from typing import Optional, Literal
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).parent.resolve()


# ──────────────────────────────────────────────
# Catppuccin Mocha — Paleta oficial del sistema
# ──────────────────────────────────────────────
class MochaTheme(BaseModel):
    bg:       str = "#1E1E2E"
    surface0: str = "#313244"
    surface1: str = "#45475A"
    overlay:  str = "#6C7086"
    text:     str = "#CDD6F4"
    subtext:  str = "#BAC2DE"
    green:    str = "#A6E3A1"
    red:      str = "#F38BA8"
    yellow:   str = "#F9E2AF"
    blue:     str = "#89B4FA"
    mauve:    str = "#CBA6F7"
    teal:     str = "#94E2D5"
    peach:    str = "#FAB387"
    flamingo: str = "#F2CDCD"
    sky:      str = "#89DCEB"
    sapphire: str = "#74C7EC"
    lavender: str = "#B4BEFE"
    pink:     str = "#F5C2E7"
    maroon:   str = "#EBA0AC"
    rosewater:str = "#F5E0DC"


# ──────────────────────────────────────────────
# API Keys — Todas opcionales, sistema funciona sin ellas
# ──────────────────────────────────────────────
class APIKeys(BaseModel):
    shodan:       Optional[str] = None
    virustotal:   Optional[str] = None
    greynoise:    Optional[str] = None
    hibp:         Optional[str] = None
    dehashed:     Optional[str] = None
    dehashed_user:Optional[str] = None
    github:       Optional[str] = None
    anthropic:    Optional[str] = None
    gemini:       Optional[str] = None

    def available(self) -> list[str]:
        return [k for k, v in self.model_dump().items() if v is not None]


# ──────────────────────────────────────────────
# Configuración del K6 — Evasion Mesh
# ──────────────────────────────────────────────
class EvasionConfig(BaseModel):
    enabled:             bool = True
    tor_enabled:         bool = False
    tor_socks_port:      int  = 9050
    tor_control_port:    int  = 9051
    tor_renew_every:     int  = 50
    proxy_pool:          list[str] = []
    proxy_rotation:      bool = True
    rotate_user_agents:  bool = True
    rate_limit_delay:    float = 1.0
    jitter_factor:       float = 0.3
    max_retries:         int   = 3
    backoff_base:        float = 2.0

    @field_validator("proxy_pool", mode="before")
    @classmethod
    def _parse_proxy_pool(cls, v):
        """Tolera .env vacío, CSV, o JSON array."""
        if v is None or v == "" or v == "[]":
            return []
        if isinstance(v, list):
            return [str(p).strip() for p in v if str(p).strip()]
        if isinstance(v, str):
            s = v.strip()
            if s.startswith("["):
                import json
                try:
                    return [p for p in json.loads(s) if p]
                except Exception:
                    pass
            return [p.strip() for p in s.split(",") if p.strip()]
        return []


# ──────────────────────────────────────────────
# Configuración del K3 — Storage
# ──────────────────────────────────────────────
class StorageConfig(BaseModel):
    sqlite_path:   Path = BASE_DIR / "database" / "leviathan.db"
    duckdb_path:   Path = BASE_DIR / "database" / "analytics.duckdb"
    wal_mode:      bool = True
    sync_interval: int  = 300   # segundos entre volcado SQLite → DuckDB
    max_rows_ram:  int  = 500_000


# ──────────────────────────────────────────────
# Configuración del K4 — Dashboard
# ──────────────────────────────────────────────
class DashboardConfig(BaseModel):
    mode:            Literal["tui", "phantom", "silent"] = "tui"
    ws_host:         str  = "0.0.0.0"
    ws_port:         int  = 8765
    refresh_rate:    float = 0.5   # segundos entre renders del TUI
    creator:         str  = "Luis Sánchez"
    project_name:    str  = "BLACK LEVIATAN"
    version:         str  = "v29"


# ──────────────────────────────────────────────
# Configuración del K5 — Intelligence
# ──────────────────────────────────────────────
class IntelConfig(BaseModel):
    fasttext_model:     Optional[Path] = BASE_DIR / "models" / "bl_classifier.bin"
    use_local_ai:       bool  = True
    llm_provider:       Literal["ollama", "anthropic", "gemini", "none"] = "none"
    ollama_model:       str   = "qwen2.5:3b"
    ollama_url:         str   = "http://localhost:11434"
    scorecard_retune:   bool  = True   # Auto-ajuste de pesos heurísticos
    risk_threshold_low: float = 3.0
    risk_threshold_med: float = 6.0
    risk_threshold_hi:  float = 8.5


# ──────────────────────────────────────────────
# Configuración del Plugin System
# ──────────────────────────────────────────────
class PluginConfig(BaseModel):
    enabled:      bool  = True
    plugin_dirs:  list[Path] = [BASE_DIR / "plugins"]
    auto_discover:bool  = True
    strict_mode:  bool  = False  # True = falla si plugin tiene errores


# ──────────────────────────────────────────────
# Fases del DAG — qué módulos corren en cada fase
# ──────────────────────────────────────────────
class DAGConfig(BaseModel):
    enabled_phases: list[int] = list(range(1, 11))   # 1-10 por default
    parallel_workers: int     = 8
    phase_timeout:    float   = 600.0  # 10 min max por fase
    module_timeout:   float   = 120.0  # 2 min max por módulo
    max_concurrency:  int     = 30     # cap global para módulos individuales
    max_memory_mb:    int     = 1024   # RSS cap para degradar
    max_queue_size:   int     = 5000
    max_cache_entries:int     = 10000


# ──────────────────────────────────────────────
# Configuración de Exportación
# ──────────────────────────────────────────────
class ExportConfig(BaseModel):
    output_dir:  Path = BASE_DIR / "reports"
    formats:     list[Literal["html","json","markdown","pdf","sarif","stix","neo4j","graphml"]] = ["json","markdown","html"]
    neo4j_uri:   Optional[str] = None
    neo4j_user:  Optional[str] = None
    neo4j_pass:  Optional[str] = None


# ──────────────────────────────────────────────
# CONFIGURACIÓN PRINCIPAL — Settings raíz
# ──────────────────────────────────────────────
class BLConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="BL_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # Información del scan
    target:   str   = ""
    deep_mode:bool  = False
    stealth:  bool  = True
    debug:    bool  = False

    # Sub-configuraciones
    api:       APIKeys       = Field(default_factory=APIKeys)
    evasion:   EvasionConfig = Field(default_factory=EvasionConfig)
    storage:   StorageConfig = Field(default_factory=StorageConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    intel:     IntelConfig   = Field(default_factory=IntelConfig)
    plugins:   PluginConfig  = Field(default_factory=PluginConfig)
    dag:       DAGConfig     = Field(default_factory=DAGConfig)
    export:    ExportConfig  = Field(default_factory=ExportConfig)
    theme:     MochaTheme    = Field(default_factory=MochaTheme)

    @field_validator("target")
    @classmethod
    def target_not_empty_if_set(cls, v: str) -> str:
        # Limpieza básica de target
        return v.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")

    @model_validator(mode="after")
    def ensure_dirs_exist(self) -> "BLConfig":
        self.storage.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        self.storage.duckdb_path.parent.mkdir(parents=True, exist_ok=True)
        self.export.output_dir.mkdir(parents=True, exist_ok=True)
        return self


def load_config(**overrides) -> BLConfig:
    """Punto de entrada para cargar configuración desde .env + overrides de CLI."""
    return BLConfig(**overrides)
