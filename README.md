# 🦑 BLACK LEVIATAN v29

> **OSINT Intelligence Platform** — Plataforma modular de inteligencia de fuentes abiertas  
> Creado por **Luis Sánchez** | Stack: Python 3.11+ / Rust (PyO3 0.22) / SQLite WAL / DuckDB  
> Arquitectura: MicroKernel + DAG de 10 fases + Plugin System + Catppuccin Mocha TUI

---

> ⚠️ **AVISO LEGAL**  
> Esta herramienta es para **investigación de seguridad autorizada** únicamente.  
> Úsala exclusivamente en sistemas propios o con permiso explícito por escrito.  
> El uso contra sistemas sin autorización puede ser ilegal en tu jurisdicción.

---

## Índice

1. [Características](#características)
2. [Arquitectura](#arquitectura)
3. [Instalación](#instalación)
4. [Configuración (API Keys)](#configuración)
5. [Uso](#uso)
6. [Los 10 módulos / Fases del DAG](#fases-dag)
7. [Kernels (K1-K6)](#kernels)
8. [Sistema de Plugins](#sistema-de-plugins)
9. [Exportar Reportes](#exportar-reportes)
10. [Agregar Módulos Propios (sin romper la arquitectura)](#agregar-módulos)
11. [Créditos](#créditos)

---

## Características

| Feature | Detalle |
|---------|---------|
| **33 módulos OSINT** | 10 fases: recon → deep intel → cloud infra |
| **6 Kernels especializados** | Crawler, Correlator, Storage, TUI, Intel, Evasion |
| **Plugin system** | Hot-reload, auto-discovery, manifest YAML |
| **DAG paralelo** | Fases con dependencias, módulos en paralelo dentro de cada fase |
| **5 formatos de reporte** | JSON, Markdown, HTML, SARIF, STIX 2.1 |
| **Rust cores** | K1 (bl_crawler) + K5 (bl_intel) via PyO3 0.22 |
| **Dashboard TUI** | Rich + WebSocket, Catppuccin Mocha |
| **Knowledge Graph** | NetworkX + correlaciones temporales (K2) |
| **Dual storage** | SQLite WAL (OLTP) + DuckDB (OLAP analytics) |
| **K6 Evasion** | Proxy pool + Tor + UA rotation (activado por Vigilante automáticamente) |

---

## Arquitectura

```
BLACK LEVIATAN v29
│
├── black_leviathan.py          ← Entry point CLI
├── bl_config.py                ← Pydantic v2 config (env vars)
│
├── core/
│   ├── event_bus.py            ← PriorityQueue + wildcards + ring buffer
│   ├── state_manager.py        ← Redux-like state + 25 Actions
│   ├── vigilante_v2.py         ← FSM + Circuit Breakers + WAF detection
│   └── orchestrator.py         ← DAG scheduler 10 fases
│
├── kernels/
│   ├── k1_stealth_crawler/     ← aiohttp + Playwright + Rust TokenBucket
│   ├── k2_deep_correlator/     ← NetworkX KnowledgeGraph + UnionFind
│   ├── k3_immortal_storage/    ← SQLite WAL + DuckDB dual engine
│   ├── k4_phantom_dashboard/   ← Rich TUI + WebSocket (Luis Sánchez branding)
│   ├── k5_autonomous_intel/    ← FastText + Rust shannon_entropy/ngram
│   └── k6_evasion_mesh/        ← ProxyPool + TorCircuits + AdaptiveBackoff
│
├── modules/                    ← Los 33 módulos OSINT
│   ├── base_module.py          ← BaseModule ABC, Finding, ModuleResult
│   ├── f01_recon/              ← whois, dns, geo, robots
│   ├── f02_discovery/          ← shodan, crtsh, subdomain_brute, port_scan
│   ├── f03_enum/               ← emails, sherlock, tech_fingerprint
│   ├── f04_correlate/          ← virustotal, ip_reputation, greynoise
│   ├── f05_breach/             ← hibp, holehe, paste_monitor, dehashed
│   ├── f06_social/             ← github, reddit, linkedin_osint
│   ├── f07_ai_future/          ← threat_predictor, behavioral, quantum_resistant
│   ├── f08_deep_osint/         ← zero_day_hunter, ransomware_leaks, darkweb_search
│   ├── f09_historical/         ← wayback_deep, cert_stream, github_history
│   └── f10_cloud_infra/        ← cloud_bucket_hunt, sourcemap_secrets, tech_fp_deep
│
├── plugins/                    ← Plugin system (hot-reload)
│   ├── loader.py
│   ├── hooks.py
│   ├── example_plugin/         ← Módulo de ejemplo funcional
│   └── template_plugin/        ← Plantilla en blanco para tus módulos
│
└── export/                     ← Exporters: json/md/html/sarif/stix
```

### DAG de Dependencias

```
Fase 1 (RECON)      → no deps
Fase 2 (DISCOVERY)  → requiere 1
Fase 3 (ENUM)       → requiere 1, 2
Fase 4 (CORRELATE)  → requiere 1, 2, 3
Fase 5 (BREACH)     → requiere 3
Fase 6 (SOCIAL)     → requiere 1, 2
Fase 7 (AI/FUTURE)  → requiere 4, 5
Fase 8 (DEEP OSINT) → requiere 4, 6
Fase 9 (HISTORICAL) → requiere 1, 2
Fase 10 (CLOUD)     → requiere 1, 2, 3
```

---

## Instalación

### Rápida (recomendada)

```bash
git clone https://github.com/luissanchez/black-leviatan-v29
cd black-leviatan-v29
chmod +x install.sh
./install.sh
```

### Manual paso a paso

```bash
# 1. Python 3.11+ requerido
python3 --version   # debe ser 3.11+

# 2. Entorno virtual
python3 -m venv .venv
source .venv/bin/activate       # bash/zsh
# fish:  source .venv/bin/activate.fish

# 3. Dependencias Python
pip install -r requirements.txt

# 4. Playwright (para K1 Playwright fallback)
python -m playwright install chromium

# 5. Kernels Rust (requiere cargo/rustup)
# K1 — bl_crawler
cd kernels/k1_stealth_crawler/rust_core
.venv/bin/maturin develop --release
cd ../../..

# K5 — bl_intel
cd kernels/k5_autonomous_intel/rust_core
.venv/bin/maturin develop --release
cd ../../..

# 6. Configurar API keys
cp .env.example .env
micro .env    # configura las keys que tienes
```

### Sin Rust (modo compatibilidad)

```bash
./install.sh --no-rust
# K1 usa fallback aiohttp (sin TokenBucketRs)
# K5 usa fallback Python (sin shannon_entropy Rust)
```

---

## Configuración

Edita `.env` con las API keys que tengas. **Todas son opcionales** — el módulo correspondiente
muestra `[SKIP]` si no hay key, sin romper el scan.

```bash
# APIs de Threat Intelligence
BL_API__VIRUSTOTAL=tu_key_aqui        # virustotal.com (gratis tier: 500 req/día)
BL_API__SHODAN=tu_key_aqui            # shodan.io (member: ~$49/mes)
BL_API__GREYNOISE=tu_key_aqui         # greynoise.io (community: gratis)
BL_API__HIBP=tu_key_aqui              # haveibeenpwned.com/API ($3.50/mes)
BL_API__DEHASHED=tu_key_aqui          # dehashed.com (~$5/mes)
BL_API__DEHASHED_USER=tu@email.com
BL_API__GITHUB=ghp_tu_token           # github.com > Settings > Tokens (gratis)

# Evasión (sólo si tienes proxies/Tor configurado)
BL_EVASION__TOR_ENABLED=false
BL_EVASION__PROXY_POOL=socks5://127.0.0.1:9050
```

---

## Uso

```bash
# Activar entorno
source .venv/bin/activate   # o: .venv/bin/python black_leviathan.py [...]

# Scan básico
python black_leviathan.py -t example.com

# Scan rápido (sólo fases 1-3, ~2 min)
python black_leviathan.py -t example.com --mode fast

# Scan profundo (todas las fases, ~25 min)
python black_leviathan.py -t example.com --mode deep

# Fases específicas
python black_leviathan.py -t example.com --phases 1,2,5,8

# Omitir fases lentas
python black_leviathan.py -t example.com --skip-phases 8,9,10

# Módulos específicos
python black_leviathan.py -t example.com --modules whois_lookup,port_scan,hibp

# Con dashboard TUI en tiempo real
python black_leviathan.py -t example.com --tui

# Múltiples targets desde archivo
python black_leviathan.py -f targets.txt --mode fast

# Reporte en Markdown
python black_leviathan.py -t example.com --output markdown

# Reporte SARIF (para GitHub Actions)
python black_leviathan.py -t example.com --output sarif

# Listar módulos disponibles
python black_leviathan.py --list-modules

# Listar plugins instalados
python black_leviathan.py --list-plugins

# Verificar configuración
python black_leviathan.py --validate-config
```

### Modos de ejecución

| Modo | Fases | Tiempo aprox. | Descripción |
|------|-------|---------------|-------------|
| `fast` | 1-3 | ~2 min | Recon básico: WHOIS, DNS, tech |
| `normal` | 1-7 | ~10 min | Análisis completo (default) |
| `deep` | 1-10 | ~25 min | Todo: historical, cloud, deep intel |
| `stealth` | 1-7 + K6 | ~15 min | Normal + evasión activa desde el inicio |

---

## Fases DAG

### Fase 1 — RECON

| Módulo | Fuente | API Key |
|--------|--------|---------|
| `whois_lookup` | Registradores públicos | No |
| `dns_enum` | DNS público (1.1.1.1, 8.8.8.8) | No |
| `geolocation` | ip-api.com (free) | No |
| `robots_sitemap` | HTTP público | No |

### Fase 2 — DISCOVERY

| Módulo | Fuente | API Key |
|--------|--------|---------|
| `shodan_idb` | internetdb.shodan.io (free) + API | Opcional |
| `crtsh_stream` | crt.sh (Certificate Transparency) | No |
| `sub_permutation` | DNS brute force (70 prefijos) | No |
| `port_scan` | TCP async scan (35 puertos críticos) | No |

### Fase 3 — ENUMERATION

| Módulo | Fuente | API Key |
|--------|--------|---------|
| `email_harvest` | Páginas web públicas del dominio | No |
| `sherlock_deep` | 20+ plataformas (perfiles públicos) | No |
| `tech_fingerprint` | HTTP headers, cookies, HTML | No |

### Fase 4 — CORRELATE

| Módulo | Fuente | API Key |
|--------|--------|---------|
| `virustotal` | virustotal.com API | Sí |
| `ip_reputation` | ipinfo.io (free) + AbuseIPDB | Opcional |
| `greynoise` | greynoise.io API | Sí |

### Fase 5 — BREACH

| Módulo | Fuente | API Key |
|--------|--------|---------|
| `hibp` | haveibeenpwned.com API | Sí |
| `holehe` | Password reset endpoints públicos | No |
| `paste_monitor` | psbdmp.ws + DuckDuckGo | No |
| `dehashed_local` | dehashed.com API | Sí |

### Fase 6 — SOCIAL

| Módulo | Fuente | API Key |
|--------|--------|---------|
| `github` | GitHub API (public repos) | Opcional |
| `reddit` | Reddit API (public posts) | No |
| `linkedin_osint` | Google/DDG dork (datos indexados) | No |

### Fase 7 — AI/FUTURE

| Módulo | Descripción | API Key |
|--------|-------------|---------|
| `threat_predictor` | Risk scoring compuesto de hallazgos | No |
| `behavioral` | Anomalías de infraestructura (geo mismatch, fast-flux) | No |
| `quantum_resistant` | TLS version, ciphers débiles, key size | No |

### Fase 8 — DEEP OSINT

| Módulo | Fuente | API Key |
|--------|--------|---------|
| `zero_day_hunter` | NVD/NIST CVE database (free) | No |
| `ransomware_leaks` | ransomware.live API + OTX | No |
| `darkweb_search` | OTX AlienVault + URLScan + ThreatFox | No |

### Fase 9 — HISTORICAL

| Módulo | Fuente | API Key |
|--------|--------|---------|
| `wayback_deep` | web.archive.org CDX API | No |
| `cert_stream` | crt.sh historial completo | No |
| `github_history` | GitHub commits + diff analysis | Opcional |

### Fase 10 — CLOUD INFRA

| Módulo | Fuente | API Key |
|--------|--------|---------|
| `cloud_bucket_hunt` | S3/Azure/GCS public endpoints | No |
| `sourcemap_secrets` | JavaScript source maps | No |
| `tech_fingerprint_deep` | Security headers, CORS, CSP, cookies | No |

---

## Kernels

### K1 — Stealth Crawler
Motor de HTTP con rate limiting Rust (TokenBucketRs). Playwright como fallback para JS-heavy.
```python
from kernels.k1_stealth_crawler.crawler import StealthCrawler
```

### K2 — Deep Correlator
Knowledge Graph con NetworkX. Correlaciones temporales y Union-Find para clustering.
```python
from kernels.k2_deep_correlator.correlator import DeepCorrelator
```

### K3 — Immortal Storage
SQLite WAL para datos transaccionales + DuckDB para analytics OLAP.
```python
from kernels.k3_immortal_storage.storage import ImmortalStorage
```

### K4 — Phantom Dashboard
TUI con Rich + WebSocket para streaming en tiempo real. Branding Luis Sánchez, tema Catppuccin Mocha.
```bash
python black_leviathan.py -t example.com --tui
```

### K5 — Autonomous Intel
Clasificador FastText + heurísticas Python + `shannon_entropy`/`ngram_score` en Rust.

### K6 — Evasion Mesh
Activado automáticamente por el Vigilante cuando detecta bloqueo WAF:
- ProxyPool con selección inteligente por success_rate
- TorCircuitManager via `stem`
- User-Agent rotation (8 UAs reales)
- AdaptiveBackoff exponencial con jitter

---

## Sistema de Plugins

### Auto-discovery

BLACK LEVIATAN detecta automáticamente cualquier módulo en `plugins/` que:
1. Tenga un `manifest.yaml` válido
2. Tenga una clase que hereda de `BaseModule`
3. Tenga `NAME != "unnamed"`

No necesitas registrar nada manualmente.

### Hot-reload

```python
# En tiempo de ejecución:
from plugins.loader import PluginLoader
loader = PluginLoader(...)
await loader.reload_plugin("mi_modulo")
```

### Estructura de un plugin

```
plugins/
└── mi_modulo/
    ├── manifest.yaml
    ├── __init__.py       (puede estar vacío)
    └── plugin.py
```

**manifest.yaml:**
```yaml
name: mi_modulo
version: "1.0.0"
author: "Luis Sánchez"
description: "Qué hace mi módulo"
enabled: true
phase: 1          # Fase del DAG: 1-10
tags:
  - custom
```

**plugin.py:**
```python
from modules.base_module import BaseModule, Phase, ModuleResult, Severity
import time

class MiModulo(BaseModule):
    NAME        = "mi_modulo"
    PHASE       = Phase.RECON
    DESCRIPTION = "Mi módulo personalizado"

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            # Tu lógica aquí
            result.add_finding(
                type="mi_hallazgo",
                value="algo interesante",
                severity=Severity.INFO,
                confidence=0.9,
            )
            result.risk_score = 1.0
        except Exception as exc:
            result.add_error(str(exc))
        result.execution_time = time.time() - t0
        return result
```

---

## Exportar Reportes

```bash
# JSON (default, completo)
python black_leviathan.py -t example.com --output json

# Markdown (legible, para notas)
python black_leviathan.py -t example.com --output markdown

# HTML (Catppuccin Mocha, para browser)
python black_leviathan.py -t example.com --output html

# SARIF 2.1.0 (GitHub Actions, IDEs)
python black_leviathan.py -t example.com --output sarif

# STIX 2.1 (threat intel platforms, MISP, OpenCTI)
python black_leviathan.py -t example.com --output stix

# Directorio de salida personalizado
python black_leviathan.py -t example.com --output html --output-dir /tmp/bl_reports
```

Los reportes se guardan en `reports/` con nombre `bl_{target}_{timestamp}.{ext}`.

---

## Agregar Módulos

Ver `PLUGIN_GUIDE.md` para la guía completa paso a paso.

**Resumen de 5 pasos:**

```bash
# 1. Copiar template
cp -r plugins/template_plugin plugins/mi_nuevo_modulo

# 2. Editar manifest
micro plugins/mi_nuevo_modulo/manifest.yaml

# 3. Implementar run()
micro plugins/mi_nuevo_modulo/plugin.py

# 4. Verificar que auto-discovery lo detecta
python black_leviathan.py --list-plugins

# 5. ¡Listo! Aparece en el siguiente scan
python black_leviathan.py -t example.com
```

**Reglas críticas para no romper la arquitectura:**

1. **Nunca lances excepciones sin atrapar** — usa `result.add_error(str(exc))`
2. **Siempre registra `result.execution_time`** al final del `run()`
3. **Usa `self.get_from_context()`** para leer datos de fases previas (no accedas directamente)
4. **Usa `self.push_to_context()`** para escribir datos que otros módulos necesiten
5. **Usa `return self.skip(target, "razón")`** para skip limpio (no `return result` con `result.findings = []`)
6. **Respeta el DAG**: si tu módulo necesita datos de DNS, pon `PHASE = Phase.ENUM` o posterior
7. **No importes de `black_leviathan.py`** (circular import)
8. **`NAME` debe ser único** entre todos los módulos y plugins

---

## Créditos

**BLACK LEVIATAN v29** fue diseñado y construido por **Luis Sánchez** (@wero).

- Arquitectura: MicroKernel + EventBus + DAG
- Stack: Python 3.11 / Rust PyO3 0.22 / SQLite WAL / DuckDB / Rich / NetworkX
- Target hardware: Parrot Security OS aarch64 / Kali NetHunter
- Tema visual: Catppuccin Mocha en todo el proyecto

---

*Para agregar módulos, reportar bugs o extender el sistema: ver `PLUGIN_GUIDE.md`*
