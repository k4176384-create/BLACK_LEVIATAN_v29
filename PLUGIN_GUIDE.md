# 🦑 BLACK LEVIATAN v29 — Plugin Guide

> Guía completa para agregar módulos **sin romper la arquitectura**.  
> Autor: Luis Sánchez

---

## Índice

1. [Cómo funciona el plugin system](#cómo-funciona)
2. [Ciclo de vida de un módulo](#ciclo-de-vida)
3. [Tutorial paso a paso](#tutorial)
4. [API completa de BaseModule](#api-basemodule)
5. [Contexto compartido entre módulos](#contexto-compartido)
6. [Severidades y tipos de finding](#severidades)
7. [Errores comunes (y cómo evitarlos)](#errores-comunes)
8. [Ejemplo completo real](#ejemplo-completo)

---

## Cómo funciona

BLACK LEVIATAN usa **auto-discovery** al iniciar:

```
1. PluginLoader.discover() escanea plugins/*/
2. Por cada directorio, lee manifest.yaml
3. Si enabled: true, importa la clase indicada en entry_point
4. La clase se registra en el Orchestrator para su fase
5. Al hacer un scan, el Orchestrator ejecuta los módulos de cada fase en paralelo
```

No necesitas registrar nada. Si el archivo existe y hereda de `BaseModule`, **se detecta solo**.

---

## Ciclo de vida de un módulo

```
Orchestrator
    │
    ├── 1. module.setup()            ← inicialización (opcional)
    │
    ├── 2. module.run(target, ctx)   ← lógica principal (OBLIGATORIA)
    │       │
    │       ├── Lee context (datos de fases anteriores)
    │       ├── Hace HTTP/DNS/API calls
    │       ├── Emite findings via result.add_finding()
    │       └── Escribe al context para fases siguientes
    │
    ├── 3. module.teardown()         ← limpieza (opcional)
    │
    └── 4. result → Orchestrator → EventBus → Dashboard/Storage
```

---

## Tutorial

### Paso 1 — Copiar la plantilla

```bash
cp -r plugins/template_plugin plugins/mi_scanner_dns
```

### Paso 2 — Editar manifest.yaml

```yaml
# plugins/mi_scanner_dns/manifest.yaml
name: mi_scanner_dns           # Identificador único. Sin espacios. Minúsculas + guiones bajos.
version: "1.0.0"
author: "Luis Sánchez"
description: "Scanner DNS personalizado con lógica propia"
enabled: true
phase: 2                       # Fase del DAG: 1-10
                               # 1=Recon, 2=Discovery, 3=Enum, 4=Correlate...
tags:
  - dns
  - custom
  - network
```

### Paso 3 — Editar plugin.py

```python
# plugins/mi_scanner_dns/plugin.py
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity

class MiScannerDns(BaseModule):
    NAME        = "mi_scanner_dns"     # DEBE coincidir con manifest.yaml name
    PHASE       = Phase.DISCOVERY      # DEBE coincidir con la fase del manifest
    DESCRIPTION = "Scanner DNS personalizado"
    AUTHOR      = "Luis Sánchez"
    VERSION     = "1.0.0"
    TAGS        = ["dns", "custom"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            # Leer datos de fases anteriores
            ips = self.get_from_context(context, "resolved_ips", default=[])

            # Tu lógica aquí
            for ip in ips[:5]:
                result.add_finding(
                    type="mi_hallazgo_dns",
                    value=f"IP procesada: {ip}",
                    severity=Severity.INFO,
                    confidence=0.9,
                    metadata={"ip": ip, "source": "mi_scanner_dns"},
                    tags=["dns", "ip"],
                )

            # Guardar datos para módulos de fases siguientes
            self.push_to_context(context, "mi_datos_dns", {"count": len(ips)})

            # Calcular risk score (0.0 - 10.0)
            result.risk_score = min(len(ips) * 0.5, 5.0)

        except Exception as exc:
            # SIEMPRE atrapar excepciones así — nunca dejar que propaguen
            result.add_error(f"Error en mi_scanner_dns: {exc}")

        result.execution_time = time.time() - t0   # SIEMPRE al final
        return result
```

### Paso 4 — Verificar detección

```bash
python black_leviathan.py --list-plugins
# debe aparecer "mi_scanner_dns" en la lista
```

### Paso 5 — Probar

```bash
python black_leviathan.py -t example.com --modules mi_scanner_dns
```

---

## API completa de BaseModule

### Métodos disponibles en `self`

```python
# ── Crear el resultado (SIEMPRE al inicio de run) ─────────────────────────
result = self.make_result(target)    # → ModuleResult

# ── Agregar un hallazgo ───────────────────────────────────────────────────
result.add_finding(
    type="nombre_del_hallazgo",      # str: identificador del tipo
    value="el dato encontrado",      # str: valor principal del hallazgo
    severity=Severity.HIGH,          # Severity enum
    confidence=0.85,                 # float 0.0-1.0
    metadata={},                     # dict: datos adicionales (opcional)
    tags=["tag1", "tag2"],           # list[str]: para filtrado (opcional)
)

# ── Agregar un error (sin romper el módulo) ───────────────────────────────
result.add_error("Mensaje de error descriptivo")

# ── Skip limpio (cuando no hay datos para procesar) ───────────────────────
return self.skip(target, "razón del skip")

# ── Leer del contexto compartido ──────────────────────────────────────────
ips     = self.get_from_context(context, "resolved_ips", default=[])
emails  = self.get_from_context(context, "harvested_emails", default=[])

# ── Escribir al contexto compartido ──────────────────────────────────────
self.push_to_context(context, "mi_key", mi_valor)

# ── Emitir evento al bus (para TUI/otros oyentes) ────────────────────────
await self.emit("mi_evento", {"datos": "..."})

# ── Acceder a config ──────────────────────────────────────────────────────
shodan_key    = self.config.api.shodan       # API keys
timeout       = self.config.module_timeout   # segundos
tor_enabled   = self.config.evasion.tor_enabled
```

### Propiedades de ModuleResult

```python
result.target            # str: el target procesado
result.module_name       # str: NAME del módulo
result.findings          # list[Finding]: hallazgos agregados
result.errors            # list[str]: errores no fatales
result.metadata          # dict: datos libres del módulo
result.risk_score        # float 0.0-10.0: puntaje de riesgo
result.execution_time    # float: segundos (setear al final)
result.critical_count    # int: findings CRITICAL
result.high_count        # int: findings HIGH
```

---

## Contexto compartido entre módulos

El `context: dict` es un diccionario compartido entre TODOS los módulos del mismo scan.
Las fases posteriores leen lo que las anteriores escribieron.

### Keys estándar disponibles en el contexto

| Key | Tipo | Escrita por | Leída por |
|-----|------|-------------|-----------|
| `resolved_ips` | `list[str]` | `dns_enum` (F1) | shodan, geo, port_scan, ip_rep... |
| `harvested_emails` | `list[str]` | `email_harvest` (F3) | hibp, holehe, dehashed |
| `registrant_emails` | `list[str]` | `whois_lookup` (F1) | hibp, holehe |
| `ct_subdomains` | `list[str]` | `crtsh_stream` (F2) | threat_predictor |
| `brute_subdomains` | `list[str]` | `sub_permutation` (F2) | threat_predictor |
| `open_ports` | `list[int]` | `port_scan` (F2) | threat_predictor, shodan |
| `detected_tech` | `list[dict]` | `tech_fingerprint` (F3) | zero_day_hunter |
| `social_profiles` | `list[dict]` | `sherlock_deep` (F3) | threat_predictor |
| `geo_data` | `dict[ip, geo]` | `geolocation` (F1) | behavioral |
| `whois_data` | `dict` | `whois_lookup` (F1) | behavioral |

### Escribir tus propias keys

```python
# Tu módulo puede escribir cualquier key
self.push_to_context(context, "mi_modulo_data", {
    "resultado": 42,
    "items": ["a", "b", "c"],
})

# Y leerla en un módulo de fase posterior
datos = self.get_from_context(context, "mi_modulo_data", default={})
```

---

## Severidades

```python
from modules.base_module import Severity

Severity.INFO       # Datos informativos (sin riesgo directo)
Severity.LOW        # Riesgo bajo (best practice, disclosure menor)
Severity.MEDIUM     # Riesgo moderado (misconfiguration, info sensible)
Severity.HIGH       # Riesgo alto (CVE, breach, config crítica)
Severity.CRITICAL   # Riesgo crítico (RCE posible, credenciales expuestas, acceso a DB)
```

### Cuándo usar cada severidad

| Severidad | Ejemplos |
|-----------|----------|
| INFO | IP geolocalizada, perfil social encontrado, cert válido |
| LOW | Puerto 8080 abierto, tech stack expuesto, wildcard cert |
| MEDIUM | CORS wildcard, cookie sin HttpOnly, paste encontrado, SPF permissivo |
| HIGH | CVE CVSS 7+, breach en HIBP, puerto RDP/VNC abierto, secret en código |
| CRITICAL | CVE CVSS 9+, bucket S3 público con listing, API key hardcodeada, múltiples breaches |

---

## Errores comunes

### ❌ Error 1: Lanzar excepción sin atrapar

```python
# MAL — rompe el módulo y el scan completo
async def run(self, target, context):
    result = self.make_result(target)
    data = requests.get("...")   # Si falla, propaga excepción
    return result

# BIEN
async def run(self, target, context):
    result = self.make_result(target)
    t0 = time.time()
    try:
        data = requests.get("...")
    except Exception as exc:
        result.add_error(str(exc))
    result.execution_time = time.time() - t0
    return result
```

### ❌ Error 2: Olvidar `execution_time`

```python
# MAL — el dashboard muestra tiempo 0.0
return result

# BIEN
result.execution_time = time.time() - t0
return result
```

### ❌ Error 3: Acceder al contexto directamente

```python
# MAL — puede fallar con KeyError
ips = context["resolved_ips"]

# BIEN — con valor default
ips = self.get_from_context(context, "resolved_ips", default=[])
```

### ❌ Error 4: NAME que no coincide con manifest

```python
# manifest.yaml: name: mi_modulo
# plugin.py:
class MiModulo(BaseModule):
    NAME = "mi_modulo_distinto"   # ❌ No coincide → no se registra
    NAME = "mi_modulo"            # ✅ Debe coincidir exactamente
```

### ❌ Error 5: Importar de black_leviathan.py (circular)

```python
# MAL — circular import
from black_leviathan import alguna_funcion

# BIEN — importa desde los módulos directos
from bl_config import BLConfig
from modules.base_module import BaseModule
```

### ❌ Error 6: Bloquear el event loop con código síncrono

```python
# MAL — bloquea el event loop durante el I/O
import requests
resp = requests.get("https://...")

# BIEN — usa aiohttp o run_in_executor para código síncrono
import aiohttp
async with aiohttp.ClientSession() as session:
    async with session.get("https://...") as resp:
        data = await resp.json()

# O para librerías síncronas:
import asyncio
loop = asyncio.get_event_loop()
result = await loop.run_in_executor(None, sync_function, arg1, arg2)
```

---

## Ejemplo completo real

Un módulo que busca en Pastebin usando DuckDuckGo y reporta findings correctamente:

```python
"""plugins/dorkear_github/plugin.py — GitHub dork para secrets expuestos."""
from __future__ import annotations
import asyncio
import time
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class DorkearGithub(BaseModule):
    NAME        = "dorkear_github"
    PHASE       = Phase.SOCIAL       # Fase 6 — depende de F1/F2
    DESCRIPTION = "GitHub dork: busca el dominio en repositorios públicos"
    AUTHOR      = "Luis Sánchez"
    TAGS        = ["github", "dork", "secrets"]

    KEYWORDS = ["password", "api_key", "secret", "token", "credential"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        t0 = time.time()
        try:
            import aiohttp
            gh_token = self.config.api.github
            headers  = {"Accept": "application/vnd.github+json"}
            if gh_token:
                headers["Authorization"] = f"token {gh_token}"

            async with aiohttp.ClientSession(headers=headers) as session:
                for keyword in self.KEYWORDS:
                    await asyncio.sleep(2)  # GitHub rate limit: 10 req/min sin auth
                    query = f'"{target}" {keyword}'

                    async with session.get(
                        "https://api.github.com/search/code",
                        params={"q": query, "per_page": 5},
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        if resp.status == 200:
                            data  = await resp.json()
                            total = data.get("total_count", 0)
                            if total > 0:
                                items = data.get("items", [])
                                result.add_finding(
                                    type="github_dork_hit",
                                    value=f"'{query}' → {total} archivos en GitHub",
                                    severity=Severity.HIGH if total > 5 else Severity.MEDIUM,
                                    confidence=0.75,
                                    metadata={
                                        "query":  query,
                                        "total":  total,
                                        "sample": [i.get("html_url") for i in items[:3]],
                                    },
                                    tags=["github", "dork", keyword],
                                )
                        elif resp.status == 403:
                            result.add_error("GitHub rate limit alcanzado. "
                                             "Configura BL_API__GITHUB para mayor quota.")
                            break

            result.risk_score = min(result.high_count * 2.0 + result.medium_count_safe * 1.0, 8.0)

        except Exception as exc:
            result.add_error(f"dorkear_github error: {exc}")

        result.execution_time = time.time() - t0
        return result

    @property
    def medium_count_safe(self) -> int:
        """Helper: contar findings MEDIUM sin crashear."""
        try:
            return sum(1 for f in self.findings if f.severity.value == "MEDIUM")
        except Exception:
            return 0
```

**Para usarlo:**

```bash
cp -r plugins/template_plugin plugins/dorkear_github
# copiar el código de arriba a plugins/dorkear_github/plugin.py
# editar manifest.yaml con: name: dorkear_github, phase: 6

python black_leviathan.py --list-plugins     # verificar detección
python black_leviathan.py -t example.com --modules dorkear_github
```

---

*¿Dudas sobre la arquitectura? Revisa `core/orchestrator.py` y `modules/base_module.py`.*  
*Creado por **Luis Sánchez*** 🦑
