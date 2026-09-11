#!/usr/bin/env python3
"""
BLACK LEVIATAN v29 — Entry Point CLI
Creado por: Luis Sánchez
"""
from __future__ import annotations
import argparse
import asyncio
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("bl.main")


# ─────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="black_leviathan",
        description="BLACK LEVIATAN v29 — OSINT Intelligence Platform by Luis Sánchez",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  %(prog)s -t example.com
  %(prog)s -t example.com --phases 1,2,3
  %(prog)s -t example.com --mode stealth --output markdown
  %(prog)s -t example.com --tui
  %(prog)s --list-modules
  %(prog)s --list-plugins

Modos disponibles:
  fast      Sólo fases 1-3 (recon básico, ~2min)
  normal    Fases 1-7 (análisis completo, ~10min)   [default]
  deep      Todas las fases 1-10 (~25min)
  stealth   Normal + K6 Evasion activo desde el inicio

Formatos de salida:
  json, markdown, html, pdf, sarif, stix
        """,
    )

    tg = p.add_argument_group("Target")
    tg.add_argument("-t", "--target", metavar="DOMAIN")
    tg.add_argument("-f", "--file",   metavar="FILE")

    eg = p.add_argument_group("Ejecución")
    eg.add_argument("--mode", "-m", choices=["fast","normal","deep","stealth"], default="normal")
    eg.add_argument("--phases",       metavar="1,2,3")
    eg.add_argument("--skip-phases",  metavar="7,8")
    eg.add_argument("--modules",      metavar="whois_lookup,port_scan")
    eg.add_argument("--timeout",      type=int, default=120, metavar="SECONDS")
    eg.add_argument("--concurrency",  type=int, default=10,  metavar="N")

    og = p.add_argument_group("Salida")
    og.add_argument("--output", "-o", choices=["json","markdown","html","pdf","sarif","stix"], default="json")
    og.add_argument("--output-dir", metavar="DIR", default="reports")
    og.add_argument("--tui", action="store_true")
    og.add_argument("--quiet", "-q", action="store_true")

    cg = p.add_argument_group("Configuración")
    cg.add_argument("--config",     metavar="FILE", default=".env")
    cg.add_argument("--plugin-dir", metavar="DIR",  default="plugins")

    ug = p.add_argument_group("Utilidades")
    ug.add_argument("--list-modules",    action="store_true")
    ug.add_argument("--list-plugins",    action="store_true")
    ug.add_argument("--validate-config", action="store_true")
    ug.add_argument("--version", "-v",   action="version",
                    version="BLACK LEVIATAN v29 — by Luis Sánchez")
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────
async def run_scan(args: argparse.Namespace) -> int:
    from bl_config import BLConfig
    from core.event_bus import EventBus
    from core.state_manager import StateManager
    from core.vigilante_v2 import VigilanteV2
    from core.orchestrator import Orchestrator
    from plugins.hooks import HookRegistry

    # Config
    if args.config and Path(args.config).exists():
        from dotenv import load_dotenv
        load_dotenv(args.config)
    config = BLConfig()

    # Fases
    phase_overrides: list[int] | None = None
    if args.mode == "fast":       phase_overrides = [1, 2, 3]
    elif args.mode == "deep":     phase_overrides = list(range(1, 11))
    elif args.mode == "stealth":  config.stealth = True

    if args.phases:
        try:    phase_overrides = [int(x.strip()) for x in args.phases.split(",")]
        except: log.error("--phases inválido. Usa: 1,2,3"); return 1

    if args.skip_phases:
        skip = {int(x.strip()) for x in args.skip_phases.split(",")}
        phase_overrides = [p for p in (phase_overrides or range(1,11)) if p not in skip]

    if phase_overrides is not None:
        config.dag.enabled_phases = phase_overrides

    if args.plugin_dir:
        config.plugins.plugin_dirs = [Path(args.plugin_dir)]

    # Sistema
    bus       = EventBus()
    state     = StateManager()
    vigilante = VigilanteV2(bus, state, config)
    hooks     = HookRegistry()

    orchestrator = Orchestrator(
        config=config, bus=bus, state=state,
        vigilante=vigilante, hooks=hooks,
    )

    await orchestrator.setup_kernels()
    await orchestrator.setup_plugins()

    # Targets
    targets: list[str] = []
    if args.target:
        targets.append(
            args.target.strip().lower()
            .removeprefix("https://").removeprefix("http://")
            .rstrip("/").split("/")[0]
        )
    if args.file:
        targets += [
            ln.strip().lower() for ln in Path(args.file).read_text().splitlines()
            if ln.strip() and not ln.startswith("#")
        ]

    if not targets:
        log.error("Falta target: -t example.com  o  -f targets.txt")
        return 1

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    for target in targets:
        if not args.quiet:
            print(f"\n{'─'*60}\n  🦑  BLACK LEVIATAN v29  |  {target}\n{'─'*60}\n")

        # CRÍTICO: el Orchestrator pasa config.target a los módulos (no el arg de run_scan)
        config.target = target

        report = await orchestrator.run_scan(target)
        report["target"] = target

        # IntelPipeline lee report.get("phases") que no existe en el context plano.
        # Calcular risk desde orchestrator._results directamente.
        if hasattr(orchestrator, "_results") and orchestrator._results:
            W = {"CRITICAL": 4.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.3, "INFO": 0.0}
            total_risk = 0.0
            sev_counts: dict[str, int] = {k: 0 for k in W}
            for mod_result in orchestrator._results.values():
                for finding in getattr(mod_result, "findings", []):
                    sev = getattr(finding, "severity", None)
                    sev_str = sev.value if hasattr(sev, "value") else str(sev) if sev else "INFO"
                    conf = getattr(finding, "confidence", 0.5)
                    total_risk += W.get(sev_str, 0) * conf
                    sev_counts[sev_str] = sev_counts.get(sev_str, 0) + 1
            report["total_risk"]     = min(round(total_risk, 2), 10.0)
            report["severity_counts"] = sev_counts
            report["total_findings"] = sum(sev_counts.values())

        try:
            from export import get_exporter
            out = await get_exporter(args.output).export(report, output_dir)
            if not args.quiet:
                print(f"\n  ✅ Reporte: {out}")
        except Exception as exc:
            log.error("Export error: %s", exc)

    return 0


# ─────────────────────────────────────────────────────────────────
def cmd_list_modules() -> None:
    from rich.console import Console
    from rich.table import Table
    console = Console()
    table = Table(title="BLACK LEVIATAN v29 — Módulos disponibles", style="bold magenta")
    table.add_column("Fase",    style="cyan", justify="center")
    table.add_column("Módulo",  style="green")
    table.add_column("Descripción", style="white")
    modules = [
        ("1 — RECON",       "whois_lookup",         "WHOIS: registrante, fechas, nameservers"),
        ("1 — RECON",       "dns_enum",             "DNS: A/MX/TXT/NS + SPF/DMARC"),
        ("1 — RECON",       "geolocation",          "Geolocalización de IPs"),
        ("1 — RECON",       "robots_sitemap",       "robots.txt + sitemap.xml"),
        ("2 — DISCOVERY",   "shodan_idb",           "Shodan InternetDB (free) + API"),
        ("2 — DISCOVERY",   "crtsh_stream",         "Certificate Transparency Logs"),
        ("2 — DISCOVERY",   "sub_permutation",      "DNS brute force (70+ prefijos)"),
        ("2 — DISCOVERY",   "port_scan",            "TCP async scan (35 puertos)"),
        ("3 — ENUM",        "email_harvest",        "Emails expuestos en páginas"),
        ("3 — ENUM",        "sherlock_deep",        "Username en 20+ plataformas"),
        ("3 — ENUM",        "tech_fingerprint",     "Stack: CMS/framework/CDN"),
        ("4 — CORRELATE",   "virustotal",           "VirusTotal: AV detections"),
        ("4 — CORRELATE",   "ip_reputation",        "AbuseIPDB + ipinfo.io"),
        ("4 — CORRELATE",   "greynoise",            "GreyNoise: scanner context"),
        ("5 — BREACH",      "hibp",                 "Have I Been Pwned"),
        ("5 — BREACH",      "holehe",               "Cuentas registradas por email"),
        ("5 — BREACH",      "paste_monitor",        "Pastebins públicos"),
        ("5 — BREACH",      "dehashed_local",       "DeHashed breach database"),
        ("6 — SOCIAL",      "github",               "GitHub repos + commit leaks"),
        ("6 — SOCIAL",      "reddit",               "Reddit: menciones y sentiment"),
        ("6 — SOCIAL",      "linkedin_osint",       "LinkedIn: empleados públicos"),
        ("7 — AI/FUTURE",   "threat_predictor",     "Scoring de riesgo compuesto"),
        ("7 — AI/FUTURE",   "behavioral",           "Anomalías de infraestructura"),
        ("7 — AI/FUTURE",   "quantum_resistant",    "TLS/cipher análisis"),
        ("8 — DEEP OSINT",  "zero_day_hunter",      "CVE correlation via NVD"),
        ("8 — DEEP OSINT",  "ransomware_leaks",     "Ransomware victim intel"),
        ("8 — DEEP OSINT",  "darkweb_search",       "IOC intel: OTX + ThreatFox"),
        ("9 — HISTORICAL",  "wayback_deep",         "Wayback Machine: paths históricos"),
        ("9 — HISTORICAL",  "cert_stream",          "Historial completo de certs"),
        ("9 — HISTORICAL",  "github_history",       "Commits históricos + secrets"),
        ("10 — CLOUD",      "cloud_bucket_hunt",    "S3/Azure/GCS buckets públicos"),
        ("10 — CLOUD",      "sourcemap_secrets",    "JS source maps + secrets"),
        ("10 — CLOUD",      "tech_fingerprint_deep","Security headers + CORS/CSP"),
    ]
    for phase, name, desc in modules:
        table.add_row(phase, name, desc)
    console.print(table)


# ─────────────────────────────────────────────────────────────────
def main() -> None:
    args = parse_args()

    if args.list_modules:
        cmd_list_modules()
        return

    if args.list_plugins:
        from bl_config import BLConfig
        from core.event_bus import EventBus
        from core.state_manager import StateManager
        from core.vigilante_v2 import VigilanteV2
        from plugins.hooks import HookRegistry
        from core.orchestrator import Orchestrator
        from rich.console import Console
        from rich.table import Table

        async def _list_plugins():
            config    = BLConfig()
            bus       = EventBus()
            state     = StateManager()
            vigilante = VigilanteV2(bus, state, config)
            hooks     = HookRegistry()
            orch      = Orchestrator(config=config, bus=bus, state=state,
                                     vigilante=vigilante, hooks=hooks)
            await orch.setup_kernels()
            await orch.setup_plugins()
            names = orch.loader.registered_names if orch.loader else []
            console = Console()
            table = Table(title="Plugins instalados", style="bold magenta")
            table.add_column("Nombre", style="green")
            for n in names:
                table.add_row(n)
            console.print(table)

        asyncio.run(_list_plugins())
        return

    if args.validate_config:
        from bl_config import BLConfig
        from rich.console import Console
        config  = BLConfig()
        console = Console()
        console.print("[bold magenta]BLACK LEVIATAN v29 — Validación de config[/]")
        for k, v in config.api.model_dump().items():
            status = "✅" if v else "⚠️  sin configurar"
            console.print(f"  {k:25s}: {status}")
        return

    sys.exit(asyncio.run(run_scan(args)))


if __name__ == "__main__":
    main()
