#!/usr/bin/env python3
"""tools/doctor.py — Self-audit BLACK LEVIATAN v29"""
from __future__ import annotations
import importlib.util, pathlib, sys, shutil, platform
ROOT = pathlib.Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(ROOT))

passed = 0
failed = 0
warnings = 0

def check(msg, ok, detail="", warn=False):
    global passed, failed, warnings
    if warn:
        icon = "⚠️ "
        warnings += 1
    elif ok:
        icon = "✅"
        passed += 1
    else:
        icon = "❌"
        failed += 1
    print(f"{icon} {msg}" + (f" — {detail}" if detail else ""))

def main():
    global passed, failed, warnings
    print("=" * 60)
    print("  BLACK LEVIATAN v29 — Doctor Self-Audit")
    print("=" * 60)

    # ── 1. Python version ──
    v = sys.version_info
    check(f"Python {v.major}.{v.minor}.{v.micro}", v >= (3, 11), f"requiere >= 3.11")

    # ── 2. Core imports ──
    try:
        from bl_config import BLConfig
        check("bl_config import", True)
    except Exception as e:
        check("bl_config import", False, str(e))
        return

    try:
        from core.event_bus import EventBus
        from core.state_manager import StateManager
        from core.vigilante_v2 import VigilanteV2
        from core.orchestrator import Orchestrator
        from core.target import classify_target, TargetType
        from core.validation import validate_finding, confidence_engine
        from core.checkpoint import CheckpointManager
        from core.queue import RetryQueue, PersistentDLQ
        from plugins.hooks import HookRegistry
        check("Core imports (6 modules)", True)
    except Exception as e:
        check("Core imports", False, str(e))

    # ── 3. Kernels ──
    kernel_files = [
        ("k1_stealth_crawler/crawler.py", "K1 Stealth Crawler"),
        ("k2_deep_correlator/correlator.py", "K2 Deep Correlator"),
        ("k3_immortal_storage/storage.py", "K3 Immortal Storage"),
        ("k4_phantom_dashboard/tui.py", "K4 Phantom Dashboard"),
        ("k5_autonomous_intel/intel.py", "K5 Autonomous Intel"),
        ("k6_evasion_mesh/evasion.py", "K6 Evasion Mesh"),
    ]
    for path, name in kernel_files:
        check(f"Kernel {name}", (ROOT/"kernels"/path).exists())

    # ── 4. Config validation ──
    config = BLConfig()
    check("Config instantiation", True)
    check(f"Config phases: {config.dag.enabled_phases}",
          len(config.dag.enabled_phases) > 0, "no hay fases habilitadas",
          warn=len(config.dag.enabled_phases) < 5)

    # ── 5. API keys status ──
    api = config.api
    keys = {
        "virustotal": api.virustotal,
        "shodan": api.shodan,
        "greynoise": api.greynoise,
        "hibp": api.hibp,
        "github": api.github,
        "abuseipdb": api.abuseipdb,
    }
    configured = sum(1 for v in keys.values() if v)
    total = len(keys)
    print(f"\n  API Keys: {configured}/{total} configuradas")
    for name, val in keys.items():
        status = "✅" if val else "⚠️  (no configurada)"
        print(f"    {name}: {status}")
    if configured == 0:
        check("API keys", False, "ninguna configurada — módulos usarán fallback", warn=True)
    else:
        check("API keys", True, f"{configured}/{total}")

    # ── 6. Plugin manifests ──
    plugins_dir = ROOT / "plugins"
    manifest_count = 0
    enabled_count = 0
    for mf in plugins_dir.glob("*/manifest.yaml"):
        manifest_count += 1
        content = mf.read_text()
        if "enabled: true" in content:
            enabled_count += 1
    check(f"Plugin manifests: {manifest_count} total, {enabled_count} habilitados",
          manifest_count > 0)

    # ── 7. Exporters ──
    for fmt in ["json", "markdown", "html", "sarif", "stix"]:
        p = ROOT / f"export/{fmt}_export.py"
        if p.exists():
            content = p.read_text()
            ok = "def export" in content and "report" in content
            has_mkdir = "mkdir" in content
            check(f"Exporter {fmt} — signature + mkdir", ok and has_mkdir,
                  "falta mkdir" if not has_mkdir else "")
        else:
            check(f"Exporter {fmt}", False, "no existe")

    # ── 8. Security checks ──
    # WebSocket bind (check config, not tui which reads from config)
    config_text = (ROOT/"bl_config.py").read_text()
    check("WebSocket bind 127.0.0.1",
          '127.0.0.1' in config_text and 'ws_host' in config_text,
          "exposición pública detectada",
          warn='0.0.0.0' in config_text)

    # Plugin defaults
    for mf in plugins_dir.glob("*/manifest.yaml"):
        content = mf.read_text()
        if "enabled: true" in content:
            name = mf.parent.name
            if "example" in name or "template" in name:
                check(f"Plugin '{name}' deshabilitado", False, f"'{mf.name}' tiene enabled: true")

    # ── 9. Database files ──
    db_files = list(ROOT.glob("**/*.db"))
    duck_files = list(ROOT.glob("**/*.duckdb"))
    check(f"SQLite databases: {len(db_files)}", True)
    check(f"DuckDB databases: {len(duck_files)}", True)

    # ── 10. Disk space ──
    free = shutil.disk_usage(str(ROOT)).free // 1024 // 1024
    check(f"Disk free: {free} MB", free > 100, warn=free < 500)

    # ── 11. Target classifier smoke test ──
    try:
        from core.target import classify_target, TargetType
        info = classify_target("example.com")
        check(f"Target classifier: example.com → {info.type.value}",
              info.type == TargetType.DOMAIN)
    except Exception as e:
        check("Target classifier", False, str(e))

    # ── 12. Validation engine ──
    try:
        from core.validation import validate_finding
        result = validate_finding("test_finding", "test_value", {})
        score = result.get("confidence_adjust", 0)
        check(f"Validation engine: state={result.get('validation_state', '?')}", True)
    except Exception as e:
        check("Validation engine", False, str(e))

    # ── Summary ──
    total = passed + failed + warnings
    print("\n" + "=" * 60)
    print(f"  PASSED: {passed}  |  FAILED: {failed}  |  WARNINGS: {warnings}  |  TOTAL: {total}")
    if failed == 0:
        print("  ✅ Sistema operativo — listo para escaneo")
    else:
        print(f"  ❌ {failed} problema(s) detectado(s) — revisar antes de escanear")
    print("=" * 60)

    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
