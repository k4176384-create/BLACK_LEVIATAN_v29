#!/usr/bin/env python3
"""tools/doctor.py — Self-audit BLACK LEVIATAN v29"""
from __future__ import annotations
import importlib.util, pathlib, sys
ROOT = pathlib.Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(ROOT))

def check(msg, ok, detail=""):
    icon = "✅" if ok else "❌"
    print(f"{icon} {msg}" + (f" — {detail}" if detail else ""))

def main():
    print("=== BLACK LEVIATAN v29 — Doctor Self-Audit ===\n")
    # 1. Imports
    try:
        from bl_config import BLConfig
        check("BLConfig import", True)
    except Exception as e:
        check("BLConfig import", False, str(e))
        return
    try:
        from core.event_bus import EventBus
        from core.state_manager import StateManager
        from core.vigilante_v2 import VigilanteV2
        from core.orchestrator import Orchestrator
        check("Core imports", True)
    except Exception as e:
        check("Core imports", False, str(e))
    # 2. Target classifier
    tc = ROOT / "core/target.py"
    check("core/target.py exists", tc.exists())
    # 3. Checkpoint
    check("core/checkpoint.py exists", (ROOT/"core/checkpoint.py").exists())
    # 4. Queues
    check("core/queue.py exists", (ROOT/"core/queue.py").exists())
    # 5. Orchestrator wiring
    orch_text = (ROOT/"core/orchestrator.py").read_text()
    check("Orchestrator starts EventBus", "await self._bus.start()" in orch_text)
    check("Orchestrator starts Vigilante", "await self._vigilante.start()" in orch_text)
    check("Orchestrator export signature", "report: dict" in (ROOT/"export/json_export.py").read_text())
    check("Orchestrator _build_report", "_build_report" in orch_text)
    # 6. Finding provenance
    fm = (ROOT/"modules/base_module.py").read_text()
    check("Finding has provenance", "provenance" in fm.lower() or "validation_state" in fm.lower())
    # 7. Plugin count
    try:
        from plugins.loader import PluginLoader
        from bl_config import BLConfig
        from core.event_bus import EventBus
        from kernels.k3_immortal_storage.storage import ImmortalStorage
        config=BLConfig()
        bus=EventBus()
        # storage dummy
        print(f"   Config OK: phases={config.dag.enabled_phases[:3]}...")
    except Exception as e:
        print(f"   Config error: {e}")
    # 8. Export signature consistency
    for fmt in ["json","markdown","html","sarif","stix"]:
        p=ROOT/f"export/{fmt}_export.py"
        if p.exists():
            ok="def export" in p.read_text() and "report" in p.read_text()
            check(f"Exporter {fmt} signature", ok)
    # 9. Disk resources
    import shutil
    free=shutil.disk_usage(str(ROOT)).free // 1024 // 1024
    check(f"Disk free {free} MB", free>100)
    print("\nDone.")

if __name__ == "__main__":
    main()
