from __future__ import annotations
from datetime import datetime
from pathlib import Path

SEV_ICONS = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","INFO":"🔵"}

class MarkdownExporter:
    async def export(self, report: dict, output_dir: Path) -> Path:
        t  = report.get("target","unknown").replace("/","_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fn = output_dir / f"bl_{t}_{ts}.md"
        s  = report.get("summary",{})
        lines = [
            f"# 🦑 BLACK LEVIATAN v29 — Reporte OSINT",
            f"",
            f"**Target:** `{report.get('target','?')}`  ",
            f"**Risk Score:** {report.get('total_risk',0):.1f}/10.0  ",
            f"**Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  ",
            f"**Creado por:** Luis Sánchez  ",
            f"",
            f"---",
            f"",
            f"## Resumen",
            f"",
            f"| Métrica | Valor |",
            f"|---------|-------|",
            f"| Módulos ejecutados | {s.get('modules_run',0)} |",
            f"| Hallazgos totales  | {s.get('total_findings',0)} |",
            f"| 🔴 Críticos        | {s.get('critical',0)} |",
            f"| 🟠 Altos           | {s.get('high',0)} |",
            f"| 🟡 Medios          | {s.get('medium',0)} |",
            f"| Tiempo total       | {s.get('total_time','?')}s |",
            f"",
            f"## Hallazgos",
            f"",
        ]
        for phase in report.get("phases",[]):
            lines.append(f"### Fase {phase.get('phase','?')} — {phase.get('phase_name','?')}")
            for f_ in phase.get("findings",[]):
                icon = SEV_ICONS.get(f_.get("severity","INFO"),"⚪")
                lines.append(f"- {icon} **{f_.get('type','?')}**: {f_.get('value','?')}")
            lines.append("")
        fn.write_text("\n".join(lines), encoding="utf-8")
        return fn
