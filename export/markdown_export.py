from __future__ import annotations
import html as html_mod
from datetime import datetime
from pathlib import Path

SEV_ICONS = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","INFO":"🔵"}

class MarkdownExporter:
    async def export(self, report: dict, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
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
        # Support both flat findings and phase->results
        all_findings = report.get("findings") or []
        if not all_findings:
            for phase in report.get("phases",[]):
                for res in phase.get("results",[]):
                    all_findings.extend(res.get("findings",[]))
                all_findings.extend(phase.get("findings",[]))
        # Group by validation
        lines.append("### Hallazgos (con evidencia)")
        for f_ in all_findings[:100]:
            icon = SEV_ICONS.get(f_.get("severity","INFO"),"⚪")
            vs = f_.get("validation_state","")
            lim = f_.get("limitations","")
            extra = f" _( {vs} conf:{f_.get('confidence')} )_" if vs else ""
            lines.append(f"- {icon} **{html_mod.escape(str(f_.get('type','?')))}**: {html_mod.escape(str(f_.get('value','?')))}{extra}")
            if lim:
                lines.append(f"  > _Limitación: {lim}_")
        # Also per-phase summary
        for phase in report.get("phases",[]):
            lines.append(f"### Fase {phase.get('phase','?')} — hallazgos: {len(phase.get('results',[]))} módulos")
        lines.append("")
        fn.write_text("\n".join(lines), encoding="utf-8")
        return fn
