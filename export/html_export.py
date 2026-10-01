from __future__ import annotations
import html
from datetime import datetime
from pathlib import Path

CSS = """
body{background:#1e1e2e;color:#cdd6f4;font-family:'JetBrains Mono',monospace;padding:2rem;margin:0}
h1{color:#cba6f7}h2{color:#89b4fa;margin-top:2rem}
table{border-collapse:collapse;width:100%;margin-top:1rem}
th{background:#313244;color:#cba6f7;padding:.6rem 1rem;text-align:left}
td{border-bottom:1px solid #313244;padding:.4rem 1rem}
.CRITICAL{color:#f38ba8;font-weight:bold}.HIGH{color:#fab387;font-weight:bold}
.MEDIUM{color:#f9e2af}.LOW{color:#a6e3a1}.INFO{color:#89b4fa}
.meta{color:#6c7086;font-size:.85em}.badge{border-radius:4px;padding:2px 8px}
"""

class HtmlExporter:
    async def export(self, report: dict, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        t  = report.get("target","unknown").replace("/","_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fn = output_dir / f"bl_{t}_{ts}.html"
        s  = report.get("summary",{})
        # Support both new report (findings flat) and old phases->results
        all_findings = report.get("findings") or []
        if not all_findings:
            for phase in report.get("phases",[]):
                for res in phase.get("results",[]):
                    all_findings.extend(res.get("findings",[]))
                all_findings.extend(phase.get("findings",[]))
        rows = []
        for fi in all_findings:
            sev = fi.get("severity","INFO")
            vs = fi.get("validation_state","")
            conf = fi.get("confidence","")
            ev = fi.get("limitations","")[:80]
            rows.append(
                f"<tr><td class='{html.escape(sev)} badge'>{html.escape(sev)}</td>"
                f"<td>{html.escape(str(fi.get('type','?')))}<br><span class='meta'>{html.escape(str(vs))} conf:{html.escape(str(conf))}</span></td>"
                f"<td>{html.escape(str(fi.get('value','?')))}<br><span class='meta'>{html.escape(str(ev))}</span></td>"
                f"<td class='meta'>{html.escape(str(fi.get('source','?')))}</td></tr>"
            )
        html_content = f"""<!DOCTYPE html><html lang="es">
<head><meta charset="UTF-8"><title>BL v29 — {report.get('target','?')}</title>
<style>{CSS}</style></head><body>
<h1>🦑 BLACK LEVIATAN v29</h1>
<p>Target: <b>{report.get('target','?')}</b> &nbsp;|&nbsp;
Risk: <b class="CRITICAL">{report.get('total_risk',0):.1f}/10</b> &nbsp;|&nbsp;
{s.get('total_findings',0)} hallazgos &nbsp;|&nbsp;
{datetime.now().strftime('%Y-%m-%d %H:%M')} &nbsp;|&nbsp;
<span class="meta">by Luis Sánchez</span></p>
<table><thead><tr><th>Sev</th><th>Tipo</th><th>Valor</th><th>Fase</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></body></html>"""
        fn.write_text(html_content, encoding="utf-8")
        return fn
