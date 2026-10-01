from __future__ import annotations
import json, uuid
from datetime import datetime
from pathlib import Path

SEV = {"CRITICAL":"error","HIGH":"error","MEDIUM":"warning","LOW":"note","INFO":"none"}

class SarifExporter:
    async def export(self, report: dict, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        t  = report.get("target","unknown").replace("/","_")
        fn = output_dir / f"bl_{t}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sarif"
        rules, results = {}, []
        all_findings = report.get("findings", [])
        if not all_findings:
            for phase in report.get("phases",[]):
                all_findings.extend(phase.get("findings",[]))
        for fi in all_findings:
                rid = fi.get("type","unknown")
                if rid not in rules:
                    rules[rid] = {"id":rid,"shortDescription":{"text":rid.replace("_"," ").title()}}
                results.append({
                    "ruleId": rid,
                    "level":  SEV.get(fi.get("severity","INFO"),"none"),
                    "message":{"text": fi.get("value","")},
                    "locations":[{"physicalLocation":{"artifactLocation":{"uri":report.get("target","")}}}],
                })
        sarif = {"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0",
                 "runs":[{"tool":{"driver":{"name":"BLACK LEVIATAN","version":"29.0.0",
                  "rules":list(rules.values())}},"results":results}]}
        fn.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        return fn
