from __future__ import annotations
import json, uuid
from datetime import datetime
from pathlib import Path

class StixExporter:
    async def export(self, report: dict, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        t   = report.get("target","unknown").replace("/","_")
        fn  = output_dir / f"bl_{t}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.stix.json"
        now = datetime.utcnow().isoformat()+"Z"
        objs = [{"type":"report","spec_version":"2.1","id":f"report--{uuid.uuid4()}",
                 "created":now,"modified":now,"name":f"BL v29 — {report.get('target','')}",
                 "report_types":["threat-report"],"published":now,"object_refs":[]}]
        all_findings = report.get("findings", [])
        if not all_findings:
            for phase in report.get("phases",[]):
                all_findings.extend(phase.get("findings",[]))
        for fi in all_findings:
                if fi.get("severity","INFO") in ("CRITICAL","HIGH","MEDIUM"):
                    oid = f"indicator--{uuid.uuid4()}"
                    objs[0]["object_refs"].append(oid)
                    objs.append({"type":"indicator","spec_version":"2.1","id":oid,
                                 "created":now,"modified":now,
                                 "name":fi.get("type","?"),"description":fi.get("value",""),
                                 "pattern":f"[domain-name:value = '{report.get('target','')}']",
                                 "pattern_type":"stix","valid_from":now,
                                 "confidence":int(fi.get("confidence",0.5)*100)})
        bundle = {"type":"bundle","id":f"bundle--{uuid.uuid4()}","objects":objs}
        fn.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        return fn
