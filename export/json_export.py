from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path

class JsonExporter:
    async def export(self, report: dict, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        t = report.get("target","unknown").replace("/","_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fn = output_dir / f"bl_{t}_{ts}.json"
        with open(fn,"w",encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        return fn
