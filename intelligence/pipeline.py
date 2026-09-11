"""intelligence/pipeline.py — Post-scan enrichment pipeline."""
from __future__ import annotations
import logging

log = logging.getLogger("bl.intel.pipeline")


class IntelPipeline:
    """Pipeline de enriquecimiento post-scan. Corre después del Orchestrator."""

    async def enrich(self, report: dict) -> dict:
        """Aplica enriquecimiento al reporte completo."""
        report = self._deduplicate_findings(report)
        report = self._calculate_composite_risk(report)
        report = self._generate_executive_summary(report)
        return report

    def _deduplicate_findings(self, report: dict) -> dict:
        """Elimina findings duplicados por (type, value)."""
        for phase in report.get("phases", []):
            seen: set[tuple] = set()
            unique = []
            for f in phase.get("findings", []):
                key = (f.get("type"), f.get("value"))
                if key not in seen:
                    seen.add(key)
                    unique.append(f)
            phase["findings"] = unique
        return report

    def _calculate_composite_risk(self, report: dict) -> dict:
        """Calcula risk score compuesto ponderado por severidad."""
        weights = {"CRITICAL": 4.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.3, "INFO": 0.0}
        total = 0.0
        count = 0
        for phase in report.get("phases", []):
            for f in phase.get("findings", []):
                sev    = f.get("severity", "INFO")
                conf   = f.get("confidence", 0.5)
                total += weights.get(sev, 0) * conf
                count += 1
        report["total_risk"] = min(round(total, 2), 10.0)
        return report

    def _generate_executive_summary(self, report: dict) -> dict:
        """Genera resumen ejecutivo."""
        all_findings = [
            f for phase in report.get("phases", [])
            for f in phase.get("findings", [])
        ]
        by_sev = {}
        for f in all_findings:
            sev = f.get("severity", "INFO")
            by_sev[sev] = by_sev.get(sev, 0) + 1

        report["summary"] = {
            "total_findings": len(all_findings),
            "critical":       by_sev.get("CRITICAL", 0),
            "high":           by_sev.get("HIGH", 0),
            "medium":         by_sev.get("MEDIUM", 0),
            "low":            by_sev.get("LOW", 0),
            "info":           by_sev.get("INFO", 0),
            "modules_run":    len(report.get("module_runs", [])),
            "phases_run":     len(report.get("phases", [])),
        }
        return report
