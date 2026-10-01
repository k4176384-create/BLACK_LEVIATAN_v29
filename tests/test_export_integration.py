"""Tests de integración de exporters."""
from __future__ import annotations
import asyncio
import json
import pytest
from pathlib import Path
from export import get_exporter
from export.json_export import JsonExporter
from export.markdown_export import MarkdownExporter
from export.html_export import HtmlExporter
from export.sarif_export import SarifExporter
from export.stix_export import StixExporter


@pytest.fixture
def sample_report():
    """Reporte de ejemplo para tests de exportación."""
    return {
        "target": "example.com",
        "job_id": "test123",
        "total_risk": 7.5,
        "total_findings": 3,
        "severity_counts": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "INFO": 0},
        "findings": [
            {
                "type": "open_port",
                "value": "1.2.3.4:22 (SSH)",
                "severity": "CRITICAL",
                "confidence": 0.95,
                "source": "port_scan",
                "validation_state": "OBSERVED",
                "limitations": "",
                "metadata": {"port": 22},
                "tags": ["port"],
                "timestamp": 1234567890.0,
                "provenance": {"source": "port_scan", "source_type": "active_tcp"},
                "evidence": {"banner": "SSH-2.0-OpenSSH"},
                "corroboration": [],
                "observed_at": 1234567890.0,
            },
            {
                "type": "spf_misconfiguration",
                "value": "SPF permissive: v=spf1 +all",
                "severity": "HIGH",
                "confidence": 0.95,
                "source": "dns_enum",
                "validation_state": "OBSERVED",
                "limitations": "",
                "metadata": {},
                "tags": ["spf"],
                "timestamp": 1234567890.0,
                "provenance": {"source": "dns_enum", "source_type": "dns"},
                "evidence": {},
                "corroboration": [],
                "observed_at": 1234567890.0,
            },
            {
                "type": "subdomain_ct",
                "value": "api.example.com",
                "severity": "MEDIUM",
                "confidence": 0.9,
                "source": "crtsh_stream",
                "validation_state": "INFERRED",
                "limitations": "Firma puede venir de CDN/proxy",
                "metadata": {},
                "tags": ["subdomain"],
                "timestamp": 1234567890.0,
                "provenance": {"source": "crt.sh", "source_type": "ct_log"},
                "evidence": {},
                "corroboration": [],
                "observed_at": 1234567890.0,
            },
        ],
        "phases": [
            {
                "phase": 1,
                "results": [],
                "findings": [],
            }
        ],
        "module_results": [],
        "summary": {
            "total_findings": 3,
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 0,
            "info": 0,
            "modules_run": 3,
            "phases_run": 1,
        },
        "scan_meta": {},
        "context": {},
    }


@pytest.fixture
def output_dir(tmp_path):
    return tmp_path / "reports"


@pytest.mark.asyncio
async def test_json_exporter(sample_report, output_dir):
    """Test JSON exporter."""
    exporter = get_exporter("json")
    result = await exporter.export(sample_report, output_dir)
    assert result.exists()
    assert result.suffix == ".json"
    with open(result) as f:
        data = json.load(f)
    assert data["target"] == "example.com"
    assert data["total_findings"] == 3


@pytest.mark.asyncio
async def test_markdown_exporter(sample_report, output_dir):
    """Test Markdown exporter."""
    exporter = get_exporter("markdown")
    result = await exporter.export(sample_report, output_dir)
    assert result.exists()
    assert result.suffix == ".md"
    content = result.read_text()
    assert "BLACK LEVIATAN" in content
    assert "example.com" in content


@pytest.mark.asyncio
async def test_html_exporter(sample_report, output_dir):
    """Test HTML exporter."""
    exporter = get_exporter("html")
    result = await exporter.export(sample_report, output_dir)
    assert result.exists()
    assert result.suffix == ".html"
    content = result.read_text()
    assert "BLACK LEVIATAN" in content
    assert "example.com" in content


@pytest.mark.asyncio
async def test_sarif_exporter(sample_report, output_dir):
    """Test SARIF exporter."""
    exporter = get_exporter("sarif")
    result = await exporter.export(sample_report, output_dir)
    assert result.exists()
    assert result.suffix == ".sarif"
    with open(result) as f:
        data = json.load(f)
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1


@pytest.mark.asyncio
async def test_stix_exporter(sample_report, output_dir):
    """Test STIX exporter."""
    exporter = get_exporter("stix")
    result = await exporter.export(sample_report, output_dir)
    assert result.exists()
    assert ".stix.json" in result.name
    with open(result) as f:
        data = json.load(f)
    assert data["type"] == "bundle"


def test_get_exporter_invalid():
    """Test invalid exporter format."""
    with pytest.raises(ValueError, match="Formato desconocido"):
        get_exporter("invalid_format")


@pytest.mark.asyncio
async def test_html_xss_protection(sample_report, output_dir):
    """Test HTML XSS protection - script tags should be escaped."""
    sample_report["findings"][0]["value"] = "<script>alert('xss')</script>"
    exporter = get_exporter("html")
    result = await exporter.export(sample_report, output_dir)
    content = result.read_text()
    assert "<script>" not in content
    assert "&lt;script&gt;" in content
