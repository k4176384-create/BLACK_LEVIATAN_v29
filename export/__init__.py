"""export package — json, markdown, html, sarif, stix."""
from __future__ import annotations
from pathlib import Path


def get_exporter(fmt: str):
    match fmt:
        case "json":     from .json_export import JsonExporter;         return JsonExporter()
        case "markdown": from .markdown_export import MarkdownExporter; return MarkdownExporter()
        case "html":     from .html_export import HtmlExporter;         return HtmlExporter()
        case "sarif":    from .sarif_export import SarifExporter;       return SarifExporter()
        case "stix":     from .stix_export import StixExporter;         return StixExporter()
        case _: raise ValueError(f"Formato desconocido: {fmt}")
