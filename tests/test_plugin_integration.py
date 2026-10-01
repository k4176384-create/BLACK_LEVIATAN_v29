"""Tests de integración del plugin system."""
from __future__ import annotations
import pytest
from pathlib import Path
from plugins.loader import PluginLoader, PluginManifest
from plugins.hooks import HookRegistry, HookType
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class SamplePlugin(BaseModule):
    """Plugin de prueba."""
    NAME = "test_plugin"
    PHASE = Phase.RECON
    DESCRIPTION = "Test plugin"

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        result.add_finding(
            type="plugin_finding",
            value="plugin_value",
            severity=Severity.INFO,
            confidence=0.9,
        )
        return result


def test_plugin_manifest_parsing(tmp_path):
    """Test manifest.yaml parsing."""
    manifest_file = tmp_path / "manifest.yaml"
    manifest_file.write_text("""
name: test_plugin
version: "1.0.0"
author: "Test"
description: "Test plugin"
enabled: true
phase: 1
tags:
  - test
""")
    manifest = PluginManifest(manifest_file)
    assert manifest.name == "test_plugin"
    assert manifest.version == "1.0.0"
    assert manifest.enabled is True
    assert manifest.tags == ["test"]


def test_plugin_manifest_disabled(tmp_path):
    """Test disabled plugin manifest."""
    manifest_file = tmp_path / "manifest.yaml"
    manifest_file.write_text("""
name: disabled_plugin
enabled: false
""")
    manifest = PluginManifest(manifest_file)
    assert manifest.enabled is False


def test_hook_registry():
    """Test hook registration and firing."""
    registry = HookRegistry()
    fired = []

    async def callback(ctx):
        fired.append(ctx)

    hook_id = registry.register(
        HookType.PRE_PHASE,
        callback,
        "test_plugin",
        phase=1,
    )
    assert hook_id > 0
    assert registry.total_hooks == 1

    hooks = registry.get_hooks(HookType.PRE_PHASE, phase=1)
    assert len(hooks) == 1

    hooks = registry.get_hooks(HookType.PRE_PHASE, phase=2)
    assert len(hooks) == 0


@pytest.mark.asyncio
async def test_hook_fire():
    """Test hook firing."""
    registry = HookRegistry()
    fired = []

    async def callback(ctx):
        fired.append(ctx)

    registry.register(HookType.PRE_PHASE, callback, "test_plugin")
    await registry.fire(HookType.PRE_PHASE, {"phase": 1})
    assert len(fired) == 1
    assert fired[0]["phase"] == 1
