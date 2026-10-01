"""Tests de integración del orchestrator con módulos mock."""
from __future__ import annotations
import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from core.orchestrator import Orchestrator, DAG_DEPS, PHASE_NAMES
from core.event_bus import EventBus
from core.state_manager import StateManager
from core.vigilante_v2 import VigilanteV2
from plugins.hooks import HookRegistry
from modules.base_module import BaseModule, Phase, ModuleResult, Severity


class MockModule(BaseModule):
    """Módulo mock para tests."""
    NAME = "mock_module"
    PHASE = Phase.RECON
    DESCRIPTION = "Mock module for testing"
    INPUT_TYPES = set()  # Accept all
    DEPENDENCIES = []

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        result.add_finding(
            type="mock_finding",
            value=f"mock_value_for_{target}",
            severity=Severity.INFO,
            confidence=0.9,
        )
        result.risk_score = 1.0
        return result


class MockModuleFails(BaseModule):
    """Módulo mock que falla."""
    NAME = "mock_fails"
    PHASE = Phase.RECON
    DESCRIPTION = "Mock module that fails"
    INPUT_TYPES = set()
    DEPENDENCIES = []

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        result.add_error("Simulated failure")
        return result


class MockModuleWithDeps(BaseModule):
    """Módulo mock con dependencias."""
    NAME = "mock_with_deps"
    PHASE = Phase.DISCOVERY
    DESCRIPTION = "Mock module with dependencies"
    INPUT_TYPES = set()
    DEPENDENCIES = ["mock_module"]

    async def run(self, target: str, context: dict) -> ModuleResult:
        result = self.make_result(target)
        result.add_finding(
            type="dep_finding",
            value="dep_value",
            severity=Severity.LOW,
            confidence=0.8,
        )
        return result


@pytest.fixture
def bus():
    return EventBus()


@pytest.fixture
def state():
    return StateManager()


@pytest.fixture
def config():
    from bl_config import BLConfig
    return BLConfig()


@pytest.fixture
def vigilante(bus, state, config):
    return VigilanteV2(bus, state, config)


@pytest.fixture
def hooks():
    return HookRegistry()


@pytest.fixture
def orchestrator(config, bus, state, vigilante, hooks):
    return Orchestrator(config=config, bus=bus, state=state, vigilante=vigilante, hooks=hooks)


def test_dag_dependencies():
    """Verificar que las dependencias del DAG son consistentes."""
    for phase, deps in DAG_DEPS.items():
        assert 1 <= phase <= 10
        for dep in deps:
            assert 1 <= dep <= 10
            assert dep < phase  # Deps must be earlier phases


def test_phase_names_complete():
    """Verificar que todos los 10 fases tienen nombre."""
    assert len(PHASE_NAMES) == 10
    for i in range(1, 11):
        assert i in PHASE_NAMES


def test_orchestrator_init(orchestrator):
    """Verificar que el orchestrator se inicializa correctamente."""
    assert orchestrator._config is not None
    assert orchestrator._bus is not None
    assert orchestrator._state is not None
    assert orchestrator._vigilante is not None
    assert orchestrator._hooks is not None
    assert orchestrator._results == {}
    assert orchestrator._context == {}
    assert orchestrator._running is False


def test_orchestrator_build_report(orchestrator):
    """Verificar que _build_report genera un reporte válido."""
    from modules.base_module import ModuleResult, Finding, Severity, Phase

    # Crear un resultado mock
    result = ModuleResult(
        module_name="test_module",
        phase=Phase.RECON,
        target="example.com",
    )
    result.add_finding(
        type="test_finding",
        value="test_value",
        severity=Severity.HIGH,
        confidence=0.9,
    )
    orchestrator._results["test_module"] = result

    report = orchestrator._build_report("example.com")
    assert report["target"] == "example.com"
    assert report["total_findings"] == 1
    assert "HIGH" in report["severity_counts"]
    assert report["severity_counts"]["HIGH"] == 1


@pytest.mark.asyncio
async def test_orchestrator_stop(orchestrator):
    """Verificar que stop() detiene el orchestrator."""
    orchestrator._running = True
    orchestrator.stop()
    assert orchestrator._running is False
