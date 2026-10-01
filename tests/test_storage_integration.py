"""Tests de integración de storage (K3 ImmortalStorage)."""
from __future__ import annotations
import asyncio
import json
import pytest
from pathlib import Path
from bl_config import BLConfig
from modules.base_module import ModuleResult, Finding, Severity, Phase


@pytest.fixture
def config(tmp_path):
    cfg = BLConfig()
    cfg.storage.sqlite_path = tmp_path / "test.db"
    cfg.storage.duckdb_path = tmp_path / "test.duckdb"
    return cfg


@pytest.fixture
def sample_result():
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
        metadata={"key": "value"},
        tags=["test"],
    )
    result.risk_score = 5.0
    result.execution_time = 1.5
    return result


@pytest.mark.asyncio
async def test_storage_init(config):
    """Test storage initialization."""
    from kernels.k3_immortal_storage.storage import ImmortalStorage
    storage = ImmortalStorage(config)
    await storage.init()
    assert storage._conn is not None
    assert storage._duck is not None
    await storage.close()


@pytest.mark.asyncio
async def test_storage_scan_lifecycle(config):
    """Test scan create and close."""
    from kernels.k3_immortal_storage.storage import ImmortalStorage
    storage = ImmortalStorage(config)
    await storage.init()

    await storage.create_scan("test_scan_1", "example.com")
    assert storage._scan_id == "test_scan_1"

    await storage.close_scan("test_scan_1", 7.5)

    # Sync to DuckDB before querying
    await asyncio.get_event_loop().run_in_executor(None, storage._sync_to_duckdb)

    # Verify scan was created
    rows = await storage.query("SELECT * FROM scans WHERE id = 'test_scan_1'")
    assert len(rows) == 1
    assert rows[0]["target"] == "example.com"
    assert rows[0]["risk_score"] == 7.5

    await storage.close()


@pytest.mark.asyncio
async def test_storage_save_module_result(config, sample_result):
    """Test saving module results."""
    from kernels.k3_immortal_storage.storage import ImmortalStorage
    storage = ImmortalStorage(config)
    await storage.init()

    await storage.create_scan("test_scan_2", "example.com")
    await storage.save_module_result(sample_result)

    # Sync to DuckDB before querying
    await asyncio.get_event_loop().run_in_executor(None, storage._sync_to_duckdb)

    # Verify findings were saved
    rows = await storage.query("SELECT * FROM findings WHERE scan_id = 'test_scan_2'")
    assert len(rows) == 1
    assert rows[0]["type"] == "test_finding"
    assert rows[0]["value"] == "test_value"
    assert rows[0]["severity"] == "HIGH"

    await storage.close()


@pytest.mark.asyncio
async def test_storage_idempotency(config, sample_result):
    """Test that saving same result twice doesn't duplicate."""
    from kernels.k3_immortal_storage.storage import ImmortalStorage
    storage = ImmortalStorage(config)
    await storage.init()

    await storage.create_scan("test_scan_3", "example.com")
    await storage.save_module_result(sample_result)
    await storage.save_module_result(sample_result)  # Duplicate

    # Sync to DuckDB before querying
    await asyncio.get_event_loop().run_in_executor(None, storage._sync_to_duckdb)

    # Should only have 1 finding due to unique index
    rows = await storage.query("SELECT * FROM findings WHERE scan_id = 'test_scan_3'")
    assert len(rows) == 1

    await storage.close()


@pytest.mark.asyncio
async def test_storage_duckdb_sync(config, sample_result):
    """Test DuckDB sync."""
    from kernels.k3_immortal_storage.storage import ImmortalStorage
    storage = ImmortalStorage(config)
    await storage.init()

    await storage.create_scan("test_scan_4", "example.com")
    await storage.save_module_result(sample_result)

    # Force sync
    await asyncio.get_event_loop().run_in_executor(None, storage._sync_to_duckdb)

    # Query DuckDB
    rows = await storage.query("SELECT * FROM findings")
    assert len(rows) >= 1

    await storage.close()


@pytest.mark.asyncio
async def test_storage_search(config, sample_result):
    """Test search functionality."""
    from kernels.k3_immortal_storage.storage import ImmortalStorage
    storage = ImmortalStorage(config)
    await storage.init()

    await storage.create_scan("test_scan_5", "example.com")
    await storage.save_module_result(sample_result)

    # Sync to DuckDB before querying
    await asyncio.get_event_loop().run_in_executor(None, storage._sync_to_duckdb)

    # Search by type
    rows = await storage.search_findings(type_filter="test_finding")
    assert len(rows) == 1

    # Search by severity
    rows = await storage.search_findings(severity_filter="HIGH")
    assert len(rows) == 1

    # Search by value contains
    rows = await storage.search_findings(value_contains="test_value")
    assert len(rows) == 1

    await storage.close()


@pytest.mark.asyncio
async def test_storage_close_flushes_duckdb(config, sample_result):
    """Test that close() flushes DuckDB."""
    from kernels.k3_immortal_storage.storage import ImmortalStorage
    storage = ImmortalStorage(config)
    await storage.init()

    await storage.create_scan("test_scan_6", "example.com")
    await storage.save_module_result(sample_result)

    # Close should flush DuckDB
    await storage.close()

    # Reopen and verify data persisted in DuckDB
    storage2 = ImmortalStorage(config)
    await storage2.init()
    rows = await storage2.query("SELECT * FROM findings")
    assert len(rows) >= 1
    await storage2.close()
