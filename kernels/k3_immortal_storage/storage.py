"""
kernels/k3_immortal_storage/storage.py — SQLite WAL + DuckDB OLAP
Autor: Luis Sánchez — BLACK LEVIATAN v29

Arquitectura dual:
  - SQLite WAL: persistencia transaccional en tiempo real (eventos, findings)
  - DuckDB: queries analíticas complejas sobre millones de filas sin freezing
  - Sync automático SQLite → DuckDB cada N segundos (configurable)
"""
from __future__ import annotations
import asyncio
import json
import logging
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING

import duckdb

if TYPE_CHECKING:
    from bl_config import BLConfig
    from modules.base_module import ModuleResult

log = logging.getLogger("bl.k3")

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=-64000;

CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    started_at  REAL NOT NULL,
    ended_at    REAL,
    status      TEXT DEFAULT 'running',
    risk_score  REAL DEFAULT 0,
    metadata    TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS module_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL,
    module_name TEXT NOT NULL,
    phase       INTEGER NOT NULL,
    target      TEXT NOT NULL,
    risk_score  REAL DEFAULT 0,
    exec_time   REAL DEFAULT 0,
    skipped     INTEGER DEFAULT 0,
    skip_reason TEXT DEFAULT '',
    metadata    TEXT DEFAULT '{}',
    errors      TEXT DEFAULT '[]',
    created_at  REAL DEFAULT (unixepoch('now')),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL,
    module_name TEXT NOT NULL,
    phase       INTEGER NOT NULL,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    confidence  REAL DEFAULT 1.0,
    metadata    TEXT DEFAULT '{}',
    tags        TEXT DEFAULT '[]',
    timestamp   REAL DEFAULT (unixepoch('now')),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT,
    topic       TEXT NOT NULL,
    data        TEXT NOT NULL,
    ts          REAL DEFAULT (unixepoch('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_scan  ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev   ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_type  ON findings(type);
CREATE INDEX IF NOT EXISTS idx_events_topic   ON events(topic);
"""


class ImmortalStorage:
    """
    K3: Almacenamiento dual. API async-first con acceso síncrono
    interno a SQLite (thread executor) y DuckDB para analytics.
    """

    def __init__(self, config: "BLConfig") -> None:
        self._config       = config
        self._sqlite_path  = config.storage.sqlite_path
        self._duckdb_path  = config.storage.duckdb_path
        self._conn:  Optional[sqlite3.Connection] = None
        self._duck:  Optional[duckdb.DuckDBPyConnection] = None
        self._scan_id:     str  = ""
        self._sync_task:   Optional[asyncio.Task] = None
        self._insert_queue: asyncio.Queue = asyncio.Queue(maxsize=10_000)

    # ── Inicialización ────────────────────────
    async def init(self) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._init_sqlite)
        await loop.run_in_executor(None, self._init_duckdb)
        self._sync_task = asyncio.create_task(self._sync_loop(), name="k3_sync")
        asyncio.create_task(self._flush_loop(), name="k3_flush")
        log.info("K3 Storage inicializado: SQLite WAL + DuckDB")

    def _init_sqlite(self) -> None:
        import threading
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            str(self._sqlite_path),
            check_same_thread=False,
            isolation_level=None,   # autocommit
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA_SQL)
        # Dedup index: prevent duplicate findings on re-run (idempotent)
        try:
            self._conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup ON findings(scan_id, type, value)")
        except: pass
        # Dedup module_results: clean stale duplicates before creating unique index
        try:
            self._conn.execute("""
                DELETE FROM module_results WHERE rowid NOT IN (
                    SELECT MIN(rowid) FROM module_results GROUP BY scan_id, module_name
                )
            """)
            self._conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_module_results_dedup ON module_results(scan_id, module_name)")
        except: pass
        self._conn.commit()

    def _init_duckdb(self) -> None:
        self._duck = duckdb.connect(str(self._duckdb_path))

    # ── Scan lifecycle ────────────────────────
    async def create_scan(self, scan_id: str, target: str) -> None:
        self._scan_id = scan_id
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._insert_scan, scan_id, target)

    def _insert_scan(self, scan_id: str, target: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO scans(id, target, started_at) VALUES(?,?,?)",
            (scan_id, target, time.time())
        )

    async def close_scan(self, scan_id: str, risk_score: float) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._update_scan, scan_id, risk_score)

    def _update_scan(self, scan_id: str, risk_score: float) -> None:
        self._conn.execute(
            "UPDATE scans SET ended_at=?, status='done', risk_score=? WHERE id=?",
            (time.time(), risk_score, scan_id)
        )

    # ── Guardar resultados de módulos ─────────
    async def save_module_result(self, result: "ModuleResult") -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._save_result_sync, result)

    def _save_result_sync(self, result: "ModuleResult") -> None:
        if not self._conn:
            return
        # Thread-safe + idempotent via UNIQUE index
        with self._lock:
            # Use transaction for atomicity
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    """INSERT OR IGNORE INTO module_results
                       (scan_id, module_name, phase, target, risk_score, exec_time,
                        skipped, skip_reason, metadata, errors)
                       VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (
                        self._scan_id,
                        result.module_name,
                        int(result.phase),
                        result.target,
                        result.risk_score,
                        result.execution_time,
                        int(result.skipped),
                        result.skip_reason,
                        json.dumps(result.metadata),
                        json.dumps(result.errors),
                    )
                )
                for f in result.findings:
                    try:
                        self._conn.execute(
                            """INSERT OR IGNORE INTO findings
                               (scan_id, module_name, phase, type, value, severity,
                                confidence, metadata, tags, timestamp)
                               VALUES(?,?,?,?,?,?,?,?,?,?)""",
                            (
                                self._scan_id,
                                result.module_name,
                                int(result.phase),
                                f.type,
                                f.value,
                                f.severity.label,
                                f.confidence,
                                json.dumps(f.metadata),
                                json.dumps(f.tags),
                                f.timestamp,
                            )
                        )
                    except Exception as e:
                        log.debug("Insert finding ignore: %s", e)
                self._conn.commit()
            except Exception as e:
                self._conn.rollback()
                log.error("Save result tx failed: %s", e)

    # ── Queries analíticas (DuckDB) ────────────
    async def query(self, sql: str, params: list = None) -> list[dict]:
        """Ejecuta una query analítica en DuckDB. Soporta JOINs y aggregations."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._duck_query, sql, params or [])

    def _duck_query(self, sql: str, params: list) -> list[dict]:
        if not self._duck:
            return []
        try:
            if params:
                result = self._duck.execute(sql, params)
            else:
                result = self._duck.execute(sql)
            cols = [d[0] for d in result.description]
            return [dict(zip(cols, row)) for row in result.fetchall()]
        except Exception as exc:
            log.error("DuckDB query error: %s | SQL: %s", exc, sql[:200])
            return []

    async def get_findings_by_severity(self) -> dict[str, int]:
        rows = await self.query(
            "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
        )
        return {r["severity"]: r["cnt"] for r in rows}

    async def get_top_findings(self, limit: int = 20) -> list[dict]:
        return await self.query(
            """SELECT f.*, m.exec_time 
               FROM findings f 
               JOIN module_results m ON f.module_name = m.module_name
               WHERE f.severity IN ('CRITICAL','HIGH')
               ORDER BY f.timestamp DESC 
               LIMIT ?""",
            [limit]
        )

    async def search_findings(
        self,
        type_filter:     Optional[str] = None,
        severity_filter: Optional[str] = None,
        value_contains:  Optional[str] = None,
    ) -> list[dict]:
        conditions = []
        params = []
        if type_filter:
            conditions.append("type = ?")
            params.append(type_filter)
        if severity_filter:
            conditions.append("severity = ?")
            params.append(severity_filter)
        if value_contains:
            conditions.append("value LIKE ?")
            params.append(f"%{value_contains}%")
        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        return await self.query(f"SELECT * FROM findings {where} LIMIT 1000", params)

    # ── Sync SQLite → DuckDB ──────────────────
    async def _sync_loop(self) -> None:
        interval = self._config.storage.sync_interval
        while True:
            await asyncio.sleep(interval)
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self._sync_to_duckdb)
                log.debug("K3 sync: SQLite → DuckDB completado")
            except Exception as exc:
                log.error("K3 sync error: %s", exc)

    def _sync_to_duckdb(self) -> None:
        if not self._duck or not self._conn:
            return
        sqlite_path = str(self._sqlite_path)
        # DuckDB puede leer SQLite directamente
        try:
            self._duck.execute(f"ATTACH '{sqlite_path}' AS bl_sqlite (TYPE SQLITE)")
            for table in ["findings", "module_results", "scans"]:
                self._duck.execute(f"""
                    CREATE OR REPLACE TABLE {table} AS 
                    SELECT * FROM bl_sqlite.{table}
                """)
            self._duck.execute("DETACH bl_sqlite")
        except Exception as exc:
            log.debug("DuckDB sync alternativo: %s", exc)
            # Fallback: leer desde SQLite y escribir en DuckDB
            for table in ["findings", "module_results", "scans"]:
                rows = self._conn.execute(f"SELECT * FROM {table}").fetchall()
                if rows:
                    cols = [d[0] for d in self._conn.execute(
                        f"SELECT * FROM {table} LIMIT 0"
                    ).description]
                    self._duck.executemany(
                        f"INSERT OR REPLACE INTO {table} VALUES ({','.join(['?']*len(cols))})",
                        rows
                    )

    async def _flush_loop(self) -> None:
        """Vacía el queue de inserts en batches."""
        batch = []
        while True:
            try:
                item = await asyncio.wait_for(self._insert_queue.get(), timeout=0.5)
                batch.append(item)
            except asyncio.TimeoutError:
                pass
            if len(batch) >= 100:
                # Flush batch (futuro: bulk insert)
                batch.clear()

    # ── Cierre ────────────────────────────────
    async def close(self) -> None:
        if self._sync_task:
            self._sync_task.cancel()
        # Flush final SQLite → DuckDB antes de cerrar
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._sync_to_duckdb)
            log.debug("K3 flush final: SQLite → DuckDB completado")
        except Exception as exc:
            log.error("K3 flush final error: %s", exc)
        if self._conn:
            self._conn.close()
        if self._duck:
            self._duck.close()
        log.info("K3 Storage cerrado")
