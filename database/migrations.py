"""database/migrations.py — SQL schema helpers para SQLite WAL."""
from __future__ import annotations
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT    NOT NULL,
    started_at  TEXT    NOT NULL,
    finished_at TEXT,
    total_risk  REAL    DEFAULT 0.0,
    phases_run  TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    module_name TEXT    NOT NULL,
    phase       INTEGER NOT NULL,
    type        TEXT    NOT NULL,
    value       TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    confidence  REAL    DEFAULT 0.0,
    metadata    TEXT,
    tags        TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS module_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    module_name    TEXT    NOT NULL,
    phase          INTEGER NOT NULL,
    status         TEXT    DEFAULT 'pending',
    execution_time REAL,
    risk_score     REAL    DEFAULT 0.0,
    errors         TEXT,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_scan     ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_type     ON findings(type);
CREATE INDEX IF NOT EXISTS idx_module_runs_scan  ON module_runs(scan_id);
"""


def init_db(db_path: str | Path) -> sqlite3.Connection:
    """Inicializa la base de datos con el schema completo."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn
