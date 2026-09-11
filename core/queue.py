"""
core/queue.py — PriorityQueue + RetryQueue + DeadLetterQueue para OSINT
"""
from __future__ import annotations
import asyncio, time, json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
import logging
log = logging.getLogger("bl.queue")

class TaskStatus(Enum):
    PENDING="pending"; RUNNING="running"; RETRY="retry"; FAILED="failed"; DONE="done"; DLQ="dlq"

@dataclass(order=True)
class QueuedTask:
    priority: int
    task_id: str = field(compare=False)
    module: str = field(compare=False)
    phase: int = field(compare=False)
    target: str = field(compare=False)
    attempts: int = field(default=0, compare=False)
    max_retries: int = field(default=3, compare=False)
    created_at: float = field(default_factory=time.time, compare=False)
    last_error: str = field(default="", compare=False)
    status: TaskStatus = field(default=TaskStatus.PENDING, compare=False)

class RetryQueue:
    def __init__(self, max_size: int = 5000):
        self._q: asyncio.PriorityQueue[QueuedTask] = asyncio.PriorityQueue(maxsize=max_size)
        self._dlq: list[QueuedTask] = []
        self._stats = {"enqueued":0, "retried":0, "dlq":0, "completed":0}

    async def enqueue(self, task: QueuedTask):
        try: self._q.put_nowait(task); self._stats["enqueued"]+=1
        except asyncio.QueueFull: log.warning("RetryQueue full, dropping %s", task.task_id)

    async def dequeue(self) -> Optional[QueuedTask]:
        try: return await asyncio.wait_for(self._q.get(), timeout=0.1)
        except asyncio.TimeoutError: return None

    def mark_retry(self, task: QueuedTask, error: str):
        task.attempts+=1; task.last_error=error
        if task.attempts >= task.max_retries:
            task.status=TaskStatus.DLQ; self._dlq.append(task); self._stats["dlq"]+=1
            log.warning("Task %s → DLQ after %d attempts: %s", task.task_id, task.attempts, error)
        else:
            task.status=TaskStatus.RETRY; task.priority+=10 # lower priority on retry
            try: self._q.put_nowait(task); self._stats["retried"]+=1
            except asyncio.QueueFull: self._dlq.append(task)

    def mark_done(self, task: QueuedTask):
        self._stats["completed"]+=1

    @property
    def dlq(self) -> list[QueuedTask]: return list(self._dlq)
    @property
    def stats(self) -> dict:
        return {**self._stats, "queue_size": self._q.qsize(), "dlq_size": len(self._dlq)}

# ── Dead Letter Queue persistente (SQLite) ───────────────────────
class PersistentDLQ:
    def __init__(self, db_path: str = "data/dlq.db"):
        self.db_path=db_path
        import sqlite3, pathlib
        p=pathlib.Path(db_path); p.parent.mkdir(parents=True, exist_ok=True)
        self.conn=sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("""CREATE TABLE IF NOT EXISTS dlq (
            id TEXT PRIMARY KEY, module TEXT, phase INTEGER, target TEXT,
            error TEXT, attempts INTEGER, ts REAL, payload TEXT)""")
        self.conn.commit()
    def store(self, task: QueuedTask):
        import json
        self.conn.execute("INSERT OR REPLACE INTO dlq VALUES (?,?,?,?,?,?,?,?)",
            (task.task_id, task.module, task.phase, task.target, task.last_error, task.attempts, time.time(), json.dumps(task.__dict__, default=str)))
        self.conn.commit()
    def list(self, limit=50):
        cur=self.conn.execute("SELECT * FROM dlq ORDER BY ts DESC LIMIT ?", (limit,))
        cols=[d[0] for d in cur.description]
        return [dict(zip(cols,r)) for r in cur.fetchall()]
