"""
core/checkpoint.py — Persistencia de estado para resume/pause/cancel
Soporta SIGKILL/OOM via WAL atomic writes.
"""
from __future__ import annotations
import asyncio, json, time, os
from pathlib import Path
from typing import Any, Optional
import logging
log = logging.getLogger("bl.checkpoint")

class CheckpointManager:
    def __init__(self, base_dir: Path = Path("data/checkpoints")):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.job_id: str = ""
        self._ckpt_path: Optional[Path] = None

    def new_job(self, target: str) -> str:
        import uuid
        self.job_id = str(uuid.uuid4())[:8]
        self._ckpt_path = self.base_dir / f"ckpt_{self.job_id}.json"
        data = {"job_id": self.job_id, "target": target, "created_at": time.time(), "phase_done": [], "results": {}, "context": {}}
        self._atomic_write(data)
        return self.job_id

    def load(self, job_id: str) -> Optional[dict]:
        p = self.base_dir / f"ckpt_{job_id}.json"
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text())
        except Exception as e:
            log.error("Checkpoint load %s: %s", job_id, e)
            return None

    def _atomic_write(self, data: dict):
        if not self._ckpt_path:
            return
        tmp = self._ckpt_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, default=str))
        try:
            with open(tmp, "r") as f:
                os.fsync(f.fileno())
        except: pass
        tmp.replace(self._ckpt_path)
        try:
            fd = os.open(str(self.base_dir), os.O_DIRECTORY)
            os.fsync(fd); os.close(fd)
        except Exception:
            pass

    def save(self, phase_done: set[int], results: dict, context: dict, scan_meta: dict):
        if not self._ckpt_path:
            return
        data = {
            "job_id": self.job_id,
            "updated_at": time.time(),
            "phase_done": sorted(phase_done),
            "results": {k: v.to_dict() if hasattr(v, "to_dict") else v for k,v in results.items()},
            "context": context,
            "scan_meta": scan_meta,
        }
        try:
            self._atomic_write(data)
        except Exception as e:
            log.error("Checkpoint save failed: %s", e)

    def list_jobs(self) -> list[dict]:
        out=[]
        for p in self.base_dir.glob("ckpt_*.json"):
            try:
                d=json.loads(p.read_text())
                out.append({"job_id": d.get("job_id"), "target": d.get("target"), "updated_at": d.get("updated_at")})
            except: pass
        return out

    def delete(self, job_id: str):
        p=self.base_dir / f"ckpt_{job_id}.json"
        if p.exists(): p.unlink()
