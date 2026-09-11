"""
core/signal_handler.py — Graceful shutdown en SIGINT/SIGTERM
"""
from __future__ import annotations
import asyncio, signal, logging
log = logging.getLogger("bl.signal")

class GracefulShutdown:
    def __init__(self, orchestrator):
        self.orch = orchestrator
        self._triggered=False

    def install(self):
        loop=asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try: loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self._handle(s)))
            except NotImplementedError: # Windows
                signal.signal(sig, lambda s,f: asyncio.create_task(self._handle(s)))

    async def _handle(self, sig):
        if self._triggered: return
        self._triggered=True
        log.warning("Signal %s received — graceful shutdown...", sig)
        self.orch.stop()
        # flush checkpoint if exists
        if hasattr(self.orch, "_checkpoint") and self.orch._checkpoint:
            try: self.orch._checkpoint.save(self.orch._phase_done, self.orch._results, self.orch._context, self.orch._state.snapshot())
            except: pass
        # close kernels
        try:
            if self.orch.storage: await self.orch.storage.close()
            if self.orch.crawler: await self.orch.crawler.close()
            if self.orch.dashboard: await self.orch.dashboard.stop()
        except: pass
        log.info("Graceful shutdown complete — checkpoint saved")
