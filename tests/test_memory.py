import asyncio
from core.queue import RetryQueue, QueuedTask

def test_queue_overflow():
    import asyncio
    q = RetryQueue(max_size=2)
    # Fill
    async def run():
        await q.enqueue(QueuedTask(priority=0, task_id="1", module="a", phase=1, target="x"))
        await q.enqueue(QueuedTask(priority=0, task_id="2", module="a", phase=1, target="x"))
        # third should not crash, just drop with log
        await q.enqueue(QueuedTask(priority=0, task_id="3", module="a", phase=1, target="x"))
        assert q.stats["enqueued"]==2
    asyncio.run(run())

def test_dlq_transition():
    q = RetryQueue()
    t = QueuedTask(priority=0, task_id="1", module="a", phase=1, target="x", max_retries=1)
    import asyncio
    async def run():
        q.mark_retry(t, "error")
        assert len(q.dlq)==1
    asyncio.run(run())

# Memory guard: check config limits
def test_config_limits():
    from bl_config import BLConfig
    c = BLConfig()
    assert c.dag.max_memory_mb >0
    assert c.dag.max_queue_size >0
