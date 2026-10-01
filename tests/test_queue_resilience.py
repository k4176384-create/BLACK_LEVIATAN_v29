"""Tests de resiliencia de queue, DLQ, circuit breaker."""
from __future__ import annotations
import asyncio
import pytest
from core.queue import RetryQueue, PersistentDLQ, QueuedTask, TaskStatus


class TestRetryQueue:
    """Tests de RetryQueue."""

    @pytest.mark.asyncio
    async def test_enqueue_dequeue(self):
        q = RetryQueue()
        task = QueuedTask(
            priority=0,
            task_id="test_1",
            module="test_module",
            phase=1,
            target="example.com",
        )
        await q.enqueue(task)
        assert q.stats["enqueued"] == 1
        assert q.stats["queue_size"] == 1

        dequeued = await q.dequeue()
        assert dequeued is not None
        assert dequeued.task_id == "test_1"

    @pytest.mark.asyncio
    async def test_queue_overflow(self):
        q = RetryQueue(max_size=2)
        for i in range(3):
            await q.enqueue(QueuedTask(
                priority=0,
                task_id=f"task_{i}",
                module="test",
                phase=1,
                target="x",
            ))
        assert q.stats["enqueued"] == 2  # Third was dropped

    def test_mark_retry(self):
        q = RetryQueue()
        task = QueuedTask(
            priority=0,
            task_id="test_1",
            module="test",
            phase=1,
            target="x",
            max_retries=2,
        )
        q.mark_retry(task, "error 1")
        assert task.attempts == 1
        assert task.status == TaskStatus.RETRY

        q.mark_retry(task, "error 2")
        assert task.attempts == 2
        assert task.status == TaskStatus.DLQ
        assert len(q.dlq) == 1

    def test_mark_done(self):
        q = RetryQueue()
        task = QueuedTask(
            priority=0,
            task_id="test_1",
            module="test",
            phase=1,
            target="x",
        )
        q.mark_done(task)
        assert q.stats["completed"] == 1


class TestPersistentDLQ:
    """Tests de PersistentDLQ."""

    def test_store_and_list(self, tmp_path):
        db_path = str(tmp_path / "test_dlq.db")
        dlq = PersistentDLQ(db_path)
        task = QueuedTask(
            priority=0,
            task_id="test_1",
            module="test_module",
            phase=1,
            target="example.com",
            last_error="Test error",
            attempts=3,
        )
        dlq.store(task)
        items = dlq.list()
        assert len(items) == 1
        assert items[0]["id"] == "test_1"
        assert items[0]["module"] == "test_module"

    def test_dlq_persistence(self, tmp_path):
        db_path = str(tmp_path / "test_dlq.db")
        dlq1 = PersistentDLQ(db_path)
        task = QueuedTask(
            priority=0,
            task_id="test_1",
            module="test",
            phase=1,
            target="x",
        )
        dlq1.store(task)

        # New instance should see the data
        dlq2 = PersistentDLQ(db_path)
        items = dlq2.list()
        assert len(items) == 1


class TestCircuitBreaker:
    """Tests de Circuit Breaker."""

    def test_circuit_breaker_basic(self):
        from core.vigilante_v2 import CircuitBreaker, CBState
        cb = CircuitBreaker(name="test", failure_threshold=3, timeout=1.0)
        assert cb.state == CBState.CLOSED
        assert not cb.is_open

        # Record failures
        for _ in range(3):
            cb.record_failure("test error")
        assert cb.state == CBState.OPEN
        assert cb.is_open

    def test_circuit_breaker_recovery(self):
        from core.vigilante_v2 import CircuitBreaker, CBState
        cb = CircuitBreaker(name="test", failure_threshold=2, success_threshold=2, timeout=0.1)
        # Open the circuit
        cb.record_failure("error")
        cb.record_failure("error")
        assert cb.state == CBState.OPEN

        # Wait for timeout
        import time
        time.sleep(0.15)

        # Should be half-open now
        assert not cb.is_open  # is_open returns False when transitioning to HALF_OPEN

        # Record successes to close
        cb.record_success()
        cb.record_success()
        assert cb.state == CBState.CLOSED

    def test_circuit_breaker_success_resets(self):
        from core.vigilante_v2 import CircuitBreaker, CBState
        cb = CircuitBreaker(name="test", failure_threshold=3)
        cb.record_failure("error")
        cb.record_failure("error")
        assert cb._failures == 2
        cb.record_success()
        assert cb._failures == 1


class TestBackpressureManager:
    """Tests de BackpressureManager."""

    def test_retry_after_parsing(self):
        from core.vigilante_v2 import BackpressureManager
        bpm = BackpressureManager()

        # Numeric Retry-After
        assert bpm.parse_retry_after({"Retry-After": "30"}) == 30.0

        # No header
        assert bpm.parse_retry_after({}) is None

        # Invalid header
        assert bpm.parse_retry_after({"Retry-After": "invalid"}) is None

    @pytest.mark.asyncio
    async def test_host_penalization(self):
        from core.vigilante_v2 import BackpressureManager
        bpm = BackpressureManager(base_delay=0.1)
        bpm.record_response(429, host="blocked.example.com")
        assert "blocked.example.com" in bpm._host_delays
