"""Tests for the bounded output queues.

The behaviour the two queues share is tested once, with one body per scenario
that runs against `Outbox` and against `AsyncOutbox` (the ``make`` fixture).
The asyncio queue lives on an event loop in a helper thread of the test, and
the test's own threads call its ``put`` and ``take`` through the loop, so a
scenario can use plain threads for its producers and consumers. What is only
true of one class is tested at the end.

Timing tests use real threads and short real waits; every wait for another
thread has a bound, so a failure is a failed assertion and not a hang.
"""

from __future__ import annotations

import asyncio
import statistics
import threading
import time
from time import monotonic, perf_counter, sleep
from typing import TYPE_CHECKING

import pytest

from logprobe._aoutbox import AsyncOutbox
from logprobe._outbox import MARKER_BYTES, STALLED, TICK, Outbox

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

JOIN = 10.0  # bound for waiting on a thread in a test
SLICE_LIMIT = TICK + 0.25  # one time slice plus scheduling slack


def _spawn(target, *args) -> threading.Thread:
    thread = threading.Thread(target=target, args=args, daemon=True)
    thread.start()
    return thread


def _bounded_put(box, *args, **kwargs) -> object:
    """``box.put(*args, **kwargs)`` on a helper thread; fails instead of hanging.

    For a put that must return on its own (a limit or an interruption): when it
    is still waiting after `JOIN` seconds, the queue is killed to release the
    thread and the test fails.
    """
    results: list[object] = []
    thread = _spawn(lambda: results.append(box.put(*args, **kwargs)))
    thread.join(JOIN)
    if thread.is_alive():
        box.request_kill()
        thread.join(JOIN)
        pytest.fail(f"put still waiting after {JOIN} s")
    (result,) = results
    return result


def _until(predicate, limit: float = JOIN) -> None:
    end = monotonic() + limit
    while not predicate():
        assert monotonic() < end, "condition not reached in time"
        sleep(0.001)


class BlockingBox(Outbox):
    """`Outbox` with the few operations a scenario needs that differ by class."""

    def close(self) -> None:
        self.request_kill()

    def consumers_parked(self) -> int:
        """Consumers inside `take`'s wait now (CPython detail)."""
        return len(self._ready._waiters)  # ty: ignore[unresolved-attribute]

    def interrupt(self) -> None:
        with self._space:
            self.interrupt_waiters()

    def free_room_silently(self) -> None:
        """Empty the queue without waking the waiting producers."""
        with self._space:
            self._forget()

    def wake_producers(self) -> None:
        with self._space:
            self._wake_producers()


class LoopBox:
    """`AsyncOutbox` on an event loop in a helper thread, with a blocking face.

    ``put`` and ``take`` run on the loop and wait for the result; every other
    call that touches the queue's state runs on the loop too, as the real
    users of the queue do. Only the two flag setters are called from the
    calling thread, as their contract allows.
    """

    def __init__(self, max_lines: int, max_bytes: int, *, tick: float = TICK) -> None:
        self.box = AsyncOutbox(max_lines, max_bytes, tick=tick)
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self._thread.start()

    def _on_loop[T](self, call: Callable[[], T]) -> T:
        async def run() -> T:
            return call()

        return asyncio.run_coroutine_threadsafe(run(), self.loop).result(JOIN)

    def close(self) -> None:
        self.box.request_kill()
        if not self.loop.is_closed():
            self.loop.call_soon_threadsafe(self.loop.stop)
            self._thread.join(JOIN)
            self.loop.close()

    def put(self, segments, charge, producer=None, *, interruptible=False, limit=None):
        coroutine = self.box.put(
            segments, charge, producer, interruptible=interruptible, limit=limit
        )
        return asyncio.run_coroutine_threadsafe(coroutine, self.loop).result()

    def wait_half_empty(self, producer):
        coroutine = self.box.wait_half_empty(producer)
        return asyncio.run_coroutine_threadsafe(coroutine, self.loop).result()

    def take(self, timeout=None):
        return asyncio.run_coroutine_threadsafe(
            self.box.take(timeout), self.loop
        ).result()

    def backpressure(self):
        return self._on_loop(self.box.backpressure)

    def clear(self) -> None:
        self._on_loop(self.box.clear)

    def consumers_parked(self) -> int:
        return self._on_loop(lambda: len(self.box._ready._futures))

    def interrupt(self) -> None:
        self._on_loop(self.box.interrupt_waiters)

    def free_room_silently(self) -> None:
        self._on_loop(self.box._forget)

    def wake_producers(self) -> None:
        self._on_loop(self.box._wake_producers)

    def __getattr__(self, name):
        return getattr(self.box, name)


@pytest.fixture(params=["blocking", "async"])
def make(request: pytest.FixtureRequest) -> Iterator[Callable[..., Outbox | LoopBox]]:
    """Build a queue of the class under test; async queues are closed at the end."""
    made: list[LoopBox] = []

    def build(max_lines: int, max_bytes: int, *, tick: float = TICK):
        if request.param == "blocking":
            return BlockingBox(max_lines, max_bytes, tick=tick)
        box = LoopBox(max_lines, max_bytes, tick=tick)
        made.append(box)
        return box

    yield build
    for box in made:
        box.close()


def _consumer_parked(box) -> bool:
    """Whether a consumer is inside `take`'s wait."""
    return box.consumers_parked() == 1


def _chunk(n: int, tag: object = 0) -> list[object]:
    return [[(tag, i) for i in range(n)]]


class TestLimits:
    def test_rejects_bad_arguments(self, make):
        with pytest.raises(TypeError):
            make(1.5, 1)
        with pytest.raises(TypeError):
            make(1, True)  # noqa: FBT003
        with pytest.raises(ValueError, match="max_lines"):
            make(0, 1)
        with pytest.raises(ValueError, match="max_bytes"):
            make(1, 0)
        with pytest.raises(ValueError, match="tick"):
            make(1, 1, tick=0)

    def test_admits_below_caps_without_waiting(self, make):
        box = make(10, 1000)
        assert box.put(_chunk(4), 40) == 0.0
        assert (box.pending_lines, box.pending_bytes) == (4, 40)
        assert box.put(_chunk(4), 40) == 0.0
        assert (box.pending_lines, box.pending_bytes) == (8, 80)

    def test_a_chunk_larger_than_the_caps_is_admitted_when_empty(self, make):
        box = make(1, 1)
        waits: list[float] = []
        thread = _spawn(lambda: waits.append(box.put(_chunk(100), 5000)))
        thread.join(JOIN)
        try:
            assert not thread.is_alive()
            assert waits == [0.0]
            assert box.pending_lines == 100
            assert box.take(0) is not None
        finally:
            box.request_kill()

    def test_crossing_a_cap_admits_the_whole_chunk_then_blocks(self, make):
        box = make(10, 10_000)
        thread = _spawn(self._fill, box)
        thread.join(JOIN)
        try:
            assert not thread.is_alive()
            assert box.pending_lines == 18
            blocked = _spawn(box.put, _chunk(1), 1)
            _until(lambda: box.waiting == 1)
            assert box.take(0) is not None  # 9 left: below the cap
            blocked.join(JOIN)
            assert not blocked.is_alive()
        finally:
            box.request_kill()

    @staticmethod
    def _fill(box: Outbox) -> None:
        box.put(_chunk(9), 90)  # below the cap
        box.put(_chunk(9), 90)  # still below before it goes in: admitted whole

    def test_byte_cap_blocks_independently_of_lines(self, make):
        box = make(1000, 100)
        box.put(_chunk(1), 100)
        thread = _spawn(box.put, _chunk(1), 1)
        _until(lambda: box.waiting == 1)
        assert box.pending_lines == 1  # the line cap is far away
        assert box.take(0) is not None
        thread.join(JOIN)
        assert not thread.is_alive()

    def test_markers_count_one_line_and_a_fixed_charge(self, make):
        box = make(10, 10_000)
        box.put([[1, 2, 3], "gap", "end"], 30)
        assert box.pending_lines == 5
        assert box.pending_bytes == 30 + 2 * MARKER_BYTES

    def test_empty_chunk_is_not_queued(self, make):
        for segments in ([], [[]], [[], []]):
            for charge in (0, 100):
                # A fresh box per case: if an empty chunk were queued, the
                # next put on a shared box would block and hang the test
                # instead of failing it.
                box = make(1, 1)
                assert box.put(segments, charge) == 0.0
                assert (box.pending_lines, box.pending_bytes) == (0, 0)
                assert box.take(0) is None

    def test_overshoot_is_less_than_one_chunk_per_admission(self, make):
        box = make(10, 1_000_000, tick=0.01)
        size = 7
        peak = 0
        done = threading.Event()

        def producer(tag):
            nonlocal peak
            for _ in range(200):
                box.put(_chunk(size, tag), size)
                peak = max(peak, box.pending_lines)

        threads = [_spawn(producer, tag) for tag in range(3)]

        def consume():
            while not done.is_set():
                box.take(0.01)

        consumer = _spawn(consume)
        for thread in threads:
            thread.join(JOIN * 3)
            assert not thread.is_alive()
        done.set()
        consumer.join(JOIN)
        assert peak < box.max_lines + size

    def test_counts_return_to_zero(self, make):
        box = make(50, 5000)
        for _ in range(3):
            box.put([[1, 2], "gap"], 20)
        while box.take(0) is not None:
            pass
        assert (box.pending_lines, box.pending_bytes) == (0, 0)


class TestChunks:
    def test_take_returns_whole_chunks_in_order(self, make):
        box = make(100, 10_000)
        first = [[1, 2, 3], "gap", [4]]
        second = [[5]]
        box.put(first, 10)
        box.put(second, 10)
        assert box.take(0) is first
        assert box.take(0) is second
        assert box.take(0) is None

    def test_take_times_out(self, make):
        box = make(1, 1)
        start = monotonic()
        assert box.take(0.05) is None
        assert 0.04 < monotonic() - start < 0.05 + SLICE_LIMIT

    def test_take_wakes_when_a_chunk_arrives(self, make):
        box = make(10, 100, tick=10)  # only a notify can wake it in time
        got = []
        thread = _spawn(lambda: got.append(box.take(JOIN)))
        _until(lambda: _consumer_parked(box))
        start = monotonic()
        box.put([[1]], 1)
        thread.join(JOIN)
        assert got == [[[1]]]
        assert monotonic() - start < 2.0

    def test_take_wakes_a_waiting_producer(self, make):
        box = make(1, 100, tick=10)  # only a notify can wake it in time
        box.put(_chunk(1), 1)
        thread = _spawn(box.put, _chunk(1), 1)
        _until(lambda: box.waiting == 1)
        start = monotonic()
        assert box.take(0) is not None
        thread.join(JOIN)
        assert not thread.is_alive()
        assert monotonic() - start < 2.0


class TestInterrupt:
    def test_an_interrupted_put_returns_none_and_queues_nothing(self, make):
        box = make(1, 100, tick=10)  # only the interruption can wake it in time
        box.put(_chunk(1), 1)
        results: list[float | None] = []
        thread = _spawn(
            lambda: results.append(box.put(_chunk(1), 1, "p", interruptible=True))
        )
        _until(lambda: box.waiting == 1)
        box.interrupt()
        thread.join(JOIN)
        assert results == [None]
        assert box.pending_lines == 1
        assert box.waiting == 0
        assert box.backpressure()["p"] > 0  # the wait so far is kept
        # an interruptible put that must wait does not, and a plain put still does
        assert box.put(_chunk(1), 1, "p", interruptible=True) is None
        plain = _spawn(box.put, _chunk(1), 1)
        _until(lambda: box.waiting == 1)
        assert box.take(0) is not None
        plain.join(JOIN)
        assert not plain.is_alive()


class TestStallLimit:
    def test_a_put_past_its_limit_returns_stalled_queues_nothing_and_counts_the_wait(
        self, make
    ):
        box = make(1, 10_000)
        box.put(_chunk(1, "fill"), 1)
        began = perf_counter()
        assert _bounded_put(box, _chunk(1, "late"), 1, "p", limit=0.1) is STALLED
        assert 0.1 <= perf_counter() - began < 0.1 + SLICE_LIMIT
        assert (box.pending_lines, box.waiting) == (1, 0)
        assert box.backpressure()["p"] >= 0.1  # the wait is back-pressure
        chunk = box.take(0)
        assert chunk is not None
        assert chunk[0][0][0] == "fill"
        assert box.take(0) is None  # "late" was not queued
        assert box.put(_chunk(1, "next"), 1, "p", limit=0.1) == 0.0  # room: at once

    def test_a_put_admitted_within_its_limit_returns_its_wait(self, make):
        box = make(1, 10_000, tick=10)  # only the take can wake it in time
        box.put(_chunk(1), 1)
        results: list[object] = []
        thread = _spawn(
            lambda: results.append(box.put(_chunk(1, "w"), 1, "p", limit=JOIN))
        )
        _until(lambda: box.waiting == 1)
        box.take(0)
        thread.join(JOIN)
        (waited,) = results
        assert isinstance(waited, float)
        assert waited < JOIN
        assert box.pending_lines == 1

    @pytest.mark.parametrize("request_name", ["request_stop", "request_kill"])
    def test_stop_admits_and_kill_drops_before_the_limit(self, make, request_name):
        box = make(1, 10_000)
        box.put(_chunk(1, "fill"), 1)
        results: list[object] = []
        thread = _spawn(
            lambda: results.append(box.put(_chunk(1, "w"), 1, "p", limit=JOIN))
        )
        _until(lambda: box.waiting == 1)
        began = monotonic()
        getattr(box, request_name)()
        thread.join(JOIN)
        assert monotonic() - began < SLICE_LIMIT
        (result,) = results
        assert isinstance(result, float)  # neither STALLED nor None
        if request_name == "request_stop":
            assert box.pending_lines == 2
            # once stopping, even a limit that has passed admits at once
            assert box.put(_chunk(1, "x"), 1, "p", limit=0.0) == 0.0
            assert box.pending_lines == 3
        else:
            assert box.pending_lines == 0
            assert box.put(_chunk(1, "x"), 1, "p", limit=0.0) == 0.0
            assert box.pending_lines == 0

    def test_a_stop_admits_a_limited_put_behind_another_producer_in_turn(self, make):
        """A stopped put never stalls, even while another producer is first in line."""
        box = make(1, 10_000, tick=5.0)  # only a notify can wake a waiter in time
        box.put(_chunk(1, "fill"), 1)
        first: list[object] = []
        second: list[object] = []
        thread_a = _spawn(lambda: first.append(box.put(_chunk(1, "a"), 1, "a")))
        _until(lambda: box.waiting == 1)
        box.request_stop()  # sets a flag only: "a" stays parked in its slice
        # The limit has passed already, but a stop request is due as well.
        thread_b = _spawn(
            lambda: second.append(box.put(_chunk(1, "b"), 1, "b", limit=0.0))
        )
        _until(lambda: box.waiting == 2 or bool(second))
        assert second == []  # "b" waits for its turn instead of giving up
        box.wake_producers()
        thread_a.join(JOIN)
        thread_b.join(JOIN)
        assert [type(result) for result in (*first, *second)] == [float, float]
        tags = [chunk[0][0][0] for chunk in iter(lambda: box.take(0), None)]
        assert tags == ["fill", "a", "b"]

    def test_an_interruption_wins_over_the_limit(self, make):
        """A reader that must write a flush marker does that before it gives up."""
        box = make(1, 10_000, tick=10)
        box.put(_chunk(1), 1)
        box.interrupt()
        # The limit has passed already and the interruption is due as well.
        interrupted = _bounded_put(
            box, _chunk(1), 1, "p", interruptible=True, limit=0.0
        )
        assert interrupted is None
        # Without an interruption to honour, the same put gives up on its limit.
        assert _bounded_put(box, _chunk(1), 1, "p", limit=0.0) is STALLED
        assert (box.pending_lines, box.waiting) == (1, 0)


class TestHalfEmpty:
    def test_the_half_empty_wait_needs_both_counts_at_half(self, make):
        box = make(4, 1000, tick=10)  # only a take can wake the wait in time
        box.put(_chunk(1, "a"), 100)
        box.put(_chunk(1, "b"), 500)  # 2 lines (half), 600 bytes (above half)
        results: list[bool] = []
        waiter = _spawn(lambda: results.append(box.wait_half_empty("p")))
        _until(lambda: box.backpressure().get("p", 0.0) > 0.05)
        assert waiter.is_alive()
        box.take(0)  # 1 line, 500 bytes: both at half
        waiter.join(JOIN)
        assert results == [True]
        box.put(_chunk(2, "c"), 0)  # 3 lines (above half), 500 bytes (half)
        before = box.backpressure()["p"]
        waiter = _spawn(lambda: results.append(box.wait_half_empty("p")))
        _until(lambda: box.backpressure()["p"] > before + 0.05)
        assert waiter.is_alive()
        box.take(0)  # 2 lines, 0 bytes
        waiter.join(JOIN)
        assert results == [True, True]

    def test_the_half_empty_wait_holds_no_place_in_line(self, make):
        """Another device's reader is admitted as before while one waits for half."""
        box = make(4, 10_000, tick=10)
        box.put(_chunk(3, "fill"), 3)  # room left, but above half
        results: list[bool] = []
        waiter = _spawn(lambda: results.append(box.wait_half_empty("p")))
        _until(lambda: "p" in box.backpressure())
        assert box.waiting == 0
        assert box.put(_chunk(1, "other"), 1, "q") == 0.0  # in at once
        assert waiter.is_alive()
        box.take(0)  # 1 line left
        waiter.join(JOIN)
        assert results == [True]
        assert "q" not in box.backpressure()

    def test_an_interruption_does_not_end_the_half_empty_wait(self, make):
        """A flush request is handled after the reconnect, not by ending the wait."""
        box = make(2, 10_000, tick=10)
        box.put(_chunk(2), 2)
        results: list[bool] = []
        waiter = _spawn(lambda: results.append(box.wait_half_empty("p")))
        _until(lambda: "p" in box.backpressure())
        box.interrupt()
        before = box.backpressure()["p"]
        _until(lambda: box.backpressure()["p"] > before + 0.05)
        assert waiter.is_alive()
        box.take(0)
        waiter.join(JOIN)
        assert results == [True]

    def test_the_half_empty_wait_counts_as_backpressure_while_and_after(self, make):
        """A flush budget is not used up while a reader waits for half empty."""
        box = make(2, 10_000, tick=10)
        box.put(_chunk(2), 2)
        waiter = _spawn(box.wait_half_empty, "p")
        _until(lambda: "p" in box.backpressure())
        first = box.backpressure()["p"]
        _until(lambda: box.backpressure()["p"] > first + 0.05)  # a wait in progress
        box.take(0)
        waiter.join(JOIN)
        after = box.backpressure()["p"]
        assert after > first + 0.05
        assert box.backpressure()["p"] == after  # ended: it no longer grows

    @pytest.mark.parametrize("request_name", ["request_stop", "request_kill"])
    def test_the_half_empty_wait_ends_on_stop_or_kill_within_a_slice(
        self, make, request_name
    ):
        box = make(1, 10_000)
        box.put(_chunk(1), 1)
        results: list[bool] = []
        waiter = _spawn(lambda: results.append(box.wait_half_empty("p")))
        _until(lambda: "p" in box.backpressure())
        began = monotonic()
        getattr(box, request_name)()
        waiter.join(JOIN)
        assert monotonic() - began < SLICE_LIMIT
        assert results == [False]
        assert box.wait_half_empty("p") is False  # at once once stopping

    def test_take_wakes_the_half_empty_wait(self, make):
        box = make(2, 10_000, tick=10)  # no timed wake-up can help it in time
        box.put(_chunk(1), 1)
        box.put(_chunk(1), 1)
        results: list[bool] = []
        waiter = _spawn(lambda: results.append(box.wait_half_empty("p")))
        _until(lambda: "p" in box.backpressure())
        began = monotonic()
        box.take(0)
        waiter.join(JOIN)
        assert monotonic() - began < SLICE_LIMIT
        assert results == [True]


class TestFairness:
    def test_waiting_producers_are_admitted_in_arrival_order(self, make):
        box = make(1, 10_000)
        box.put(_chunk(1, "first"), 1)
        threads = []
        for count, tag in enumerate(("a", "b", "c", "d"), start=1):
            threads.append(_spawn(box.put, _chunk(1, tag), 1))
            _until(lambda count=count: box.waiting == count)
        order = []
        for _ in range(5):
            chunk = box.take(JOIN)
            assert chunk is not None
            order.append(chunk[0][0][0])
            sleep(0.01)
        assert order == ["first", "a", "b", "c", "d"]
        for thread in threads:
            thread.join(JOIN)

    def test_a_large_chunk_is_not_overtaken_by_small_ones(self, make):
        box = make(10, 10_000)
        box.put(_chunk(10, "fill"), 10)
        big = _spawn(box.put, _chunk(50, "big"), 50)
        _until(lambda: box.waiting == 1)
        small = _spawn(box.put, _chunk(1, "small"), 1)
        _until(lambda: box.waiting == 2)
        order = []
        for _ in range(3):
            chunk = box.take(JOIN)
            assert chunk is not None
            order.append(chunk[0][0][0])
            sleep(0.01)
        assert order == ["fill", "big", "small"]
        big.join(JOIN)
        small.join(JOIN)

    def test_new_arrival_queues_behind_waiters_even_with_room(self, make):
        box = make(2, 10_000, tick=60)  # no timed wake-up can help the waiter
        box.put(_chunk(2, "fill"), 2)
        waiter = _spawn(box.put, _chunk(5, "w"), 5)
        _until(lambda: box.waiting == 1)
        box.free_room_silently()  # make room without waking the waiter
        late = _spawn(box.put, _chunk(1, "late"), 1)
        _until(lambda: box.waiting == 2)  # the late one queued despite free room
        assert box.pending_lines == 0
        box.wake_producers()
        waiter.join(JOIN)
        chunk = box.take(JOIN)  # frees room for the late arrival
        late.join(JOIN)
        assert not late.is_alive()
        assert chunk is not None
        assert chunk[0][0][0] == "w"
        later = box.take(JOIN)
        assert later is not None
        assert later[0][0][0] == "late"


class TestBackPressureAccounting:
    def test_unblocked_put_reports_zero(self, make):
        assert make(10, 100).put(_chunk(1), 1) == 0.0

    def test_blocked_time_is_measured_per_producer(self, make):
        box = make(1, 10_000)
        box.put(_chunk(1), 1)
        waits: dict[str, float] = {}

        def producer(name):
            waits[name] = box.put(_chunk(1, name), 1, name)

        first = _spawn(producer, "a")
        _until(lambda: box.waiting == 1)
        sleep(0.1)
        second = _spawn(producer, "b")
        _until(lambda: box.waiting == 2)
        sleep(0.1)
        box.take(0)  # admits a, after about 0.2 s of its own waiting
        sleep(0.2)
        box.take(0)  # admits b, after about 0.3 s of its own waiting
        first.join(JOIN)
        second.join(JOIN)
        assert 0.2 <= waits["a"] < 0.2 + SLICE_LIMIT
        assert 0.3 <= waits["b"] < 0.3 + SLICE_LIMIT
        assert waits["b"] > waits["a"] + 0.05
        totals = box.backpressure()
        assert totals["a"] == pytest.approx(waits["a"])
        assert totals["b"] == pytest.approx(waits["b"])

    def test_snapshot_includes_a_wait_in_progress(self, make):
        box = make(1, 10_000)
        box.put(_chunk(1), 1)
        assert box.backpressure() == {}
        blocked = _spawn(box.put, _chunk(1, "a"), 1, "a")
        _until(lambda: box.waiting == 1)
        first = box.backpressure()
        sleep(0.1)
        second = box.backpressure()
        assert 0.08 <= second["a"] - first["a"] < 0.1 + SLICE_LIMIT
        box.take(0)
        blocked.join(JOIN)
        assert box.backpressure()["a"] >= second["a"]

    def test_unblocked_producer_total_does_not_change_while_another_waits(self, make):
        box = make(2, 10_000)
        box.put(_chunk(1), 1, "b")  # admitted without waiting
        box.put(_chunk(1), 1, "b")
        blocked = _spawn(box.put, _chunk(1, "a"), 1, "a")
        _until(lambda: box.waiting == 1)
        first = box.backpressure()
        sleep(0.1)
        second = box.backpressure()
        assert second["a"] - first["a"] >= 0.08
        assert first.get("b", 0.0) == second.get("b", 0.0) == 0.0
        box.request_kill()
        blocked.join(JOIN)
        assert box.backpressure()["a"] >= second["a"]


class TestFlags:
    def test_stop_wakes_waiting_producers_within_a_slice(self, make):
        box = make(1, 10_000)
        box.put(_chunk(1, "fill"), 1)
        results = {}
        threads = []
        for count, name in enumerate(("a", "b", "c"), start=1):
            threads.append(
                _spawn(lambda n=name: results.update({n: box.put(_chunk(1, n), 1)}))
            )
            _until(lambda count=count: box.waiting == count)
        start = monotonic()
        box.request_stop()
        for thread in threads:
            thread.join(JOIN)
            assert not thread.is_alive()
        assert monotonic() - start < SLICE_LIMIT
        assert box.pending_lines == 4  # over the cap: nothing was dropped
        order = []
        while (chunk := box.take(0)) is not None:
            order.append(chunk[0][0][0])
        assert order == ["fill", "a", "b", "c"]

    def test_stopped_queue_admits_without_waiting_and_still_delivers(self, make):
        box = make(1, 1)
        box.request_stop()
        assert box.stopping
        assert not box.killed
        waits: list[float] = []

        def put_three() -> None:
            waits.extend(box.put(_chunk(5), 5) for _ in range(3))

        # Run the puts in a thread: a regression would block them forever,
        # and the test must fail by the join bound instead of hanging.
        thread = _spawn(put_three)
        try:
            thread.join(JOIN)
            assert not thread.is_alive()
            assert waits == [0.0, 0.0, 0.0]
            assert box.pending_lines == 15
            assert sum(1 for _ in iter(lambda: box.take(0), None)) == 3
        finally:
            box.request_kill()  # releases the thread if it is still blocked

    def test_kill_wakes_waiting_producers_within_a_slice_and_drops_chunks(self, make):
        box = make(1, 10_000)
        box.put(_chunk(1), 1)
        threads = [_spawn(box.put, _chunk(1, n), 1) for n in range(3)]
        _until(lambda: box.waiting == 3)
        start = monotonic()
        box.request_kill()
        assert box.stopping
        assert box.killed
        for thread in threads:
            thread.join(JOIN)
            assert not thread.is_alive()
        assert monotonic() - start < SLICE_LIMIT
        assert box.take(0) is None
        assert (box.pending_lines, box.pending_bytes, box.waiting) == (0, 0, 0)

    def test_kill_wakes_a_waiting_consumer_within_a_slice(self, make):
        box = make(10, 100)
        got = []
        thread = _spawn(lambda: got.append((box.take(JOIN), monotonic())))
        _until(lambda: _consumer_parked(box))
        start = monotonic()
        box.request_kill()
        thread.join(JOIN)
        assert not thread.is_alive()
        taken, at = got[0]
        assert taken is None
        assert at - start < SLICE_LIMIT

    def test_take_after_kill_gets_nothing_and_put_drops(self, make):
        box = make(10, 100)
        box.put(_chunk(2), 2)
        box.request_kill()
        assert box.take(0) is None
        assert box.pending_lines == 0
        assert box.put(_chunk(2), 2) == 0.0
        assert box.pending_lines == 0
        assert box.take(0) is None

    def test_clear_drops_queued_chunks(self, make):
        box = make(10, 100)
        box.put(_chunk(2), 2)
        box.clear()
        assert (box.pending_lines, box.pending_bytes) == (0, 0)

    def test_flags_are_seen_with_a_short_tick(self, make):
        box = make(1, 1, tick=0.01)
        box.put(_chunk(1), 1)
        thread = _spawn(box.put, _chunk(1), 1)
        _until(lambda: box.waiting == 1)
        start = monotonic()
        box.request_kill()
        thread.join(JOIN)
        assert monotonic() - start < 0.2

    def test_at_most_one_delivery_arrives_after_kill_returns(self, make):
        for _ in range(100):
            box = make(50, 1_000_000, tick=0.01)
            delivered: list[object] = []
            stop_feeding = threading.Event()

            def feed(box=box, stop_feeding=stop_feeding):
                while not stop_feeding.is_set():
                    box.put(_chunk(3), 3)

            def consume(box=box, delivered=delivered):
                while True:
                    chunk = box.take(0.05)
                    if chunk is None:
                        if box.killed:
                            break
                        continue
                    delivered.append(chunk)

            feeder = _spawn(feed)
            consumer = _spawn(consume)
            _until(lambda delivered=delivered: len(delivered) > 5)
            box.request_kill()
            seen = len(delivered)
            consumer.join(JOIN)
            assert not consumer.is_alive()
            assert len(delivered) - seen <= 1
            stop_feeding.set()
            feeder.join(JOIN)
            assert not feeder.is_alive()
            box.close()


class TestConcurrency:
    def test_no_chunk_is_lost_or_duplicated_and_producer_order_holds(self, make):
        producers = 6
        per_producer = 3000
        # A producer's wait for room gets no timed wake-up: a take or the
        # producer ahead must end it. The consumers still poll with a timeout.
        # (A tick shorter than the event loop's clock resolution, 15.6 ms on
        # Windows with Python 3.12, would make every asyncio wait expire at once.)
        box = make(200, 4000, tick=10)
        total_waited = []

        def produce(pid):
            waited = 0.0
            for seq in range(per_producer):
                size = 1 + (seq % 7)
                waited += box.put([[(pid, seq, k) for k in range(size)]], size * 3)
            total_waited.append(waited)

        threads = [_spawn(produce, pid) for pid in range(producers)]
        seen: dict[int, list[tuple[int, int]]] = {pid: [] for pid in range(producers)}
        chunks = 0
        end = monotonic() + 60
        while chunks < producers * per_producer:
            assert monotonic() < end, "stress test timed out"
            chunk = box.take(0.05)
            if chunk is None:
                continue
            chunks += 1
            (entries,) = chunk
            pid, seq, _ = entries[0]
            assert [e[:2] for e in entries] == [(pid, seq)] * len(entries)
            seen[pid].append((seq, len(entries)))
        for thread in threads:
            thread.join(JOIN)
            assert not thread.is_alive()
        for pid in range(producers):
            assert seen[pid] == [(s, 1 + s % 7) for s in range(per_producer)]
        assert box.take(0) is None
        assert (box.pending_lines, box.pending_bytes, box.waiting) == (0, 0, 0)
        assert len(total_waited) == producers

    def test_several_consumers_get_each_chunk_exactly_once(self, make):
        producers = 4
        per_producer = 2000
        box = make(100, 2000, tick=10)  # producers: no timed wake-up, as above
        taken: list[list[tuple[int, int]]] = [[] for _ in range(3)]
        done = threading.Event()

        def produce(pid):
            for seq in range(per_producer):
                box.put([[(pid, seq)]], 2)

        def consume(index):
            while not done.is_set():
                chunk = box.take(0.02)
                if chunk is not None:
                    taken[index].append(chunk[0][0])

        consumers = [_spawn(consume, i) for i in range(3)]
        threads = [_spawn(produce, pid) for pid in range(producers)]
        for thread in threads:
            thread.join(60)
            assert not thread.is_alive()
        _until(lambda: sum(map(len, taken)) == producers * per_producer, 30)
        done.set()
        for thread in consumers:
            thread.join(JOIN)
        flat = [item for part in taken for item in part]
        assert len(flat) == len(set(flat)) == producers * per_producer
        for part in taken:
            for pid in range(producers):
                seqs = [s for p, s in part if p == pid]
                assert seqs == sorted(seqs)


def _delivery_cost_per_line(batches: int = 400, batch_lines: int = 500) -> float:
    """Seconds per line to move prebuilt batches through the queue.

    One producer thread puts the same prebuilt batch objects; the consumer
    thread takes each chunk and walks its entries, checking the kill flag per
    entry as a stream consumer does. Building and parsing are not included.
    """
    box = Outbox(10_000, 4 * 1024 * 1024)
    batch = [[object() for _ in range(batch_lines)]]
    charge = batch_lines * 60

    def produce():
        for _ in range(batches):
            box.put(batch, charge)

    producer = threading.Thread(target=produce, daemon=True)
    count = 0
    start = time.perf_counter()
    producer.start()
    for _ in range(batches):
        chunk = box.take(JOIN)
        assert chunk is not None
        for entries in chunk:
            for _entry in entries:
                if box.killed:
                    break
                count += 1
    elapsed = time.perf_counter() - start
    producer.join(JOIN)
    assert count == batches * batch_lines
    return elapsed / count


def test_delivery_cost_per_line(capsys):
    """Micro-benchmark row: queue plus consumer walk, per line (about 1 us budget)."""
    runs = [_delivery_cost_per_line() for _ in range(7)]
    median = statistics.median(runs)
    with capsys.disabled():
        print(  # noqa: T201
            f"\ndelivery: median {median * 1e6:.3f} us/line "
            f"(min {min(runs) * 1e6:.3f}, max {max(runs) * 1e6:.3f}, 7 runs, "
            "500-line batches, 2 threads)"
        )
    assert (
        median < 5e-6
    )  # a loose bound: it catches a missed wake-up (whole ticks), not a per-line lock


class TestAsyncOnly:
    """What only the asyncio queue promises: waits end by cancellation too."""

    def test_a_cancelled_put_leaves_the_line_and_the_next_producer_goes_on(self):
        async def scenario():
            box = AsyncOutbox(1, 100, tick=10)  # only a wake-up can help in time
            await box.put(_chunk(1, "fill"), 1)
            first = asyncio.create_task(box.put(_chunk(1, "a"), 1, "a"))
            second = asyncio.create_task(box.put(_chunk(1, "b"), 1, "b"))
            await asyncio.sleep(0)  # both producers run up to their wait
            assert box.waiting == 2
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
            assert box.waiting == 1
            assert box.backpressure()["a"] >= 0.0  # the wait so far is kept
            assert await box.take(0) is not None  # makes room for "b"
            async with asyncio.timeout(JOIN):
                assert await second > 0.0
            assert (box.pending_lines, box.waiting) == (1, 0)
            chunk = await box.take(0)
            assert chunk is not None
            assert chunk[0][0][0] == "b"  # "a" was never queued

        asyncio.run(scenario())

    def test_a_cancelled_half_empty_wait_leaves_no_wait_in_progress(self):
        async def scenario():
            box = AsyncOutbox(1, 100, tick=10)
            await box.put(_chunk(1), 1)
            waiter = asyncio.create_task(box.wait_half_empty("p"))
            await asyncio.sleep(0)  # the waiter runs up to its wait
            assert "p" in box.backpressure()
            waiter.cancel()
            with pytest.raises(asyncio.CancelledError):
                await waiter
            assert (box._since, box._draining) == ({}, 0)
            first = box.backpressure()["p"]  # the wait so far is kept
            await asyncio.sleep(0.01)
            assert box.backpressure()["p"] == first

        asyncio.run(scenario())

    def test_a_cancelled_take_takes_nothing(self):
        async def scenario():
            box = AsyncOutbox(10, 100, tick=10)
            consumer = asyncio.create_task(box.take())
            await asyncio.sleep(0)  # the consumer runs up to its wait
            assert box._ready._futures
            consumer.cancel()
            with pytest.raises(asyncio.CancelledError):
                await consumer
            await box.put(_chunk(1, "x"), 1)
            chunk = await box.take(0)
            assert chunk is not None
            assert chunk[0][0][0] == "x"  # the cancelled consumer did not lose it

        asyncio.run(scenario())
