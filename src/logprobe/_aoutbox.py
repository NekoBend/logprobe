"""The asyncio counterpart of `logprobe._outbox.Outbox`, for one event loop.

`AsyncOutbox` follows every rule of `Outbox` (see `logprobe._outbox`); only the
waiting differs. It has no lock: everything except `AsyncOutbox.request_stop`
and `AsyncOutbox.request_kill` runs on the thread of the event loop, so a step
that does not await cannot be interrupted. The two requests only set a plain
attribute and may be called from any thread or a signal handler. Every wait is
an asyncio wait of at most `TICK` seconds, so a flag set from another thread is
seen within one slice. Both classes keep their counts, caps, per-producer totals
and dropping in one base class, so the two cannot drift apart.

It lives apart from `Outbox` so that the blocking stream, and so
``import logprobe``, never import asyncio.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections import deque
from time import monotonic
from typing import TYPE_CHECKING, Literal, overload

from ._outbox import STALLED, TICK, _Ledger, _measure, _Turn

if TYPE_CHECKING:
    from collections.abc import Hashable

    from ._outbox import Chunk, _Stalled

__all__ = ["AsyncOutbox"]


class _Parked:
    """The tasks waiting for one thing."""

    def __init__(self) -> None:
        self._futures: deque[asyncio.Future[None]] = deque()

    async def wait(self, limit: float) -> None:
        """Wait until `wake` or ``limit`` seconds pass."""
        future = asyncio.get_running_loop().create_future()
        self._futures.append(future)
        try:
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(limit):
                    await future
        finally:
            with contextlib.suppress(ValueError):
                self._futures.remove(future)

    def wake(self, count: int | None = None) -> None:
        """Resume ``count`` waiting tasks, the longest waiting first; None: all."""
        futures = self._futures
        while futures and count != 0:
            future = futures.popleft()
            if not future.done():
                future.set_result(None)
                if count is not None:
                    count -= 1


class AsyncOutbox(_Ledger):
    """The queue of `Outbox` for the tasks of one event loop.

    The rules are those of `Outbox`; `put` and `take` are coroutines. All of it
    runs on the loop's thread (no lock), except `request_stop` and
    `request_kill`, which may be called from anywhere.

    Args:
        max_lines: Line cap, at least 1.
        max_bytes: Charged-byte cap, at least 1.
        tick: Seconds between looks at the flags while waiting, above 0.

    Raises:
        TypeError: A cap is not an int.
        ValueError: A cap is below 1, or ``tick`` is not above 0.

    """

    def __init__(self, max_lines: int, max_bytes: int, *, tick: float = TICK) -> None:
        super().__init__(max_lines, max_bytes, tick)
        self._space = _Parked()  # producers wait here
        self._ready = _Parked()  # consumers wait here

    def _wake_producers(self) -> None:
        self._space.wake()

    @overload
    async def put(
        self,
        segments: Chunk,
        charge: int,
        producer: Hashable | None = None,
        *,
        interruptible: Literal[False] = False,
        limit: None = None,
    ) -> float: ...

    @overload
    async def put(
        self,
        segments: Chunk,
        charge: int,
        producer: Hashable | None = None,
        *,
        interruptible: bool,
        limit: None = None,
    ) -> float | None: ...

    @overload
    async def put(
        self,
        segments: Chunk,
        charge: int,
        producer: Hashable | None = None,
        *,
        interruptible: Literal[False] = False,
        limit: float | None,
    ) -> float | _Stalled: ...

    @overload
    async def put(
        self,
        segments: Chunk,
        charge: int,
        producer: Hashable | None = None,
        *,
        interruptible: bool,
        limit: float | None,
    ) -> float | _Stalled | None: ...

    async def put(
        self,
        segments: Chunk,
        charge: int,
        producer: Hashable | None = None,
        *,
        interruptible: bool = False,
        limit: float | None = None,
    ) -> float | _Stalled | None:
        """Queue one chunk, waiting while the queue is at a cap.

        The arguments and the result are those of `Outbox.put`. A task that is
        cancelled while it waits leaves the line without queueing the chunk.
        """
        lines, charge = _measure(segments, charge)
        if lines == 0:  # nothing to deliver (every marker counts a line)
            return 0.0
        if self._killed:
            return 0.0
        waited = 0.0
        if self._waiters or not (self._stopping or self._has_room()):
            waited, turn = await self._wait_turn(
                producer, interruptible=interruptible, limit=limit
            )
            if self._killed:
                self._drop()
                return waited
            if turn is not _Turn.ADMITTED:
                return STALLED if turn is _Turn.STALLED else None
        self._admit(segments, lines, charge)
        self._ready.wake(1)
        return waited

    async def take(self, timeout: float | None = None) -> Chunk | None:
        """Take the oldest chunk, whole.

        The arguments and the result are those of `Outbox.take`. A cancelled
        call takes nothing.
        """
        deadline = None if timeout is None else monotonic() + timeout
        while True:
            if self._killed:
                self._drop()
                return None
            if self._chunks:
                break
            step = self._tick
            if deadline is not None:
                step = min(step, deadline - monotonic())
                if step <= 0:
                    return None
            await self._ready.wait(step)
        segments = self._release()
        if self._waiters or self._draining:
            self._space.wake()
        return segments

    def clear(self) -> None:
        """Drop everything queued and wake the waiting producers."""
        self._drop()

    async def wait_half_empty(self, producer: Hashable) -> bool:
        """Wait until both counts are at most half their caps.

        The rules and the result are those of `Outbox.wait_half_empty`. A task
        that is cancelled while it waits leaves no wait in progress behind.
        """
        key = self._enter_drain(producer)
        try:
            while not self._stopping and not self._half_empty():
                await self._space.wait(self._tick)
        finally:
            self._leave_drain(key)
        return not self._stopping

    async def _wait_turn(
        self, producer: Hashable | None, *, interruptible: bool, limit: float | None
    ) -> tuple[float, _Turn]:
        """Wait until this producer is first in line with room (see `Outbox`).

        The limit is measured with ``perf_counter``, not with the loop's timer,
        which can fire up to one tick of the loop's clock early.
        """
        ticket, start = self._enter_line(producer)
        deadline = None if limit is None else start + limit
        turn = _Turn.ADMITTED
        try:
            while not self._killed and not self._admissible(ticket):
                if interruptible and self._interrupted:
                    turn = _Turn.INTERRUPTED
                    break
                # A stop admits every producer in turn, so the limit no longer applies.
                step = self._slice(None if self._stopping else deadline)
                if step is None:
                    turn = _Turn.STALLED
                    break
                await self._space.wait(step)
        finally:
            waited = self._leave_line(ticket, producer, start)
            self._wake_producers()  # the next in line may be admissible now
        return waited, turn
