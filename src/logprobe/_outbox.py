"""The bounded output queue shared by all device readers of one stream.

Readers (producers) put ordered chunks in; one or more consumers take whole
chunks out. `Outbox` is plain threading: one lock and two conditions.
`logprobe._aoutbox.AsyncOutbox` is the same queue for the tasks of one event
loop; it shares the bookkeeping below through `_Ledger`.

A chunk is the list of segments one reader produced from one read: usually a
single list of entries, and a few segments when a gap or an end marker falls
inside it. The chunk keeps its segments in the order they happened, and chunks
of one reader come out in the order that reader put them in.

Limits. The queue holds at most ``max_lines`` lines and ``max_bytes`` input
bytes. A segment that is a ``list`` counts one line per element; any other
segment (a gap, an end or error marker) counts one line and `MARKER_BYTES`
bytes. The caller charges the bytes of its chunk (the input bytes the chunk was
made from). Admission looks only at the state before the chunk goes in: a chunk
is admitted whenever both counts are below their caps, however large it is. So
the queue can exceed a cap by less than one chunk (the last one admitted), and
a cap smaller than one chunk never blocks forever. After a stop request the
queue is no longer bounded by the caps.

Back-pressure. A producer that finds the queue at a cap waits. Waiting
producers are admitted strictly in the order they arrived, so a large chunk is
not starved by small ones. `Outbox.put` returns the seconds the calling
producer spent waiting. The queue also keeps a running total per producer key
(the ``producer`` argument of `Outbox.put`), including a wait still in
progress; `Outbox.backpressure` returns a snapshot of those totals taken under
the lock. Waits are timed with ``time.perf_counter``, which is fine-grained on
every platform.

Flags. `Outbox.request_stop` and `Outbox.request_kill` only set a boolean; they
take no lock and so are safe to call from anywhere (a signal handler, a
finalizer). Every wait is cut into slices of `TICK` seconds and looks at the
flags after each slice, so a flag is seen by every waiter within one slice.

- After a stop request producers are admitted without waiting for space (still
  in arrival order), and consumers keep taking what is queued.
- After a kill request producers' chunks are dropped and consumers get
  nothing: `Outbox.take` returns None. Queued chunks are dropped, not counted.
  Once `Outbox.request_kill` has returned, a consumer that was not already
  inside `Outbox.take` past its flag check gets nothing; a consumer that was
  can still receive that one chunk. The flag check and the hand-over are not
  made atomic on purpose.

Interrupting. `Outbox.interrupt_waiters` (called with the lock held) wakes the
waiting producers once: from then on a `Outbox.put` made with
``interruptible=True`` returns ``None`` instead of waiting, and does not queue
its chunk, unless it is admitted at once. The caller does what the interruption
was for and puts the same chunk again; the producer's place in its own order is
kept, because it is the same producer.
"""

from __future__ import annotations

import threading
from collections import deque
from time import monotonic, perf_counter
from typing import TYPE_CHECKING, Any, Literal, overload

if TYPE_CHECKING:
    from collections.abc import Hashable, Sequence

__all__ = ["MARKER_BYTES", "TICK", "Outbox"]

# Longest time any wait runs before it looks at the stop and kill flags.
TICK = 0.25

# Bytes charged for a segment that is not a list of entries.
MARKER_BYTES = 256

# The queue never looks inside a segment except to count a list's length, so it
# does not constrain what the segments are.
type Chunk = Sequence[Any]


def _measure(segments: Chunk, charge: int) -> tuple[int, int]:
    """The lines of a chunk and its charge, markers' own charge included."""
    lines = 0
    for segment in segments:
        if type(segment) is list:
            lines += len(segment)
        else:
            lines += 1
            charge += MARKER_BYTES
    return lines, charge


class _Ledger:
    """What both queues keep and decide, free of waiting and locking.

    The counts, the caps and the admission rule, the chunks, the producers in
    arrival order with the time each has waited, the flags and dropping. The
    subclasses add the way they wait and who may touch this state at once.
    """

    def __init__(self, max_lines: int, max_bytes: int, tick: float) -> None:
        for name, value in (("max_lines", max_lines), ("max_bytes", max_bytes)):
            if type(value) is not int:
                msg = f"{name} must be an int, not {type(value).__name__}"
                raise TypeError(msg)
            if value < 1:
                msg = f"{name} must be at least 1, got {value}"
                raise ValueError(msg)
        if not tick > 0:
            msg = f"tick must be above 0, got {tick}"
            raise ValueError(msg)
        self._max_lines = max_lines
        self._max_bytes = max_bytes
        self._tick = tick
        self._chunks: deque[tuple[Chunk, int, int]] = deque()
        self._lines = 0
        self._bytes = 0
        self._waiters: deque[object] = deque()  # tickets, in arrival order
        self._waited: dict[Hashable, float] = {}  # finished waits per producer
        # Waits in progress: ticket -> (producer, start).
        self._since: dict[object, tuple[Hashable, float]] = {}
        self._stopping = False
        self._killed = False
        self._interrupted = False

    @property
    def max_lines(self) -> int:
        """The line cap."""
        return self._max_lines

    @property
    def max_bytes(self) -> int:
        """The charged-byte cap."""
        return self._max_bytes

    @property
    def pending_lines(self) -> int:
        """Lines queued now."""
        return self._lines

    @property
    def pending_bytes(self) -> int:
        """Charged bytes queued now."""
        return self._bytes

    @property
    def waiting(self) -> int:
        """Producers waiting for space now."""
        return len(self._waiters)

    @property
    def stopping(self) -> bool:
        """True once a stop or kill was requested."""
        return self._stopping

    @property
    def killed(self) -> bool:
        """True once a kill was requested."""
        return self._killed

    def request_stop(self) -> None:
        """Let producers in without waiting for space. Takes no lock."""
        self._stopping = True

    def request_kill(self) -> None:
        """Make producers drop and consumers get nothing. Takes no lock."""
        self._stopping = True
        self._killed = True

    def backpressure(self) -> dict[Hashable, float]:
        """Snapshot of the seconds each producer has waited for space.

        A producer that is waiting now has the time of its current wait
        included, up to this instant. Producers that never waited are absent.
        """
        return self._totals(perf_counter())

    def _totals(self, now: float) -> dict[Hashable, float]:
        """The totals of `backpressure` as of ``now`` (a ``perf_counter`` reading).

        A wait in progress that began after ``now`` adds nothing.
        """
        totals = dict(self._waited)
        for key, start in self._since.values():
            totals[key] = totals.get(key, 0.0) + max(0.0, now - start)
        return totals

    def _has_room(self) -> bool:
        return self._lines < self._max_lines and self._bytes < self._max_bytes

    def _admissible(self, ticket: object) -> bool:
        """True when the producer with ``ticket`` is first in line and may go in."""
        return self._waiters[0] is ticket and (self._stopping or self._has_room())

    def _admit(self, segments: Chunk, lines: int, charge: int) -> None:
        self._chunks.append((segments, lines, charge))
        self._lines += lines
        self._bytes += charge

    def _release(self) -> Chunk:
        """Remove the oldest chunk and return its segments."""
        segments, lines, charge = self._chunks.popleft()
        self._lines -= lines
        self._bytes -= charge
        return segments

    def _wake_producers(self) -> None:
        """Wake every producer that waits for room, so it looks again."""
        raise NotImplementedError

    def interrupt_waiters(self) -> None:
        """Make waiting producers, and later interruptible puts, give up waiting.

        `Outbox` needs the caller to hold the lock (``_space``), so that it can
        change its own state in the same step.
        """
        self._interrupted = True
        self._wake_producers()

    def _forget(self) -> None:
        self._chunks.clear()
        self._lines = 0
        self._bytes = 0

    def _drop(self) -> None:
        self._forget()
        if self._waiters:
            self._wake_producers()

    def _enter_line(self, producer: Hashable | None) -> tuple[object, float]:
        """Join the producers waiting for room; return the ticket and the start."""
        ticket = object()
        self._waiters.append(ticket)
        start = perf_counter()
        if producer is not None:
            self._since[ticket] = (producer, start)
        return ticket, start

    def _leave_line(
        self, ticket: object, producer: Hashable | None, start: float
    ) -> float:
        """Leave the line; return the seconds waited, added to the producer's total."""
        waited = perf_counter() - start
        self._waiters.remove(ticket)
        if producer is not None:
            del self._since[ticket]
            self._waited[producer] = self._waited.get(producer, 0.0) + waited
        return waited


class Outbox(_Ledger):
    """A bounded queue of chunks with arrival-ordered admission.

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
        lock = threading.Lock()
        self._space = threading.Condition(lock)  # producers wait here
        self._ready = threading.Condition(lock)  # consumers wait here

    @property
    def pending_lines(self) -> int:
        """Lines queued now."""
        with self._space:
            return self._lines

    @property
    def pending_bytes(self) -> int:
        """Charged bytes queued now."""
        with self._space:
            return self._bytes

    @property
    def waiting(self) -> int:
        """Producers waiting for space now."""
        with self._space:
            return len(self._waiters)

    def _wake_producers(self) -> None:
        self._space.notify_all()

    @overload
    def put(
        self,
        segments: Chunk,
        charge: int,
        producer: Hashable | None = None,
        *,
        interruptible: Literal[False] = False,
    ) -> float: ...

    @overload
    def put(
        self,
        segments: Chunk,
        charge: int,
        producer: Hashable | None = None,
        *,
        interruptible: bool,
    ) -> float | None: ...

    def put(
        self,
        segments: Chunk,
        charge: int,
        producer: Hashable | None = None,
        *,
        interruptible: bool = False,
    ) -> float | None:
        """Queue one chunk, waiting while the queue is at a cap.

        Args:
            segments: The chunk: segments in the order they happened. A
                ``list`` segment is a list of entries; anything else is one
                marker.
            charge: Input bytes to charge for the chunk, before the markers'
                own charge.
            producer: Key under which this call's wait is added to the
                per-producer total (see `backpressure`); None keeps no total.
            interruptible: Give up waiting once `interrupt_waiters` was called.

        Returns:
            Seconds this call waited for space; 0.0 when it did not wait.
            After a kill request the chunk is dropped and the wait so far is
            returned. None when the wait was interrupted: the chunk is not
            queued, and the time waited is already in the producer's total.

        """
        lines, charge = _measure(segments, charge)
        if lines == 0:  # nothing to deliver (every marker counts a line)
            return 0.0
        with self._space:
            if self._killed:
                return 0.0
            waited = 0.0
            if self._waiters or not (self._stopping or self._has_room()):
                waited, interrupted = self._wait_turn(
                    producer, interruptible=interruptible
                )
                if self._killed:
                    self._drop()
                    return waited
                if interrupted:
                    return None
            self._admit(segments, lines, charge)
            self._ready.notify()
            return waited

    def take(self, timeout: float | None = None) -> Chunk | None:
        """Take the oldest chunk, whole.

        Args:
            timeout: Seconds to wait for a chunk; None waits until one comes
                or the queue is killed, 0 does not wait.

        Returns:
            The segments of one chunk, or None when the time ran out or the
            queue was killed (check `killed` to tell them apart).

        """
        deadline = None if timeout is None else monotonic() + timeout
        with self._ready:
            while True:
                if self._killed:
                    self._drop()
                    return None
                if self._chunks:
                    break
                step = self._tick
                if deadline is not None:
                    left = deadline - monotonic()
                    if left <= 0:
                        return None
                    step = min(step, left)
                self._ready.wait(step)
            segments = self._release()
            if self._waiters:
                self._space.notify_all()
            return segments

    def backpressure(self) -> dict[Hashable, float]:
        """Snapshot of the seconds each producer has waited for space.

        Taken under the lock. A producer that is waiting now has the time of
        its current wait included, up to this instant. Producers that never
        waited are absent.
        """
        with self._space:
            return self._totals(perf_counter())

    def clear(self) -> None:
        """Drop everything queued and wake the waiting producers."""
        with self._space:
            self._drop()

    def _wait_turn(
        self, producer: Hashable | None, *, interruptible: bool
    ) -> tuple[float, bool]:
        """Wait, lock held, until this producer is first in line with room.

        Also returns when a stop or kill is requested (a stop admits without
        room, a kill drops the chunk), or, if ``interruptible``, when the
        waiters were interrupted. Returns the seconds waited and whether the
        wait ended by an interruption with the producer not admitted.
        """
        ticket, start = self._enter_line(producer)
        interrupted = False
        try:
            while not self._killed and not self._admissible(ticket):
                if interruptible and self._interrupted:
                    interrupted = True
                    break
                self._space.wait(self._tick)
        finally:
            waited = self._leave_line(ticket, producer, start)
            # The next in line may be admissible now.
            self._wake_producers()
        return waited, interrupted
