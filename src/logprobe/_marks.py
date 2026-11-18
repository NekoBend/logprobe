"""The decisions a live stream reader makes about its markers, free of I/O.

A reader proves that it has read up to a point of the device log by writing a
marker line into it (``log -t logprobe <token>``) and reading until that line
comes back. Two things use this:

- ``since="now"`` skips the backlog. The start marker is written before the
  connection is made; the reader drops everything up to it and delivers what
  follows.
- ``stop(flush=t)`` ends a stream after the lines that were logged before the
  request. Each reader writes a flush marker, delivers what comes before it
  and ends. The time ``t`` is a budget that does not count the time a reader
  spent waiting for room in the full output queue, so a slow consumer does not
  use it up.

`Marks` holds what one device's reader knows about this and answers what to
do next (`Marks.step`). It never reads a clock, a socket or the queue: the
reader passes the times it measured (readings of ``time.perf_counter``, the
clock of the queue's back-pressure totals) and acts on the answers, so a
blocking reader and an asyncio reader share this code unchanged.

The flush state of a device (`Marks.state`) is written by `Marks` alone, and
`Marks` is used by the one reader of that device. While a flush is pending the
state reads ``not_requested``; the other four states are final.
"""

from __future__ import annotations

import enum
import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, NamedTuple

from ._feed import MARKER_TAG, MarkerArrived, new_marker

if TYPE_CHECKING:
    from collections.abc import Hashable, Mapping

    from ._feed import Segment
    from ._records import FlushState

__all__ = [
    "COMMAND_LIMIT",
    "START_WAIT",
    "Act",
    "FlushRequest",
    "Marks",
    "Phase",
    "Step",
    "check_flush",
    "marker_argv",
    "parse_clock",
    "since_t_arg",
]

#: Seconds the start marker may take to come back after the connection opened.
START_WAIT: Final = 10.0
#: The longest a one-shot device command may run, in seconds.
COMMAND_LIMIT: Final = 5.0


def check_flush(value: object) -> float:
    """``value`` as a flush budget in seconds, or raise.

    Raises:
        TypeError: ``value`` is not an int or a float (a bool is not a number).
        ValueError: ``value`` is NaN, infinite, zero or negative.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        msg = f"flush must be a number of seconds, not {type(value).__name__}"
        raise TypeError(msg)
    try:
        seconds = float(value)
    except OverflowError:  # an int beyond the range of a float
        seconds = math.inf
    if not math.isfinite(seconds) or seconds <= 0:
        msg = f"flush must be a finite number of seconds above 0, got {value}"
        raise ValueError(msg)
    return seconds


def marker_argv(token: str) -> list[str]:
    """The device command that writes the marker ``token`` into the log."""
    return ["log", "-t", MARKER_TAG, token]


def parse_clock(stdout: bytes) -> int | None:
    """The device clock in whole seconds from the output of ``date +%s``, or None."""
    text = stdout.strip()
    if not text.isdigit() or not text.isascii():
        return None
    return int(text)


def since_t_arg(clock: int) -> str:
    """The ``-T`` value that starts one second before the device clock ``clock``."""
    return f"{max(clock - 1, 0)}.000000"


@dataclass(frozen=True, slots=True)
class FlushRequest:
    """A request to flush: its budget and the moment it was made.

    Attributes:
        seconds: The budget ``t``.
        began: The moment of the request (``perf_counter``).
        waited: The seconds each reader had waited for room in the queue by
            then, keyed by serial (a wait in progress included).
    """

    seconds: float
    began: float
    waited: Mapping[Hashable, float]

    def left(self, serial: str, now: float, waited: float) -> float:
        """The budget left for ``serial`` at ``now``.

        ``waited`` is the device's total wait for room in the queue at ``now``.
        Only that time is given back; the time spent on commands, receiving,
        processing and reconnecting is used up.
        """
        gave_back = waited - self.waited.get(serial, 0.0)
        return self.seconds - ((now - self.began) - gave_back)


class Phase(enum.Enum):
    """Where a device's output is, relative to its markers."""

    #: The start marker has not come back: what arrives is dropped.
    SKIPPING = enum.auto()
    #: Normal delivery.
    DELIVERING = enum.auto()
    #: The flush marker came back: nothing more is delivered.
    CLOSED = enum.auto()


class Act(enum.Enum):
    """What the reader does next (see `Marks.step`)."""

    READ = enum.auto()  # receive, for at most ``limit`` seconds
    WRITE = enum.auto()  # write the flush marker ``token``, for at most ``limit``
    END = enum.auto()  # the flush is over (its state is set): end the device
    LATE = enum.auto()  # the start marker did not come back in time: fail


class Step(NamedTuple):
    """The answer of `Marks.step`."""

    act: Act
    limit: float | None = None
    token: str = ""


class Marks:
    """One device's markers and flush.

    Attributes:
        state: The flush state. ``not_requested`` until the flush ends.
        phase: Where the output is relative to the markers.
        start_token: The start marker this device waits for, or None.
        dropped: Entries the feeder produced that this device dropped (before
            the start marker or after the flush marker).
    """

    __slots__ = (
        "_deadline",
        "_hold",
        "_serial",
        "_token",
        "_written",
        "dropped",
        "phase",
        "request",
        "start_token",
        "state",
    )

    def __init__(self, serial: str) -> None:
        self._serial = serial
        self.phase = Phase.DELIVERING
        self.state: FlushState = "not_requested"
        self.request: FlushRequest | None = None
        self.start_token: str | None = None
        self.dropped = 0
        self._deadline = math.inf
        self._token: str | None = None
        self._written = False  # the flush marker command exited with 0
        self._hold = False  # it could not run: wait for the next connection

    @property
    def over(self) -> bool:
        """True once the flush ended in any way."""
        return self.state != "not_requested"

    # -- start marker ---------------------------------------------------------------

    def skip_until(self, token: str) -> None:
        """Drop everything up to the start marker ``token``."""
        self.phase = Phase.SKIPPING
        self.start_token = token

    def arm(self, deadline: float) -> None:
        """The start marker must come back before ``deadline``."""
        self._deadline = deadline

    def start_left(self, now: float) -> float | None:
        """The seconds the start marker may still take, or None when none is awaited.

        Zero or less means it is late. ``math.inf`` before `arm`. The time
        runs through every wait of the device, reconnects included.
        """
        if self.phase is not Phase.SKIPPING:
            return None
        return self._deadline - now

    # -- flush ------------------------------------------------------------------------

    def adopt(self, request: FlushRequest) -> None:
        """Take over the stream's flush request."""
        if self.request is None and not self.over:
            self.request = request

    def left(self, now: float, waited: float) -> float | None:
        """The seconds of the flush budget left at ``now``, or None without a flush.

        ``waited`` is this device's total wait for room in the queue at ``now``.
        A budget that is used up ends the flush as ``timed_out`` (it returns
        0.0 and `over` is True).
        """
        request = self.request
        if request is None or self.over:
            return None
        left = request.left(self._serial, now, waited)
        if left <= 0:
            self.state = "timed_out"
            return 0.0
        return left

    def step(self, now: float, waited: float) -> Step:
        """What to do next at ``now``; ``waited`` is this device's queue wait total.

        ``waited`` is only used while a flush is pending. A flush whose budget
        is used up ends here as ``timed_out``.
        """
        if self.over:
            return Step(Act.END)
        limit = self.left(now, waited)
        if self.over:
            return Step(Act.END)
        if limit is not None and self._may_write():
            if self._token is None:
                self._token = new_marker("flush")
            return Step(Act.WRITE, min(COMMAND_LIMIT, limit), self._token)
        limit = self._nearest(limit, now)
        if limit is not None and limit <= 0:  # only the start marker can be due here
            return Step(Act.LATE)
        return Step(Act.READ, limit)

    def nearest(self, now: float, waited: float) -> float | None:
        """The seconds until the nearest deadline, or None when there is none.

        The deadlines are the end of the flush budget and the end of the time
        the start marker may take. Zero or less means one has passed: a budget
        used up ends the flush as ``timed_out`` (`over` is True), a start
        marker that is late leaves `over` False. ``waited`` is this device's
        total wait for room in the queue at ``now``; it only matters while a
        flush is pending.
        """
        left = self.left(now, waited)
        if self.over:
            return 0.0
        return self._nearest(left, now)

    def _nearest(self, flush_left: float | None, now: float) -> float | None:
        start = self.start_left(now)
        if start is None or not math.isfinite(start):
            return flush_left
        return start if flush_left is None else min(flush_left, start)

    def _may_write(self) -> bool:
        return self.phase is Phase.DELIVERING and not self._written and not self._hold

    def command_done(self, exit_status: int | None) -> None:
        """Record how the flush marker command ended.

        ``None`` means it did not run to an end (the device or the connection
        was lost): the same marker is written again after the next connection.
        A non-zero status fails the flush.
        """
        if exit_status == 0:
            self._written = True
        elif exit_status is None:
            self._hold = True
        else:
            self.state = "failed"

    def resumed(self) -> None:
        """A new connection was made: a marker that could not be written may be."""
        self._hold = False

    def end_unfinished(self, *, requested: bool) -> None:
        """The reader ends: a requested flush that has no result is ``cancelled``."""
        if requested and not self.over:
            self.state = "cancelled"

    # -- the output -----------------------------------------------------------------

    def route(self, segments: list[Segment]) -> list[Segment]:
        """The segments that are to be queued; the marker that arrived moves the phase.

        Before the start marker everything is dropped, and the start marker's
        own place starts delivery. The flush marker's place ends it: what
        follows is dropped, and the flush is ``done``. `MarkerArrived` itself
        is never returned.
        """
        phase = self.phase
        if (
            phase is Phase.DELIVERING
            and len(segments) == 1
            and (type(segments[0]) is list)
        ):
            return segments
        kept: list[Segment] = []
        dropped = 0
        for segment in segments:
            if type(segment) is MarkerArrived:
                if phase is Phase.SKIPPING:
                    phase = Phase.DELIVERING
                elif phase is Phase.DELIVERING:
                    phase = Phase.CLOSED
                    self.state = "done"
            elif phase is Phase.DELIVERING:
                kept.append(segment)
            elif type(segment) is list:
                dropped += len(segment)
        self.phase = phase
        self.dropped += dropped
        return kept
