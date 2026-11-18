"""Live log streams: one reader thread per device, one shared output queue.

``stream`` builds a `LogStream` for one or more devices. Starting it opens one
``logcat`` connection per device and starts one reader thread per connection
(``logprobe-reader-<serial>``). A reader decodes the shell protocol, turns the
bytes into entries with a `Feeder` and puts the chunks into the `Outbox` that
all readers share. When a connection ends, the reader decides from ``_resume``
(pure code) whether to stop or to connect again and resume, and what to do about
markers and a flush from ``_marks`` (pure code as well); it only measures
times, waits in slices of ``TICK`` and does the I/O. The consumer is either the
caller (iterating the stream) or one extra thread (``logprobe-consumer``) that
calls ``on_entry`` for every entry. There are no other threads. A reader runs
the one-shot commands it needs (the flush marker) itself, one at a time; while
one runs, that device's logcat is not read.

Threads and shared state
------------------------

- The only lock is the `Outbox`'s. It guards the queue, the order in which
  waiting readers are let in, the time each reader spent waiting for room, the
  first error and the flush request. Two conditions share it: producers wait
  on one and consumers on the other.
- The stop flag and the kill flag are the `Outbox`'s own plain attributes,
  set by ``stop()`` and ``kill()`` without any lock (so both are safe to call
  from a signal handler or a finalizer) and read by their owner at least every
  ``TICK`` (0.25) seconds: a reader between two receives, a consumer between
  two takes, a waiting producer between two waits. ``stop(flush=)`` takes the
  lock briefly, so it is not for signal handlers.
- A reader alone writes the counters of its device (they live in its
  `Feeder`), its summary fields and its flush state; ``summary`` copies them
  without a lock, so a summary read while the stream runs may be slightly old,
  and is exact once the readers ended.
- Four values are written by more than one thread: the stop flag, the kill
  flag, the flush request and the first error. The flush request is set once,
  under the lock, by the first ``stop(flush=)`` that finds neither a stop nor
  an earlier request, and the readers read it without the lock. The first
  error is set under the lock, and the first one wins. Three more writes are
  harmless exceptions:

  - the iteration slot, which the garbage collector may give back from
    another thread when an iterator ends up in a reference cycle;
  - when ``start()`` fails after some readers are already running, ``start()``
    and those readers both close the same connections and stamp the end time;
    closing is idempotent and the time is just overwritten;
  - the ``error`` field of a device, which its reader and a failed ``start()``
    both write, but never at the same time (``start()`` writes it only for a
    failure before any reader started).

- This is verified on CPython with the global interpreter lock. The
  free-threaded build is not verified. The guarantee of ``kill()`` allows for
  one entry in flight, so it does not rely on a thread switch never happening
  between reading a flag and handing over an entry.

A reader references only the shared internal state (`_Core` and `_Unit`), never
the public `LogStream`, so an abandoned stream is finalized and its readers
stop.

The asyncio stream (``_astream``) reads with tasks instead of threads and uses
the functions of this module that do no I/O: the decisions between two reads
and two commands (what the markers ask for, what the end of a connection
leads to, how to plan and judge a reconnect, how a reader ends), the argument
checks and the start's error handling. The functions that wait or do I/O stay
here for the threads and in ``_astream`` for the tasks.
"""

# ruff: noqa: SLF001  (the stream, its iteration and its devices share internals)

from __future__ import annotations

import logging
import math
import threading
import time
import weakref
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum, auto
from time import monotonic, perf_counter
from typing import TYPE_CHECKING, Any, Literal, NamedTuple, Self, cast

from . import _adb, _marks
from ._adb import RECV_SIZE, TICK, ShellStream, ShellV2Decoder, logcat_argv
from ._conditions import build_condition
from ._device import Device
from ._errors import LogprobeError
from ._feed import Feeder, new_marker
from ._marks import Act, FlushRequest, Marks, Phase, Step
from ._outbox import STALLED, Outbox, _Ledger
from ._records import DeviceSummary, Gap, StreamSummary
from ._resume import (
    Decision,
    EndKind,
    ReconnectPolicy,
    ResumeCheck,
    ResumeFlags,
    ResumePlan,
    attempt_error_code,
    cause_of,
    classify_end,
    end_error,
    parse_sdk,
    plan_resume,
    skips_silently,
    stall_limit,
)

if TYPE_CHECKING:
    import socket
    from collections.abc import Callable, Iterable, Iterator, Sequence
    from types import TracebackType

    from ._adb import ShellResult
    from ._conditions import Condition
    from ._entry import LogEntry, LogLevel
    from ._feed import Chunk, Segment

# The longest line kept whole; a longer one is cut and counted as truncated.
MAX_LINE_BYTES = 64 * 1024

_MIN_BUFFER_BYTES = 65536
_STDERR_LINES = 20
_STDERR_LINE_BYTES = 1024
_STDERR_LOG_RATE = 10  # lines per second
_SDK_COMMAND = ("getprop", "ro.build.version.sdk")
_LOG = logging.getLogger(__name__)

__all__ = ["LogStream", "stream"]


@dataclass(frozen=True, slots=True)
class _DeviceEnded:
    """Queue element: the reader of ``serial`` put its last chunk before this."""

    serial: str


class _Phase(Enum):
    NEW = auto()
    STARTING = auto()
    RUNNING = auto()
    ENDED_EARLY = auto()  # stop() or kill() came first: nothing was connected
    FAILED = auto()  # start() raised


class _Unit:
    """One device of a stream: its feeder, connection, thread and summary fields."""

    __slots__ = (
        "conn",
        "device",
        "ended_at",
        "error",
        "feeder",
        "marks",
        "reconnect",
        "serial",
        "stall_after",
        "started_at",
        "t_arg",
        "thread",
    )

    def __init__(
        self, device: Device, condition: Condition | None, reconnect: float
    ) -> None:
        self.device = device
        self.reconnect = reconnect
        self.serial = device.serial
        self.feeder = Feeder(
            device.serial, condition=condition, max_line_bytes=MAX_LINE_BYTES
        )
        self.started_at = datetime.now(UTC)
        self.ended_at: datetime | None = None
        self.error: LogprobeError | None = None
        self.conn: ShellStream | None = None
        self.thread: threading.Thread | None = None
        self.marks = Marks(device.serial)
        # The ``-T`` value of the first connection: it starts the backlog
        # read of ``since="now"``, and is used again when a reconnect has no
        # line to resume from.
        self.t_arg: str | None = None
        # Seconds the reader may wait for room before it closes its connection
        # itself (``detect_skips`` on an older logd); None: as long as it takes.
        self.stall_after: float | None = None

    def summary(self) -> DeviceSummary:
        feeder = self.feeder
        return DeviceSummary(
            serial=self.serial,
            started_at=self.started_at,
            ended_at=self.ended_at,
            lines=feeder.lines,
            entries=feeder.entries - self.marks.dropped,
            unparsed=feeder.unparsed,
            truncated=feeder.truncated,
            gaps=feeder.gaps,
            lost=feeder.lost,
            reconnects=feeder.reconnects,
            unattributed=0,
            flush=self.marks.state,
            error=self.error,
        )


class _CoreBase[O: _Ledger]:
    """The state the readers, the consumer and the public stream share.

    The blocking stream's `_Core` and the asyncio stream's core differ only in
    the queue (``O``) and in whether the writes below need a lock.
    """

    __slots__ = (
        "ended_seen",
        "errors",
        "expected",
        "flush",
        "iterating",
        "outbox",
        "rest",
        "rest_pos",
        "units",
    )

    def __init__(self, units: Sequence[_Unit], outbox: O) -> None:
        self.units = units
        self.outbox = outbox
        # The first element is the stream's error and never changes.
        self.errors: list[BaseException] = []
        # The entries taken from the queue and not yet handed to the caller.
        self.rest: list[LogEntry | Gap] = []
        self.rest_pos = 0
        self.expected = 0  # device ends the consumer waits for (readers started)
        self.ended_seen = 0  # written by the consumer only
        self.iterating = False
        # Set once by the first stop(flush=).
        self.flush: FlushRequest | None = None

    def cancelled(self) -> bool:
        return self.outbox.stopping

    def fail(self, error: BaseException, *, kill: bool = False) -> None:
        """Remember ``error`` (the first one wins) and stop the stream."""
        self.record_error(error)
        if kill:
            self.outbox.request_kill()
        else:
            self.outbox.request_stop()

    def request_flush(self, seconds: float) -> None:
        """Ask every reader to flush within ``seconds``, unless already stopping.

        Does nothing after a stop or kill and after an earlier flush request.
        The moment and the readers' queue waits are copied in one step, so no
        wait is counted twice or missed.
        """
        outbox = self.outbox
        if self.flush is None and not outbox.stopping:
            now = perf_counter()
            self.flush = FlushRequest(seconds, now, outbox._totals(now))
            outbox.interrupt_waiters()  # a reader in a put notices at once

    def record_error(self, error: BaseException) -> None:
        """Keep ``error`` as the stream's error unless there is one already."""
        if not self.errors:
            self.errors.append(error)

    @property
    def error(self) -> BaseException | None:
        return self.errors[0] if self.errors else None

    @property
    def drained(self) -> bool:
        """True when the consumer has taken everything there will ever be."""
        return self.ended_seen >= self.expected or self.outbox.killed


class _Core(_CoreBase[Outbox]):
    """The blocking stream's shared state: the base, with the outbox's lock.

    The first error and the flush request are written by many threads, so those
    two writes are made under the outbox's condition (the first error wins).
    """

    __slots__ = ("consumer",)

    def __init__(self, units: list[_Unit], outbox: Outbox) -> None:
        super().__init__(units, outbox)
        self.consumer: threading.Thread | None = None

    def request_flush(self, seconds: float) -> None:
        with self.outbox._space:
            super().request_flush(seconds)

    def record_error(self, error: BaseException) -> None:
        with self.outbox._space:
            super().record_error(error)


class _StderrTail:
    """The last lines a command wrote to stderr; logs them at a limited rate."""

    def __init__(self, serial: str, clock: Callable[[], float] = monotonic) -> None:
        self._serial = serial
        self._clock = clock
        self._lines: deque[str] = deque(maxlen=_STDERR_LINES)
        self._partial = b""
        self._window = -1.0e9
        self._logged = 0

    def feed(self, data: bytes) -> None:
        *complete, self._partial = (self._partial + data).split(b"\n")
        self._partial = self._partial[:_STDERR_LINE_BYTES]
        for raw in complete:
            line = raw[:_STDERR_LINE_BYTES].decode("utf-8", "replace").rstrip("\r")
            if not line:
                continue
            self._lines.append(line)
            now = self._clock()
            if now - self._window >= 1.0:
                self._window = now
                self._logged = 0
            if self._logged < _STDERR_LOG_RATE:
                self._logged += 1
                _LOG.warning("logcat on %s wrote to stderr: %s", self._serial, line)

    def lines(self) -> list[str]:
        partial = self._partial.decode("utf-8", "replace").rstrip("\r")
        if not partial:
            return list(self._lines)
        return [*list(self._lines)[1 - _STDERR_LINES :], partial]


def _internal_error(serial: str, cause: Exception) -> LogprobeError:
    error = LogprobeError(
        "internal_error",
        f"the reader of {serial} failed: {cause!r}",
        {"serial": serial},
    )
    error.__cause__ = cause
    return error


def _receive(sock: socket.socket) -> bytes | None:
    """Receive from ``sock``: None when the timeout passed, ``b""`` at the end."""
    try:
        return sock.recv(RECV_SIZE)
    except TimeoutError:
        return None
    except OSError:
        return b""  # the connection broke: no exit packet


class _RunBase:
    """What one connection of a device knows, whatever it is read with."""

    __slots__ = (
        "check",
        "exit_status",
        "opened_at",
        "opened_perf",
        "output_since",
        "stalled",
        "tail",
    )

    def __init__(self, serial: str, check: ResumeCheck | None) -> None:
        self.tail = _StderrTail(serial)
        self.check = check
        self.opened_at = monotonic()
        # The same moment on the fine clock that times the waits for room.
        self.opened_perf = perf_counter()
        self.output_since: float | None = None  # when the first stdout arrived
        self.exit_status: int | None = None
        # The reader closed the connection because it waited too long for room.
        self.stalled = False

    def pending(self) -> ResumeCheck | None:
        """The resume check while it has not finished, else None."""
        check = self.check
        return check if check is not None and not check.finished else None


class _Run(_RunBase):
    """One connection of the blocking reader: socket stream and decoder."""

    __slots__ = ("conn", "decoder")

    def __init__(
        self, conn: ShellStream, serial: str, check: ResumeCheck | None
    ) -> None:
        super().__init__(serial, check)
        self.conn = conn
        self.decoder = ShellV2Decoder()

    def stall(self) -> None:
        """Close the connection: the reader waited too long for room."""
        self.stalled = True
        self.conn.close()


def _routed(unit: _Unit, chunks: list[Chunk]) -> Iterator[tuple[list[Segment], int]]:
    """The segments of each chunk that the device's markers let through, and its charge.

    Lazy: the markers move on as the caller takes one chunk after another.
    """
    for chunk in chunks:
        segments = unit.marks.route(chunk.segments)
        if segments:
            yield segments, chunk.charge


def _queue_read(core: _Core, unit: _Unit, run: _Run, chunks: list[Chunk]) -> None:
    """Queue what one read yielded; a device with a stall limit by `_enqueue_limited`.

    Raises:
        LogprobeError: The start marker did not come back in time.
    """
    if unit.stall_after is None:
        _enqueue(core, unit, chunks)
    else:
        _enqueue_limited(core, unit, run, chunks)


def _enqueue(core: _Core, unit: _Unit, chunks: list[Chunk]) -> None:
    """Queue the chunks' segments that the device's markers let through.

    A put that has to wait for room is interrupted by a flush request. The
    reader then writes its marker (the chunk it holds was read before it, so it
    belongs before the marker) and puts the same chunk again, now waiting as
    long as it takes.

    Raises:
        LogprobeError: The start marker did not come back in time.
    """
    outbox = core.outbox
    for segments, charge in _routed(unit, chunks):
        waited = outbox.put(segments, charge, unit.serial, interruptible=True)
        if waited is None:
            _marking(core, unit)
            outbox.put(segments, charge, unit.serial)


def _enqueue_limited(core: _Core, unit: _Unit, run: _Run, chunks: list[Chunk]) -> None:
    """`_enqueue` for a device whose logd may skip the lines of a slow reader.

    The puts of one read may wait ``unit.stall_after`` seconds for room in all
    (a flush request is handled as in `_enqueue`; the marker command does not
    count). When that time is used up, the reader closes the connection, so
    that logd no longer holds lines back for it, and then queues the chunk and
    the rest of the read, however long that takes: the feeder has counted
    their lines and remembers them for the resume.

    Raises:
        LogprobeError: The start marker did not come back in time.
    """
    outbox = core.outbox
    serial = unit.serial
    left = unit.stall_after
    for segments, charge in _routed(unit, chunks):
        began = perf_counter()
        waited = outbox.put(segments, charge, serial, interruptible=True, limit=left)
        if waited is None:
            if left is not None:
                left -= perf_counter() - began
            _marking(core, unit)
            waited = outbox.put(segments, charge, serial, limit=left)
        if waited is STALLED:
            run.stall()
            left = None
            outbox.put(segments, charge, serial)
        elif left is not None:
            left -= waited


def _feed_output(
    unit: _Unit, run: _RunBase, stderr: bytes, stdout: bytes
) -> list[Chunk]:
    """Keep the stderr of a read, and turn its stdout into chunks."""
    run.tail.feed(stderr)
    if not stdout:
        return []
    if run.output_since is None:
        run.output_since = monotonic()
    return unit.feeder.feed(stdout)


def _decode(
    core: _Core, run: _Run, unit: _Unit, data: bytes
) -> tuple[int | None, LogprobeError | None]:
    """Decode ``data``, keep its stderr, and queue what its stdout yields.

    Returns the exit status (None unless ``data`` completed the exit packet) and
    the protocol error that ended decoding (or None). The stdout before an error
    is queued first.
    """
    pieces, status, broken = run.decoder.feed_pieces(data)
    err = b"".join(p for kind, p, _ in pieces if kind == "stderr")
    out = b"".join(p for kind, p, _ in pieces if kind == "stdout")
    _queue_read(core, unit, run, _feed_output(unit, run, err, out))
    return status, broken


def _read(core: _Core, unit: _Unit, run: _Run) -> None:
    """Read one connection until it ends, the stream stops or the flush ends.

    One loop: look at the markers, receive (at most ``TICK`` seconds), look at
    the flags, decode the shell protocol, feed the stdout bytes to the feeder
    and queue what it returns. While a resume check is pending, every receive
    wait that brings no data counts toward its idle time (a wait on a full
    queue does not). Reading also ends once the reader closed the connection
    because it waited too long for room (``run.stalled``).

    Raises:
        LogprobeError: The shell protocol broke (the output before it was
            queued), or the start marker did not come back in time.
    """
    outbox = core.outbox
    marks = unit.marks
    sock = run.conn.sock
    wait = TICK
    sock.settimeout(wait)
    while True:
        limit = TICK
        if core.flush is not None or marks.phase is Phase.SKIPPING:
            limit = _marking(core, unit)
            if limit is None:
                return
        if limit != wait:
            wait = limit
            sock.settimeout(wait)
        began = monotonic()
        data = _receive(sock)
        if data is None:  # nothing arrived within the wait
            if _quiet(core, unit, run, monotonic() - began):
                return
            continue
        if outbox.killed or not data:
            return
        check = run.pending()
        if check is not None:
            check.received()
        status, broken = _decode(core, run, unit, data)
        if status is not None:  # whatever follows the exit packet is ignored
            run.exit_status = status
            return
        if broken is not None:  # the output before it was queued already
            raise broken
        if outbox.stopping or run.stalled:
            return


def _idle_ended(run: _RunBase, waited: float) -> bool:
    """Add ``waited`` idle seconds to a pending resume check; True when it ended."""
    check = run.pending()
    return check is not None and check.idle(waited)


def _quiet(core: _Core, unit: _Unit, run: _Run, waited: float) -> bool:
    """A receive found no data for ``waited`` seconds; True when to stop reading.

    The wait counts toward the idle time of a pending resume check, which may
    end the check and queue the gap it found.
    """
    outbox = core.outbox
    if outbox.stopping:
        return True
    if _idle_ended(run, waited):
        _queue_read(core, unit, run, unit.feeder.end_check())
        return outbox.stopping or run.stalled
    return False


_STOPPED = Step(Act.END)


def _marking_step(core: _CoreBase[Any], unit: _Unit) -> Step:
    """The next thing the device's markers ask for; ``END`` once the stream stops.

    Raises:
        LogprobeError: The start marker did not come back in time.
    """
    outbox = core.outbox
    marks = unit.marks
    if core.flush is not None:
        marks.adopt(core.flush)
    if outbox.stopping:
        return _STOPPED
    waited = 0.0
    if marks.request is not None:
        waited = outbox.backpressure().get(unit.serial, 0.0)
    step = marks.step(perf_counter(), waited)
    if step.act is Act.LATE:
        raise _start_marker_late(unit)
    return step


def _read_limit(step: Step) -> float | None:
    """The longest the next receive may wait after ``step``; None: read no more."""
    if step.act is Act.END:
        return None
    return TICK if step.limit is None else min(TICK, step.limit)


def _marking(core: _Core, unit: _Unit) -> float | None:
    """Do what the markers ask before the next receive.

    Returns the longest the receive may wait, or None when this connection is
    not to be read any more (the flush is over, or the stream stopped).

    Raises:
        LogprobeError: The start marker did not come back in time.
    """
    while True:
        step = _marking_step(core, unit)
        if step.act is not Act.WRITE:
            return _read_limit(step)
        _write_marker(core, unit, step)


def _start_marker_late(unit: _Unit) -> LogprobeError:
    argv = _marks.marker_argv(unit.marks.start_token or "")
    return LogprobeError(
        "device_command_failed",
        f"the start marker written on {unit.serial} did not come back within "
        f"{_marks.START_WAIT:g} seconds",
        {"serial": unit.serial, "command": argv, "exit_status": 0, "stderr": []},
    )


def _marker_command(unit: _Unit, step: Step) -> tuple[list[str], float]:
    """The command that writes the flush marker of ``step``, and its time limit.

    The reader remembers the marker before writing it, so a marker that comes
    back before the command returns is not missed.
    """
    unit.feeder.expect(step.token)
    limit = _marks.COMMAND_LIMIT if step.limit is None else step.limit
    return _marks.marker_argv(step.token), limit


def _write_marker(core: _Core, unit: _Unit, step: Step) -> None:
    """Write the flush marker of ``step``; its outcome goes to the unit's marks.

    A command that stops because the stream stopped leaves no outcome: the
    caller sees the flag.
    """
    argv, limit = _marker_command(unit, step)
    try:
        result = unit.device._run_command(argv, limit, core.cancelled)
    except _adb.Cancelled:
        return
    except (TimeoutError, LogprobeError, OSError):  # no exit status
        unit.marks.command_done(None)
        return
    unit.marks.command_done(result.exit_status)


def _command_failed(
    serial: str,
    argv: list[str],
    exit_status: int | None,
    stderr: bytes = b"",
    *,
    outcome: str | None = None,
) -> LogprobeError:
    """The error for a device command the start of the stream needs.

    ``outcome`` says what went wrong when the exit status does not (a timeout,
    output that could not be read).
    """
    if outcome is None:
        outcome = f"did not succeed (exit status {exit_status})"
    tail = stderr.decode("utf-8", "replace").splitlines()[-_STDERR_LINES:]
    return LogprobeError(
        "device_command_failed",
        f"the command {' '.join(argv)!r} on {serial} {outcome}",
        {
            "serial": serial,
            "command": argv,
            "exit_status": exit_status,
            "stderr": tail,
        },
    )


def _command_timed_out(unit: _Unit, argv: list[str]) -> LogprobeError:
    """The error for a command the start needs that took longer than the limit."""
    outcome = f"did not finish within {_marks.COMMAND_LIMIT:g} seconds"
    return _command_failed(unit.serial, argv, None, outcome=outcome)


def _succeeded(unit: _Unit, argv: list[str], result: ShellResult) -> ShellResult:
    """``result`` when the command exited with status 0, else the error."""
    if result.exit_status != 0:
        raise _command_failed(unit.serial, argv, result.exit_status, result.stderr)
    return result


def _one_shot(core: _Core, unit: _Unit, argv: list[str]) -> ShellResult:
    """Run a command the start needs; return its result (exit status 0 only).

    Raises:
        LogprobeError: ``device_command_failed`` when the command exits with a
            non-zero status, ends without one or takes longer than the limit.
    """
    try:
        result = unit.device._run_command(argv, _marks.COMMAND_LIMIT, core.cancelled)
    except TimeoutError:
        raise _command_timed_out(unit, argv) from None
    return _succeeded(unit, argv, result)


def _device_clock(unit: _Unit, argv: list[str], result: ShellResult) -> int:
    """The device clock in whole seconds from the result of ``date +%s``."""
    clock = _marks.parse_clock(result.stdout)
    if clock is None:
        shown = result.stdout[:80].decode("utf-8", "replace").strip()
        outcome = f"did not print a time (it printed {shown!r})"
        raise _command_failed(unit.serial, argv, 0, result.stderr, outcome=outcome)
    return clock


def _begin_start_marker(unit: _Unit, clock: int) -> list[str]:
    """Remember the start marker, and return the command that writes it.

    The marker is remembered before it is written. The first connection starts
    one second before the clock, so that the marker is replayed even when the
    time stamp the device gives it is a little earlier than the clock read.
    """
    token = new_marker("start")
    unit.feeder.expect(token)
    unit.marks.skip_until(token)
    unit.t_arg = _marks.since_t_arg(clock)
    return _marks.marker_argv(token)


def _prepare_since(core: _Core, unit: _Unit) -> None:
    """Read the device clock and write the start marker, for ``since="now"``."""
    argv = ["date", "+%s"]
    result = _one_shot(core, unit, argv)
    clock = _device_clock(unit, argv, result)
    _one_shot(core, unit, _begin_start_marker(unit, clock))


def _judge_logd(unit: _Unit, result: ShellResult | None) -> None:
    """Set the device's stall limit from the result of ``getprop ro.build.version.sdk``.

    ``result`` is None when the command took longer than its limit. A level that
    cannot be read counts as an older logd, and a WARNING says why. A newer
    logd cuts slow readers off itself and needs no limit: an INFO says that
    ``detect_skips`` is ignored there.
    """
    sdk: int | None = None
    if result is None:
        reason = "timed out"
    elif result.exit_status is None:
        reason = "no exit status"
    elif result.exit_status != 0:
        reason = f"exit status {result.exit_status}"
    else:
        sdk = parse_sdk(result.stdout)
        shown = result.stdout[:80].decode("utf-8", "replace").strip()
        reason = f"printed {shown!r}"
    if sdk is None:
        _LOG.warning(
            "could not read the API level of %s (%s); detect_skips treats its "
            "logd as one that skips lines silently",
            unit.serial,
            reason,
        )
    elif not skips_silently(sdk):
        _LOG.info(
            "logd on %s (API level %d) cuts slow readers off itself; "
            "detect_skips is not needed there and is ignored",
            unit.serial,
            sdk,
        )
    unit.stall_after = stall_limit(sdk)


def _check_logd(core: _Core, unit: _Unit) -> None:
    """Read the device's API level, for ``detect_skips``, and set its stall limit.

    A command that fails or takes too long leaves the level unread; an error of
    the adb server or the device fails the start, as in the other start steps.

    Raises:
        LogprobeError: The device or the adb server failed.
    """
    try:
        result = unit.device._run_command(
            _SDK_COMMAND, _marks.COMMAND_LIMIT, core.cancelled
        )
    except TimeoutError:
        result = None
    _judge_logd(unit, result)


def _prepare(core: _Core, unit: _Unit, *, since: bool, detect_skips: bool) -> None:
    """Step one of the start for one device: the checks and the start marker."""
    unit.device._require_shell_v2(core.cancelled)
    if detect_skips:
        _check_logd(core, unit)
    if since:
        _prepare_since(core, unit)


def _first_argv(unit: _Unit) -> list[str]:
    """The command line of the device's first logcat connection."""
    return logcat_argv(dump=False, tail=None, t=unit.t_arg)


def _arm_start_marker(unit: _Unit, *, since: bool) -> None:
    """The first connection is open: the start marker must come back in time."""
    if since:
        unit.marks.arm(perf_counter() + _marks.START_WAIT)


def _open_first(core: _Core, unit: _Unit, *, since: bool) -> ShellStream:
    """Step two of the start for one device: open its first logcat connection."""
    unit.conn = unit.device._open_logcat(_first_argv(unit), core.cancelled)
    _arm_start_marker(unit, since=since)
    return unit.conn


def _time_left(core: _CoreBase[Any], unit: _Unit) -> float | None:
    """The seconds until the device's nearest deadline, or None when it has none.

    The deadlines are the flush budget and the start marker's time (see
    `Marks.nearest`). Zero or less means one has passed; a flush whose budget is
    used up has ended as ``timed_out`` (``unit.marks.over``).
    """
    marks = unit.marks
    waited = 0.0
    if core.flush is not None:
        marks.adopt(core.flush)
        waited = core.outbox.backpressure().get(unit.serial, 0.0)
    return marks.nearest(perf_counter(), waited)


def _attempt_deadline(core: _CoreBase[Any], unit: _Unit) -> float | None:
    """The ``time.monotonic()`` time by which the next connection must be made.

    None when no deadline applies, or when the flush budget is used up (the
    caller looks at ``unit.marks.over``).

    Raises:
        LogprobeError: The start marker did not come back in time.
    """
    left = _time_left(core, unit)
    if unit.marks.over or left is None:
        return None
    if left <= 0:
        raise _start_marker_late(unit)
    return monotonic() + left


def _attempt_cancelled(core: _CoreBase[Any], unit: _Unit) -> Callable[[], bool]:
    """The cancel check of a reconnect handshake.

    It turns true when the stream stops, and also when a deadline of the
    device passes during the handshake (the flush budget, or the start marker's
    time); the caller then asks `_budget_ended` why.
    """

    def cancelled() -> bool:
        if core.cancelled():
            return True
        left = _time_left(core, unit)
        return left is not None and left <= 0

    return cancelled


def _budget_ended(core: _CoreBase[Any], unit: _Unit) -> bool:
    """True when the device's flush budget is used up (the state is set).

    Raises:
        LogprobeError: The start marker did not come back in time.
    """
    _attempt_deadline(core, unit)
    return unit.marks.over


def _pause_step(core: _CoreBase[Any], unit: _Unit, deadline: float) -> bool | float:
    """What a wait until ``deadline`` (``time.monotonic()``) does next.

    True: the time has come. False: the stream stopped or the device's flush
    ended (its budget ran out) first. Otherwise the seconds to sleep (at most
    ``TICK``) before asking again.

    Raises:
        LogprobeError: The start marker did not come back in time.
    """
    if core.outbox.stopping:
        return False
    left = deadline - monotonic()
    if left <= 0:
        return True
    limit = _attempt_deadline(core, unit)
    if unit.marks.over:
        return False
    if limit is not None:
        left = min(left, limit - monotonic())
    return max(0.0, min(TICK, left))


def _pause(core: _Core, unit: _Unit, delay: float) -> bool:
    """Wait ``delay`` seconds in slices of ``TICK``.

    Returns False when the stream stopped or the device's flush ended (its
    budget ran out) during the wait.

    Raises:
        LogprobeError: The start marker did not come back in time.
    """
    deadline = monotonic() + delay
    while True:
        step = _pause_step(core, unit, deadline)
        if isinstance(step, bool):
            return step
        time.sleep(step)


def _final_error(
    decision: Decision,
    unit: _Unit,
    run: _RunBase,
    attempt: BaseException | None = None,
) -> LogprobeError | None:
    """The error a decision that gives up stands for; None for a requested stop."""
    if decision.error is None:
        return None
    exit_status = run.exit_status
    return end_error(
        decision.error, unit.serial, exit_status, run.tail.lines(), attempt=attempt
    )


class _Retry(NamedTuple):
    """The connection ended and the device is to be connected again."""

    decision: Decision
    kind: EndKind
    carried: ResumeFlags | None


class _Attempt(NamedTuple):
    """One reconnect attempt: the plan, the command line and the deadline."""

    plan: ResumePlan
    argv: list[str]
    deadline: float | None


def _ended_at(run: _RunBase) -> float:
    """When ``run`` ended, on the ``monotonic`` clock its ``opened_at`` uses.

    A stalled connection is at least as old as the waits for room that ended it.
    Those are timed with ``perf_counter``, while ``monotonic`` can advance in
    steps of about 16 ms on some platforms, so its age is taken from
    ``perf_counter``: a stall then never looks shorter than its waits, and with
    `_resume.STALL_AFTER` not below `_resume.QUICK_END` it never counts as a
    quick end.
    """
    now = monotonic()
    if not run.stalled:
        return now
    return max(now, run.opened_at + (perf_counter() - run.opened_perf))


def _connection_ended(
    core: _CoreBase[Any],
    unit: _Unit,
    run: _RunBase,
    policy: ReconnectPolicy,
    *,
    first: bool,
) -> _Retry | LogprobeError | None:
    """What the end of a connection leads to: a retry, or the device's end.

    None ends the device without an error (a requested stop, a killed stream or
    a flush that is over); an error ends it with that error.
    """
    outbox = core.outbox
    if outbox.killed or unit.marks.over:
        return None
    stderr = "\n".join(run.tail.lines())
    kind = classify_end(
        run.exit_status,
        stderr,
        stop_requested=outbox.stopping,
        stalled=run.stalled,
        output_seen=run.output_since is not None,
        first_connection=first,
    )
    decision = policy.connection_ended(
        kind,
        opened_at=run.opened_at,
        ended_at=_ended_at(run),
        output_since=run.output_since,
    )
    if not decision.retry:
        return _final_error(decision, unit, run)
    if kind is EndKind.STALLED:
        _LOG.warning(
            "the reader of %s closed its logcat connection after waiting %g s "
            "for room in the queue; it reconnects once the queue is half empty",
            unit.serial,
            unit.stall_after,
        )
    else:
        _LOG.warning(
            "the logcat connection to %s ended (%s); reconnecting in %g s",
            unit.serial,
            kind.value,
            decision.delay,
        )
    pending = run.pending()
    return _Retry(decision, kind, None if pending is None else pending.flags)


def _next_attempt(core: _CoreBase[Any], unit: _Unit, retry: _Retry) -> _Attempt | None:
    """Plan the next connection; None when the flush budget ran out meanwhile.

    Raises:
        LogprobeError: The start marker did not come back in time.
    """
    plan = plan_resume(
        unit.feeder, cause_of(retry.kind), datetime.now(UTC), carried=retry.carried
    )
    argv = logcat_argv(dump=False, tail=None, t=plan.t_arg or unit.t_arg)
    deadline = _attempt_deadline(core, unit)
    if unit.marks.over:  # the budget ran out since the pause
        return None
    return _Attempt(plan, argv, deadline)


def _attempt_failed(
    core: _CoreBase[Any],
    unit: _Unit,
    run: _RunBase,
    policy: ReconnectPolicy,
    failure: BaseException,
) -> Decision | LogprobeError | None:
    """What a failed reconnect attempt leads to: a new decision, or the end.

    A requested end or a used-up budget wins; a deadline that passed during the
    handshake ends the device here too. None ends the device without an error.

    Raises:
        LogprobeError: The start marker did not come back in time.
    """
    if (
        core.outbox.stopping
        or _budget_ended(core, unit)
        or isinstance(failure, _adb.Cancelled)
    ):
        return None
    code = attempt_error_code(failure)
    decision = policy.attempt_failed(monotonic(), error=code)
    if not decision.retry:
        return _final_error(decision, unit, run, failure)
    _LOG.warning(
        "reconnecting to %s failed (%s); trying again in %g s",
        unit.serial,
        failure,
        decision.delay,
    )
    return decision


def _begin_connection(unit: _Unit, attempt: _Attempt) -> ResumeCheck | None:
    """A new connection is open: start its resume check; return the check."""
    check = attempt.plan.check
    unit.feeder.begin_connection(check)
    unit.marks.resumed()
    return check


def _serve(core: _Core, unit: _Unit) -> LogprobeError | None:
    """Read one device across its connections; return the error that ended it.

    For each connection: read it, then decide from how it ended whether to stop
    or to reconnect (the decisions are in ``_resume`` and ``_marks``; this
    function measures times, waits, opens connections and acts on the answers).
    A device whose flush ended is finished, whatever state its connection is in.
    A reader that closed its connection because it waited too long for room
    connects again once the queue is half empty.
    """
    policy = ReconnectPolicy(unit.reconnect)
    conn = unit.conn
    assert conn is not None  # noqa: S101
    check: ResumeCheck | None = None
    first = True
    while True:
        run = _Run(conn, unit.serial, check)
        try:
            _read(core, unit, run)
        finally:
            conn.close()
        ended = _connection_ended(core, unit, run, policy, first=first)
        if not isinstance(ended, _Retry):
            return ended
        if ended.kind is EndKind.STALLED and not core.outbox.wait_half_empty(
            unit.serial
        ):
            return None
        decision = ended.decision
        while True:
            if not _pause(core, unit, decision.delay):
                return None
            attempt = _next_attempt(core, unit, ended)
            if attempt is None:
                return None
            try:
                conn = unit.device._open_logcat(
                    attempt.argv, _attempt_cancelled(core, unit), attempt.deadline
                )
                break
            except (_adb.Cancelled, LogprobeError, OSError) as failure:
                failed = _attempt_failed(core, unit, run, policy, failure)
                if not isinstance(failed, Decision):
                    return failed
                decision = failed
        unit.conn = conn
        check = _begin_connection(unit, attempt)
        first = False


def _failure_of(unit: _Unit, failure: Exception) -> LogprobeError:
    """The error a reader that failed ends the stream with."""
    if isinstance(failure, LogprobeError):  # the decoder: a broken packet
        failure.details.setdefault("serial", unit.serial)
        return failure
    return _internal_error(unit.serial, failure)  # a bug; end the stream


def _finish(core: _CoreBase[Any], unit: _Unit, error: LogprobeError | None) -> None:
    """The last steps of a reader that do not wait, after its connection closed.

    The first error (if any) stops the other readers.
    """
    if core.outbox.killed:
        core.outbox.clear()  # nobody will take what is still queued
    unit.marks.end_unfinished(requested=core.flush is not None)
    unit.ended_at = datetime.now(UTC)
    unit.error = error
    if error is not None:
        core.fail(error)


def _reader(core: _Core, unit: _Unit) -> None:
    """Read one device's logcat until the stream stops or it cannot go on.

    When the loop ends the connection is closed, the first error (if any) stops
    the other readers, and the end of this device is queued.
    """
    error: LogprobeError | None = None
    try:
        error = _serve(core, unit)
    except Exception as failure:  # noqa: BLE001  (every failure ends the stream)
        error = _failure_of(unit, failure)
    finally:
        if unit.conn is not None:
            unit.conn.close()
        _finish(core, unit, error)
        core.outbox.put([_DeviceEnded(unit.serial)], 0, unit.serial)


def _consume(core: _Core, on_entry: Callable[[LogEntry], object]) -> None:
    """The consumer thread: call ``on_entry`` for each entry, one at a time."""
    outbox = core.outbox
    try:
        while core.ended_seen < core.expected:
            chunk = outbox.take(TICK)
            if chunk is None:
                if outbox.killed:
                    return
                continue
            for segment in chunk:
                if type(segment) is list:
                    for entry in segment:
                        if outbox.killed:
                            return
                        on_entry(entry)
                elif type(segment) is _DeviceEnded:
                    core.ended_seen += 1
    except BaseException as error:  # noqa: BLE001  (kept, re-raised by join)
        core.fail(error, kill=True)


def _unpack(
    core: _CoreBase[Any], buf: list[LogEntry | Gap], chunk: Sequence[Any]
) -> None:
    """Move the items of one queue chunk to ``buf``; count the device ends in it."""
    for segment in chunk:
        if type(segment) is list:
            buf.extend(segment)
        elif type(segment) is _DeviceEnded:
            core.ended_seen += 1
        else:
            buf.append(segment)


class _Iteration:
    """One pass over a stream's output, in the caller's thread."""

    def __init__(self, owner: LogStream, *, gaps: bool) -> None:
        self._owner = owner  # keeps the stream alive while it is iterated
        self._core = owner._core
        self._gaps = gaps
        self._done = False

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> LogEntry | Gap:
        core = self._core
        while not self._done:
            if core.rest_pos < len(core.rest):
                item = core.rest[core.rest_pos]
                core.rest_pos += 1
                if core.outbox.killed:
                    break
                if self._gaps or type(item) is not Gap:
                    return item
            elif not self._refill():
                break
        self.close()
        error = core.error
        if error is not None:
            raise error
        raise StopIteration

    def _refill(self) -> bool:
        """Wait for the next chunk; False when there will be no more."""
        core = self._core
        outbox = core.outbox
        buf = core.rest = []
        core.rest_pos = 0
        try:
            while not buf:
                if core.drained:
                    return False
                chunk = outbox.take(TICK)
                if chunk is not None:
                    _unpack(core, buf, chunk)
        except KeyboardInterrupt:
            outbox.request_kill()
            self.close()
            raise
        return True

    def close(self) -> None:
        """End this iteration, so that another one may start."""
        if not self._done:
            self._done = True
            self._core.iterating = False

    def __del__(self) -> None:
        self.close()


def _start_failure(
    core: _CoreBase[Any], error: BaseException, unit: _Unit
) -> BaseException:
    """Record that the start failed on ``unit`` with ``error``; return what to raise.

    A timeout becomes the ``adb_error`` the stream reports for a server that did
    not answer. The error is the stream's error, and every device has ended.
    """
    reported = error
    if isinstance(error, TimeoutError):
        reported = LogprobeError(
            "adb_error",
            f"the adb server did not answer in time while starting {unit.serial}",
            {"serial": unit.serial},
        )
    if isinstance(reported, LogprobeError):
        unit.error = reported
    core.record_error(reported)
    core.outbox.request_stop()
    for each in core.units:
        each.ended_at = datetime.now(UTC)
    return reported


class LogStream:
    """The live log of one or more devices.

    Create it with `logprobe.stream` or `Device.stream`. It is not started
    yet: use it in a ``with`` statement or call `start`. A stream is used
    once; after it ended it cannot be started again.

    There are two ways to consume it. Iterate it (``for entry in stream``, or
    `items` to get `Gap` records as well); the entries are then handed over on
    the calling thread. Or pass ``on_entry`` when creating it; a consumer
    thread then calls it for every entry, one at a time, and the stream cannot
    be iterated. ``on_entry`` must return; an exception from it, including
    ``SystemExit``, stops the stream and is raised again by `join` and by the
    end of the ``with`` block (unless the stream had already failed, or the
    ``with`` body raised its own exception). The entries still queued are
    dropped.

    ``stop`` and ``kill`` only set a flag; they never block and may be called
    from any thread or signal handler. (``stop(flush=...)`` also takes the
    queue's lock for a moment, so it is not for signal handlers.) All waits of
    the stream are cut into slices of 0.25 seconds, so Ctrl-C works while
    waiting, also on Windows.

    The threading rules are verified on CPython with the global interpreter
    lock; the free-threaded build is not verified.

    Attributes:
        serials: The serials of the devices, in the order given.
    """

    def __init__(
        self,
        devices: Sequence[Device],
        condition: Condition | None,
        on_entry: Callable[[LogEntry], object] | None,
        reconnect: float,
        buffer_lines: int,
        buffer_bytes: int,
        since: Literal["now"] | None = None,
        *,
        detect_skips: bool = False,
    ) -> None:
        units = [_Unit(device, condition, reconnect) for device in devices]
        self._core = _Core(units, Outbox(buffer_lines, buffer_bytes))
        self._on_entry = on_entry
        self._since = since
        self._detect_skips = detect_skips
        self._phase = _Phase.NEW
        self.serials: tuple[str, ...] = tuple(unit.serial for unit in units)
        # An abandoned stream stops its readers: this only sets the kill flag.
        weakref.finalize(self, self._core.outbox.request_kill)

    # -- starting ---------------------------------------------------------------

    def start(self) -> Self:
        """Check the devices, open every connection and start the readers.

        Runs on the calling thread in three steps: each device is prepared in
        turn (``shell_v2`` check, with ``detect_skips`` the device's API level,
        and with ``since="now"`` the device clock and the start marker), then
        all logcat connections are opened back to back, then all readers start
        (all or none). The readers wait for the start marker, not ``start()``.
        When ``stop()`` or ``kill()`` is called, before or during the start,
        nothing is left open and no reader starts; the stream then ends at once
        without an error.

        Raises:
            RuntimeError: The stream was started before, or its start failed.
            LogprobeError: A device cannot be used (``adb_error``,
                ``device_not_found``, ``device_offline``, ...), or a command
                that ``since="now"`` needs failed (``device_command_failed``;
                ``details`` has ``serial``, ``command``, ``exit_status`` and
                ``stderr``). Everything that was opened is closed, and the
                stream cannot be started again.
        """
        if self._phase is not _Phase.NEW:
            msg = "a stream can be started only once"
            raise RuntimeError(msg)
        self._phase = _Phase.STARTING
        core = self._core
        opened: list[ShellStream] = []
        working = core.units[0]
        now = datetime.now(UTC)
        for unit in core.units:
            unit.started_at = now
        try:
            if core.outbox.stopping:
                raise _adb.Cancelled
            for unit in core.units:
                working = unit
                _prepare(
                    core,
                    unit,
                    since=self._since is not None,
                    detect_skips=self._detect_skips,
                )
            for unit in core.units:
                working = unit
                opened.append(_open_first(core, unit, since=self._since is not None))
            if core.outbox.stopping:
                raise _adb.Cancelled
            self._launch()
        except _adb.Cancelled:
            self._close_all(opened)
            self._phase = _Phase.ENDED_EARLY
            for unit in core.units:
                unit.ended_at = datetime.now(UTC)
        except BaseException as error:
            self._close_all(opened)
            self._phase = _Phase.FAILED
            reported = self._start_error(error, working)
            if reported is error:
                raise
            raise reported from error
        else:
            self._phase = _Phase.RUNNING
        return self

    def _launch(self) -> None:
        """Start the reader threads and the consumer: all of them or none."""
        core = self._core
        threads: list[threading.Thread] = []
        for unit in core.units:
            unit.thread = threading.Thread(
                target=_reader,
                args=(core, unit),
                name=f"logprobe-reader-{unit.serial}",
                daemon=True,
            )
            threads.append(unit.thread)
        if self._on_entry is not None:
            core.consumer = threading.Thread(
                target=_consume,
                args=(core, self._on_entry),
                name="logprobe-consumer",
                daemon=True,
            )
        core.expected = len(core.units)
        started: list[threading.Thread] = []
        try:
            for thread in [*threads, *([core.consumer] if core.consumer else [])]:
                thread.start()
                started.append(thread)
        except BaseException:
            core.outbox.request_kill()
            for thread in started:
                thread.join(TICK)
            core.expected = 0
            raise

    @staticmethod
    def _close_all(opened: list[ShellStream]) -> None:
        for conn in opened:
            conn.close()

    def _start_error(self, error: BaseException, unit: _Unit) -> BaseException:
        """Record a failed start; return the exception to raise."""
        return _start_failure(self._core, error, unit)

    # -- consuming ----------------------------------------------------------------

    def __enter__(self) -> Self:
        return self.start()

    def __iter__(self) -> Iterator[LogEntry]:
        """Iterate the entries (one iteration at a time).

        The iteration ends when every reader ended and the queue is empty. When
        the stream failed, the error is raised after the queued entries were
        delivered; `join` and the ``with`` exit raise the same object.

        Raises:
            RuntimeError: The stream was not started (or its start failed),
                another iteration is running, or ``on_entry`` was given.
        """
        return cast("Iterator[LogEntry]", self._iterate(gaps=False))

    def items(self) -> Iterator[LogEntry | Gap]:
        """Like iterating, but also yields the `Gap` records in place.

        Raises:
            RuntimeError: As for iterating.
        """
        return self._iterate(gaps=True)

    def _iterate(self, *, gaps: bool) -> _Iteration:
        if self._on_entry is not None:
            msg = "a stream with on_entry cannot be iterated"
            raise RuntimeError(msg)
        if self._phase not in {_Phase.RUNNING, _Phase.ENDED_EARLY}:
            msg = "the stream is not running; start it first"
            raise RuntimeError(msg)
        if self._core.iterating:
            msg = "the stream is already being iterated"
            raise RuntimeError(msg)
        self._core.iterating = True
        return _Iteration(self, gaps=gaps)

    # -- stopping -----------------------------------------------------------------

    def stop(self, flush: float | None = None) -> None:
        """Ask the stream to end. Never waits; any thread, any number of times.

        Without ``flush`` this only sets a flag, so it is safe to call from a
        signal handler. The readers notice at their next check (at least
        every 0.25 seconds while they wait for data), queue the complete lines
        of their last receive and end. Those are delivered; output not received
        yet and a line whose end has not arrived (unless it was already cut at
        the 64 KiB line limit) are not. A stop before `start`
        makes the stream end at once without connecting. A stop while a flush
        is pending cancels it.

        With ``flush`` every device gets a marker line written into its log
        after the call, and its reader queues the matching entries it reads up
        to the marker and ends; a `Gap` before the marker still means lines
        may be missing. The connections stay open until then, and the stream
        ends by itself; the
        ``with`` block of a stream with ``on_entry`` waits for it. ``flush``
        is a budget in seconds that does not count the time a reader spends
        waiting for room in the full queue, so a slow consumer does not use
        it up. Writing the marker, receiving, processing and reconnecting use
        it up. How each device ended is in
        ``summary.devices[i].flush``: ``done`` (the marker came back),
        ``timed_out`` (the budget ran out), ``failed`` (the marker could not
        be written: the command exited with an error), ``cancelled`` (a
        ``stop()``, ``kill()`` or a failure of the stream came first) or
        ``not_requested`` (also what a device shows while its flush is
        pending, and what a device that had already ended before the request
        keeps). A flush that did not end as ``done`` makes the summary
        incomplete. The stream raises nothing for it. A consumer that does not
        take entries holds a flush up until a ``stop()`` or ``kill()``. With
        ``since="now"``, a flush requested before a device's start marker
        came back waits for that marker first, and the budget runs
        meanwhile. Like the start marker, the flush marker (``flush-`` and
        32 hex digits, tag ``logprobe``) is an ordinary line in the device
        log that other readers see.

        ``stop(flush=)`` does nothing after a ``stop()`` and after an earlier
        ``stop(flush=)``, and before `start` it is the same as ``stop()``. It
        takes the queue's lock for a moment, so unlike ``stop()`` it must not
        be called from a signal handler.

        Raises:
            TypeError: ``flush`` is not a number (a bool is not).
            ValueError: ``flush`` is NaN, infinite, zero or negative.
        """
        if flush is None:
            self._core.outbox.request_stop()
            return
        seconds = _marks.check_flush(flush)
        if self._phase is _Phase.NEW:
            self._core.outbox.request_stop()  # nothing is connected: nothing to flush
        else:
            self._core.request_flush(seconds)

    def kill(self) -> None:
        """End the stream now. Never blocks; any thread, any number of times.

        The readers end at their next check and queue nothing more; what is
        queued is dropped. After ``kill()`` returned no new entry is handed to
        the consumer, except one that was already being handed over when it
        was called from another thread.
        """
        self._core.outbox.request_kill()

    def join(self, timeout: float | None = None) -> StreamSummary:
        """Wait for the stream to end and return its summary.

        With ``on_entry``, this also waits until the queued entries were given
        to the callback. Without it, readers can end only when the queue is
        consumed or the stream is stopped.

        Raises:
            TimeoutError: ``timeout`` seconds passed; the stream keeps running.
            RuntimeError: Not started, or called from inside ``on_entry``.
            LogprobeError: The error that ended the stream (the same object
                every time). An exception raised by ``on_entry`` is raised
                as it is.
            KeyboardInterrupt: Raised while waiting; the stream is killed.
        """
        if self._phase is _Phase.NEW or self._phase is _Phase.STARTING:
            msg = "the stream is not started"
            raise RuntimeError(msg)
        core = self._core
        if core.consumer is not None and core.consumer is threading.current_thread():
            msg = "join() cannot be called from inside on_entry"
            raise RuntimeError(msg)
        deadline = None if timeout is None else monotonic() + timeout
        self._wait(self._threads(), deadline)
        error = core.error
        if error is not None:
            raise error
        return self.summary

    def _threads(self) -> list[threading.Thread]:
        core = self._core
        threads = [unit.thread for unit in core.units if unit.thread is not None]
        if core.consumer is not None:
            threads.append(core.consumer)
        return threads

    def _wait(self, threads: list[threading.Thread], deadline: float | None) -> None:
        """Wait for ``threads`` in slices of ``TICK``; kill on Ctrl-C."""
        try:
            for thread in threads:
                while thread.is_alive():
                    step = TICK
                    if deadline is not None:
                        left = deadline - monotonic()
                        if left <= 0:
                            msg = "the stream did not end in time"
                            raise TimeoutError(msg)
                        step = min(step, left)
                    thread.join(step)
        except KeyboardInterrupt:
            self.kill()
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        core = self._core
        if isinstance(exc, KeyboardInterrupt):
            # Do not wait for a callback that may never return.
            self.kill()
            readers = [u.thread for u in core.units if u.thread is not None]
            self._wait(readers, None)
            if core.error is not None and core.error is not exc:
                _LOG.error("the stream ended with an error", exc_info=core.error)
            return
        if self._on_entry is None:
            if not core.drained:
                self.kill()  # nobody takes the entries any more
        elif exc is not None or (core.flush is None and not core.outbox.stopping):
            self.stop()  # a stop asked for earlier is kept; a flush is waited for
        try:
            self.join()
        except BaseException as error:
            # A Ctrl-C while waiting is not the stream's error: it propagates.
            ctrl_c = isinstance(error, KeyboardInterrupt) and error is not core.error
            if exc is None or ctrl_c:
                raise
            if error is not exc:
                _LOG.error(
                    "the stream ended with an error while the with block "
                    "was leaving with another",
                    exc_info=error,
                )

    # -- reading state ------------------------------------------------------------

    @property
    def summary(self) -> StreamSummary:
        """A copy of what each device's stream did so far.

        Taken without a lock: while the stream runs it may be slightly old; once
        the readers ended it is exact. Before `start` the ``started_at`` of each
        device is the time the stream was created.
        """
        return StreamSummary(tuple(unit.summary() for unit in self._core.units))


def _check_limit(name: str, value: object, minimum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        msg = f"{name} must be an int, not {type(value).__name__}"
        raise TypeError(msg)
    if value < minimum:
        msg = f"{name} must be at least {minimum}, got {value}"
        raise ValueError(msg)


def _check_reconnect(value: object) -> float:
    """``value`` as a budget in seconds (``math.inf`` allowed), or raise."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        msg = f"reconnect must be a number of seconds, not {type(value).__name__}"
        raise TypeError(msg)
    try:
        seconds = float(value)
    except OverflowError:  # an int beyond the range of a float
        seconds = math.inf if value > 0 else -math.inf
    if math.isnan(seconds) or seconds < 0:
        msg = f"reconnect must be 0 or more seconds, got {value}"
        raise ValueError(msg)
    return seconds


def _check_since(value: object) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        msg = f"since must be 'now' or None, not {type(value).__name__}"
        raise TypeError(msg)
    if value != "now":
        msg = f"since must be 'now' or None, got {value!r}"
        raise ValueError(msg)


def _devices(devices: Iterable[Device | str]) -> list[Device]:
    """The devices as a list of `Device`; strings become ``Device(serial)``."""
    if isinstance(devices, str | bytes):
        msg = "devices must be an iterable of Device objects or serial strings"
        raise TypeError(msg)
    try:
        given = list(devices)
    except TypeError:
        msg = f"devices must be an iterable, not {type(devices).__name__}"
        raise TypeError(msg) from None
    if not given:
        msg = "devices must not be empty"
        raise ValueError(msg)
    serials: list[str] = []
    for item in given:
        if isinstance(item, Device):
            serials.append(item.serial)
        elif isinstance(item, str):
            serials.append(item)
        else:
            msg = (
                "devices must hold Device objects or strings, "
                f"not {type(item).__name__}"
            )
            raise TypeError(msg)
    if len(set(serials)) != len(serials):
        msg = "devices must not repeat a serial"
        raise ValueError(msg)
    return [Device(item) if isinstance(item, str) else item for item in given]


def _check_arguments(
    where: Condition | None,
    caller: str,
    *,
    level: LogLevel | None,
    tag: str | list[str] | tuple[str, ...] | None,
    message: str | None,
    package: str | list[str] | tuple[str, ...] | None,
    pid: int | list[int] | tuple[int, ...] | None,
    since: object,
    reconnect: object,
    buffer_lines: object,
    buffer_bytes: object,
    detect_skips: object = False,
    on_entry: object = None,
) -> tuple[Condition | None, float]:
    """Check the arguments `stream` and `astream` have in common.

    Returns the condition (None when there is none) and the reconnect budget in
    seconds. ``caller`` is the function's name, for the messages.
    """
    _check_since(since)
    budget = _check_reconnect(reconnect)
    if not isinstance(detect_skips, bool):
        msg = f"detect_skips must be a bool, not {type(detect_skips).__name__}"
        raise TypeError(msg)
    _check_limit("buffer_lines", buffer_lines, 1)
    _check_limit("buffer_bytes", buffer_bytes, _MIN_BUFFER_BYTES)
    if on_entry is not None and not callable(on_entry):
        msg = f"on_entry must be callable, not {type(on_entry).__name__}"
        raise TypeError(msg)
    condition = build_condition(
        where, level=level, tag=tag, message=message, package=package, pid=pid
    )
    if condition is not None and condition._has_package():
        msg = f"conditions on the app (Package) are not supported by {caller}() yet"
        raise NotImplementedError(msg)
    return condition, budget


def stream(
    devices: Iterable[Device | str],
    where: Condition | None = None,
    *,
    level: LogLevel | None = None,
    tag: str | list[str] | tuple[str, ...] | None = None,
    message: str | None = None,
    package: str | list[str] | tuple[str, ...] | None = None,
    pid: int | list[int] | tuple[int, ...] | None = None,
    since: Literal["now"] | None = None,
    on_entry: Callable[[LogEntry], object] | None = None,
    reconnect: float = 60.0,
    detect_skips: bool = False,
    buffer_lines: int = 10_000,
    buffer_bytes: int = 4 * 1024 * 1024,
) -> LogStream:
    """Read the log of one or more devices live.

    The stream is returned without being started. Entries of one device come
    in the order the device logged them; entries of different devices are not
    reordered. When a device fails while the stream runs, the whole stream ends:
    the other devices are stopped (a device that was only stopped ends without
    an error), the entries already queued are delivered, and then the first
    error is raised (``details["serial"]`` names its device). A failing
    ``start()`` raises at once and leaves nothing open. Every entry has the
    ``serial`` of its device.

    When the connection to a device ends (the adb server restarted, the cable
    was pulled, logd cut the reader off, or logcat exited) the stream connects
    again and resumes from just before the newest line it had read, dropping the
    lines it already delivered, so that usually nothing is missing or repeated. It
    reports what it cannot tell as `Gap` records, which `LogStream.items`
    yields at the place where the stream noticed them (iterating the stream
    skips them; the counts in `LogStream.summary` include them). A gap has a
    ``reason``:

    - ``ring_rotated``: lines read before the disconnect did not come back
      when the resume check ended, so the device probably no longer has them;
      lines after them may be missing too. The number is not known (it can be
      0). If they come back later, they are delivered a second time.
    - ``continuity_unknown``: it could not be verified that the new connection
      continues the old one (less history than the overlap needed, a line older
      than the resume point that had not been read, or a device clock that
      stepped back); lines may be missing or repeated.
    - ``device_reported``: an Android 7 device wrote a ``chatty`` notice that
      it dropped lines (``lost`` holds the count). The notice line is delivered
      as an entry as well, and the gap comes right before it.

    and a ``cause``: ``released`` (logd cut the reader off), ``disconnected``
    (the connection was lost or logcat ended), ``stalled`` (with
    ``detect_skips``, on an older logd: the reader closed the connection itself
    because it waited a second for room in the queue) or ``notice`` (for
    ``device_reported``). At most one gap is reported for one disconnect. A gap
    is reported only when the check can tell, so some losses go unreported:

    - Lines that reached logd more than one second after their time stamp (or
      after the device clock stepped back), when logd leaves them out of the
      replay.
    - Lines lost from a buffer in which no line was read during the last second
      before the disconnect, and deletions in the middle of a ring that remove
      only unread lines (logd pruning a chatty source, another tool running
      ``logcat -c``).
    - Lines an older logd skipped without a notice while the reader was slow:
      all of them without ``detect_skips``; with it, those skipped before the
      reader had waited a whole second for room.
    - Lines that do not parse: a replayed one is delivered twice without a gap.

    It may also report too much: ``ring_rotated`` when the ring dropped only
    lines that had been read or when the replay came more than one second
    late, and ``continuity_unknown`` together with repeated lines when logd
    replays from before the resume point and the history no longer holds those
    lines.

    Args:
        devices: `Device` objects or serial strings (a string becomes
            ``Device(serial)``), at least one, no serial twice.
        where: Only entries for which the condition holds are delivered.
        level: Shortcut: at least this level.
        tag: Shortcut: one of these tags.
        message: Shortcut: the message contains this text.
        package: Shortcut: lines of these apps (not implemented yet).
        pid: Shortcut: one of these process ids.
        since: ``None`` (the default) starts with the backlog the device still
            holds. ``"now"`` skips it: ``start()`` reads each device's clock,
            writes a marker line into its log and connects; the stream drops
            every line up to that marker and delivers what comes after. The
            marker itself, and markers that earlier runs left in the log, are
            never delivered. A line the device logged in the same second as
            the start may still come before or after the marker. The summary
            counts what was read before the marker in ``lines``, ``unparsed``,
            ``truncated`` and ``gaps`` too; ``entries`` counts only entries
            after the marker. So a line before the marker that does not parse
            still makes the summary incomplete (``complete`` is False). The marker
            is an ordinary line in the device's main log buffer (tag
            ``logprobe``, message ``start-`` and 32 hex digits): other
            readers of the device log, such as ``adb logcat``, see it. If a
            command fails (in ``start()``; a device or adb server that cannot
            be reached raises its own code instead), or the marker does
            not come back within 10 seconds of connecting (while reading), the
            stream fails with ``device_command_failed``.
        on_entry: Called on a consumer thread for every entry, one at a time.
            It must return. The stream cannot then be iterated.
        reconnect: Seconds the stream may spend getting a device back after it
            lost its connection, counted from the first failure after the last
            connection that stayed open for 10 seconds after its first
            standard output. The waits between attempts grow from 1 to 30
            seconds. The budget is checked when a failure happens, so it is not
            a deadline: an attempt that starts just before it runs out can
            still connect. When a failure finds it used up, the stream
            ends with ``device_lost`` (``adb_server_unavailable`` or
            ``adb_error`` when the last attempt failed that way). ``math.inf``
            never runs out of budget. 0 means: do not reconnect after a lost
            connection, an ended logcat or a failed logcat (the stream then ends with
            ``device_lost`` or ``logcat_failed``); connections that logd cut
            off, or that the reader closed itself (``detect_skips``), are still
            resumed, and three in a row that each end within a second of
            opening end the stream with ``logcat_failed``. Reconnecting never
            starts the adb server. ``logcat_failed`` also ends the stream when
            the first connection exits with a status from 1 to 127 before any
            standard output, other than logd's cut-off (even with
            ``math.inf``), or when logcat keeps failing or keeps being cut off
            quickly until the budget is used up.
        detect_skips: Also detect the lines that an older logd drops without
            any notice when the consumer falls behind. Off by default: it
            costs a device command at the start, and a reconnect whenever the
            queue stays full. With it, ``start()`` reads each device's API
            level once (``getprop ro.build.version.sdk``). On API levels 25
            and below and on 30, logd may skip lines of a reader that does not
            keep up instead of cutting it off. There the reader closes its
            connection itself once it has waited a whole second for room in
            the queue since it last read from the device, waits until the
            queue is at most half full (in lines and in bytes), and connects
            again as after any other disconnect; lines the device no longer
            has are then reported as a gap with the cause ``stalled``. That
            wait counts as waiting for room, so it does not use up the budget
            of ``stop(flush=)``. Other API levels cut a slow reader off
            themselves, which the stream always detects, so the flag is
            ignored for them (an INFO message says so). A device whose API
            level cannot be read (the command fails, prints no number or a
            number of more than four digits, or takes longer than 5 seconds)
            is treated as an older one (a WARNING says
            so); an adb error while reading it fails ``start()`` as the other
            start steps do. API levels 25, 27, 33 to 35 and above 36 were not
            tested; 25 is treated as older, the others as newer. Not detected
            even with the flag: lines logd skipped before the reader had
            waited a whole second, and lines skipped while the reader never
            waits a whole second in all for room between two reads from the
            device (a slow consumer that still takes lines often enough).
            With several devices, a device that closed its connection this
            way connects again only once the queue is half empty: while the
            other devices keep it fuller than that (they log more than a slow
            consumer takes), it stays disconnected, and lines that its own log
            buffer on the device overwrites meanwhile are lost. They are
            reported as a gap when it connects again where the gap check can
            tell; the losses listed above as unreported stay unreported, such
            as those of a buffer in which no line was read during the last
            second before the disconnect.
        buffer_lines: Most lines queued for the consumer, over all devices (at
            least 1). A slow consumer makes the readers wait; nothing is dropped.
        buffer_bytes: The same limit in bytes of logcat output (at least 65536).

    The shortcuts and ``where`` are combined with AND.

    Raises:
        TypeError: An argument has the wrong type (a bool is not a number).
        ValueError: A value is out of range (``reconnect`` is NaN or negative,
            ``since`` is a string other than ``"now"``), ``devices`` is empty or
            repeats a serial, or a shortcut value is invalid.
        NotImplementedError: The condition tests the app of a line (``Package``).
        LogprobeError: A serial string names no usable device (see `Device`).

    When iterating or joining, the error that ended the stream is raised:
    ``device_lost``, ``logcat_failed`` or ``adb_error``,
    ``adb_server_unavailable``, as described under ``reconnect``, and
    ``device_command_failed`` when a command that ``since="now"`` needs
    failed after the start (the start marker did not come back).
    """
    condition, budget = _check_arguments(
        where,
        "stream",
        level=level,
        tag=tag,
        message=message,
        package=package,
        pid=pid,
        since=since,
        reconnect=reconnect,
        buffer_lines=buffer_lines,
        buffer_bytes=buffer_bytes,
        detect_skips=detect_skips,
        on_entry=on_entry,
    )
    return LogStream(
        _devices(devices),
        condition,
        on_entry,
        budget,
        buffer_lines,
        buffer_bytes,
        since,
        detect_skips=detect_skips,
    )
