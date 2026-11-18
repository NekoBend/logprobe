"""Live log streams on asyncio: one reader task per device, one shared queue.

``astream`` builds an `AsyncLogStream` for one or more devices. It is the
counterpart of `logprobe.stream`: the same arguments, the same entries, `Gap`
records, counters, summaries and errors. Starting it opens one ``logcat``
connection per device (with the asyncio adb client of ``_aadb``) and starts one
reader task per connection (``logprobe-reader-<serial>``). A reader decodes the
shell protocol, turns the bytes into entries with a `Feeder` and puts the
chunks into the `AsyncOutbox` that all readers share; the consumer is the
caller, iterating the stream with ``async for``. A reader makes the same
decisions as a reader thread of the blocking stream: what to do when a
connection ends, and what the markers ask for, come from the same pure code
(``_resume``, ``_marks``) and from the same helper functions of ``_stream``.
The two readers differ only in how they wait and do I/O.

Nothing here starts a thread, an executor or a process, and nothing ever starts
an adb server. One stream lives on one event loop: the loop that was running
when `AsyncLogStream.start` was called.

Tasks and shared state
----------------------

- There is no lock. Everything runs on the loop's thread, one step at a time,
  and a step that does not ``await`` cannot be interrupted. So the counts, the
  order in which waiting readers are let in, the time each reader spent waiting
  for room, the first error and the flush request are plain attributes.
- Three values may be written from another thread: the stop flag and the kill
  flag, which are the queue's own plain attributes (``stop()`` and ``kill()``
  only set them, so they are safe to call from any thread, a signal handler or
  a finalizer; the finalizer of an abandoned stream sets the kill flag), and
  the flush request noted by ``stop(flush=)`` (below). Every wait is cut into
  slices of ``TICK`` (0.25) seconds and looks at the flags after each slice: a
  reader between two reads, a consumer between two takes, a waiting producer
  between two waits, a pause between two sleeps. ``stop(flush=)`` changes
  shared state, so from another thread it only notes the request (budget and
  moment, one plain attribute, so that it keeps its order with a ``stop()`` or
  ``kill()`` of the same thread) and hands it to the loop with
  ``call_soon_threadsafe``, which applies it there.
- Two more writes are harmless exceptions: the iteration slot, which the
  garbage collector may give back from another thread when an iterator ends up
  in a reference cycle, and a kill that arrives from another thread while the
  consumer is handing over an entry (that one is still delivered).
- A reader alone writes the counters of its device (they live in its
  `Feeder`), its summary fields and its flush state; ``summary`` copies them
  without any protection, so a summary read while the stream runs may be
  slightly old, and is exact once the readers ended.
- Reading is cut into slices of ``TICK``: a read runs under
  ``asyncio.timeout``, and a read that is cut loses nothing (the client keeps
  what it decoded). A reader stops taking output for one step once it holds
  about 8 KiB, and yields to the loop after every read; the iteration yields
  once per chunk it takes from the queue. The part of one packet that one
  network read brings (up to 64 KiB) is fed in one step, so a large packet can
  make a long step: devices send about one line per packet, and the step is
  then short. A fast device or a consumer that never waits therefore keeps the
  other tasks waiting for a few milliseconds at most.
- Only the reads of logcat output ask a cancel callback of the client
  (`AsyncShellStream.set_cancelled`); a one-shot command, the check of the
  device features and a connection handshake have none, so they run as a
  child task of the reader, which looks at its flags every ``TICK`` seconds
  and cancels the child when the stream stops or a deadline of the device
  passes.
- The package list taken every 30 seconds with a condition on the app runs
  as a task of its own (``logprobe-list-<serial>``) beside the reader, which
  goes on reading. The task only runs the list's commands and fills in its
  `ListJob`; the reader hands the job to the device's attributor once the
  task is done: by itself only before a new network read, never between the
  batches of one; but a batch that needs a list waits for the task and hands
  the job over as soon as it is done, so the batches of that network read
  before it were judged with the older list (each line judged with a list
  that the new one shows was outdated is still counted). The reader cancels
  the task when it ends: a reader that ends by itself also awaits it, and
  leaving ``async with`` through an exception or a cancellation cancels and
  waits for the list tasks with the readers, also one that a reader dropped and
  was still awaiting. A list task is cancelled once only: its cleanup awaits
  the command it runs. A list task that failed unexpectedly after its reader
  stopped looking at it is logged at ERROR level.

Cancellation. A reader that is cancelled at any ``await`` closes its connection
and lets ``CancelledError`` pass; since nobody would then take what it queued,
it also kills the stream. As after a kill, a protocol error it had decoded
already still ends the stream. Leaving ``async with`` through an exception or a
cancellation first aborts the transports of all open connections (no
``await``), then cancels the readers and waits for them for a short time; a
second cancellation in that wait cancels the readers again and waits for the
package list tasks to end before it goes on, so that no list is left running.

A reader references only the shared internal state (`_ACore` and `_AUnit`),
never the public `AsyncLogStream`, so an abandoned stream is finalized and its
readers stop within a tick.
"""

# ruff: noqa: SLF001  (the stream, its iteration and its devices share internals)

from __future__ import annotations

import asyncio
import contextlib
import logging
import weakref
from datetime import UTC, datetime
from functools import partial
from time import monotonic, perf_counter
from typing import TYPE_CHECKING, Any, Literal, Self, cast

from . import _adb, _attribution, _marks
from ._aadb import AsyncShellStream, aopen_shell, arequire_shell_v2, arun_shell
from ._adb import TICK
from ._aoutbox import AsyncOutbox
from ._attribution import Listed
from ._errors import LogprobeError
from ._marks import Act, FlushRequest, Phase, Step
from ._outbox import STALLED
from ._records import Gap, StreamSummary
from ._resume import Decision, EndKind, ReconnectPolicy, ResumeCheck
from ._stream import (
    _BOUNDARY_COMMAND,
    _LIST_CUT,
    _SDK_COMMAND,
    _STOPPED_LISTING,
    _arm_start_marker,
    _attempt_cancelled,
    _attempt_failed,
    _begin_connection,
    _begin_start_marker,
    _check_arguments,
    _command_timed_out,
    _connection_ended,
    _CoreBase,
    _device_clock,
    _DeviceEnded,
    _devices,
    _end_list,
    _failure_of,
    _feed_output,
    _finish,
    _first_argv,
    _flush_limits,
    _flush_overran,
    _idle_ended,
    _judge_logd,
    _judge_read,
    _list_cancelled,
    _list_is_due,
    _list_limit,
    _list_too_late,
    _list_wait_step,
    _listing_wait_step,
    _marker_command,
    _marking_step,
    _next_attempt,
    _pause_step,
    _Phase,
    _read_limit,
    _Retry,
    _routed,
    _RunBase,
    _scheduled_late,
    _set_boundary,
    _settle_failed,
    _start_failure,
    _start_list_late,
    _succeeded,
    _take_listing,
    _Unit,
    _unpack,
)

if TYPE_CHECKING:
    from collections.abc import (
        AsyncIterator,
        Awaitable,
        Callable,
        Iterable,
        Sequence,
    )
    from types import TracebackType

    from ._adb import ShellEvent, ShellResult
    from ._attribution import ListJob
    from ._conditions import Condition
    from ._device import Device
    from ._entry import LogEntry, LogLevel
    from ._feed import Chunk, Segment

_LOG = logging.getLogger(__name__)

# The most output bytes a reader takes before it lets the loop run other tasks.
_BATCH_BYTES = 8 * 1024

# How long leaving ``async with`` waits for cancelled readers to end.
_REAP_WAIT = 2 * TICK

__all__ = ["AsyncLogStream", "astream"]


class _AListing:
    """The regular package list of a device while it runs beside the reader.

    ``task`` runs the commands of ``job`` and fills the job in; the reader
    alone hands the job to the attributor once the task is done, also when
    the reader ends (`_settle_listing`).
    """

    __slots__ = ("job", "task")

    def __init__(self, job: ListJob, task: asyncio.Task[None]) -> None:
        self.job = job
        self.task = task


class _AUnit(_Unit):
    """A device of an asyncio stream: its connection and reader task."""

    __slots__ = ("alisting", "broken", "dropped", "stream", "task")

    def __init__(
        self, device: Device, condition: Condition | None, reconnect: float
    ) -> None:
        super().__init__(device, condition, reconnect)
        self.stream: AsyncShellStream | None = None
        self.task: asyncio.Task[None] | None = None
        # A protocol error the reader had decoded when it was cancelled; it
        # still ends the device, as on a kill.
        self.broken: LogprobeError | None = None
        # The regular package list while it runs beside the reader (the
        # blocking stream's ``listing`` stays None), and the task of the one
        # the reader dropped when it ended, until it is done.
        self.alisting: _AListing | None = None
        self.dropped: asyncio.Task[None] | None = None


class _ACore(_CoreBase[AsyncOutbox]):
    """The state shared by the reader tasks, the consumer and the public stream."""

    __slots__ = ("flush_asked",)

    def __init__(self, units: list[_AUnit], outbox: AsyncOutbox) -> None:
        super().__init__(units, outbox)
        # (budget, perf_counter() of the call) of a flush that another thread
        # asked for; the loop turns it into the real request.
        self.flush_asked: tuple[float, float] | None = None

    def ask_flush(self, seconds: float) -> None:
        """Note a flush request made on another thread, at the moment of the call.

        One plain attribute is written, as ``request_stop`` does. Nothing is
        noted after a stop or kill, or when a request was noted already.
        """
        if self.flush_asked is None and not self.outbox.stopping:
            self.flush_asked = (seconds, perf_counter())

    def apply_asked_flush(self) -> None:
        """On the loop: make the noted request real, even if a stop came after it.

        Called by the handed-over call, by a later ``stop(flush=)`` on the loop
        and by a reader that ends, whichever comes first. The budget counts
        from the moment of the call, and so do the readers' queue waits: a wait
        in progress counts up to that moment. A wait that ended between the
        call and now (the loop runs the handed-over call at its next step) is
        counted whole, so at most that short time is not given back to the
        budget. A later stop or kill ends the flush as cancelled, as it does on
        the blocking stream.
        """
        asked = self.flush_asked
        if asked is not None and self.flush is None:
            seconds, began = asked
            self.flush = FlushRequest(seconds, began, self.outbox._totals(began))
            self.outbox.interrupt_waiters()


class _ARun(_RunBase):
    """One connection of an asyncio reader."""

    __slots__ = ("broken", "decoded", "left", "received", "stream")

    def __init__(
        self, stream: AsyncShellStream, serial: str, check: ResumeCheck | None
    ) -> None:
        super().__init__(serial, check)
        self.stream = stream
        # ``stream.decoded()`` after the last batch (those events need no new
        # network read), when the last network read was received
        # (``perf_counter``; a read's wait for the package list counts from
        # then), and with a stall limit, the seconds of it the waits for room
        # since then have left.
        self.decoded = 0
        self.received = 0.0
        self.left: float | None = None
        # A protocol error the reader found and has not raised yet.
        self.broken: LogprobeError | None = None

    def stall(self) -> None:
        """Close the connection: the reader waited too long for room."""
        self.stalled = True
        self.stream.close()


# -- waiting for the client ---------------------------------------------------------


def _retire[T](discard: Callable[[T], object] | None, task: asyncio.Task[T]) -> None:
    """A child task ended after its caller left: free what it produced."""
    if not task.cancelled() and task.exception() is None and discard is not None:
        discard(task.result())


async def _cancellable[T](
    operation: Awaitable[T],
    cancelled: Callable[[], bool],
    discard: Callable[[T], object] | None = None,
) -> T:
    """Await ``operation``; raise `Cancelled` within ``TICK`` of ``cancelled()``.

    The operation runs as a child task, because the client has no cancel
    callback for a one-shot command, a feature check or a connection
    handshake. When this call ends without handing the result over (cancelled
    itself, stopped, or the operation failed) the child is cancelled and
    awaited, and what it produced anyway is passed to ``discard``.

    Raises:
        Cancelled: ``cancelled()`` turned true first.
    """
    if cancelled():
        if asyncio.iscoroutine(operation):
            operation.close()
        raise _adb.Cancelled
    task = asyncio.ensure_future(operation)
    try:
        while not task.done():
            await asyncio.wait((task,), timeout=TICK)
            if not task.done() and cancelled():
                raise _adb.Cancelled
        return task.result()
    except BaseException:
        task.add_done_callback(partial(_retire, discard))
        if not task.done():
            task.cancel()
            await asyncio.wait((task,))
        raise


async def _open_logcat(
    unit: _Unit,
    argv: list[str],
    cancelled: Callable[[], bool],
    deadline: float | None = None,
) -> AsyncShellStream:
    """Start ``argv`` on the device and return its output stream.

    With a ``deadline`` the adb layer's limit per step is off, and
    ``cancelled`` must turn true when the deadline passes; `_attempt_cancelled`
    does, on the clock of the flush budget, so the handshake never ends before
    the budget does. (A timer of the event loop could fire up to one tick of
    the loop's clock early: 15.6 ms on Windows with Python 3.12.)

    Raises:
        Cancelled: ``cancelled()`` turned true first.
    """
    address, serial = unit.device._address, unit.serial
    if deadline is None:
        opening = aopen_shell(address, serial, argv)
    else:
        opening = aopen_shell(address, serial, argv, timeout=None)
    return await _cancellable(opening, cancelled, AsyncShellStream.close)


async def _run_command(
    core: _ACore,
    unit: _Unit,
    argv: Sequence[str],
    limit: float,
    cancelled: Callable[[], bool] | None = None,
) -> ShellResult:
    """Run a one-shot command; `Cancelled` within ``TICK`` of a stop.

    ``cancelled`` replaces the check of the stop flag (it must include it).
    """
    command = arun_shell(unit.device._address, unit.serial, argv, limit)
    return await _cancellable(
        command, core.cancelled if cancelled is None else cancelled
    )


# -- the package list (see the blocking reader) -------------------------------------


async def _take_list(
    core: _ACore,
    unit: _Unit,
    deadline: float,
    cancelled: Callable[[], bool],
    *,
    late: str = _LIST_CUT,
    starting: bool = False,
) -> str | None:
    """Take the device's package list (see the blocking `_take_list`).

    Raises:
        Cancelled: At the start (``starting``): the stream was stopped.
        LogprobeError: At the start: the device or the adb server failed.
    """
    attributor = unit.attributor
    assert attributor is not None  # noqa: S101
    job = attributor.list_started(perf_counter())
    job.started = perf_counter()
    while not job.finished:
        limit = (
            deadline - perf_counter() if starting else _list_limit(core, unit, deadline)
        )
        if limit <= 0:
            job.fail(late)
            break
        by_flush = not starting and _flush_limits(core, unit, deadline)
        try:
            result = await _run_command(core, unit, job.argv, limit, cancelled)
        except _adb.Cancelled:
            if starting:
                raise
            if core.outbox.stopping:
                return _STOPPED_LISTING
            job.fail(late)
        except TimeoutError:
            unit.flush_cut = unit.flush_cut or by_flush
            job.fail(late)
        except (LogprobeError, OSError) as error:
            if starting:
                raise
            job.fail(f"failed ({error})")
        else:
            job.take(result.exit_status, result.stdout, result.stderr)
            late_answer = isinstance(job.outcome, Listed) and not starting
            if late_answer and _list_too_late(core, unit, deadline):
                job.fail(late, result.stderr)
    return _end_list(unit, job)


async def _list_for_read(
    core: _ACore, unit: _AUnit, segments: list[_attribution.Segment], deadline: float
) -> str | None:
    """Get a list for a read whose ``segments`` need one (see the blocking one)."""
    if unit.alisting is not None:
        cause = await _wait_listing(core, unit, deadline)
        attributor = unit.attributor
        assert attributor is not None  # noqa: S101
        if cause is not None or not attributor.needs_list(segments):
            return cause
    while True:
        step = _list_wait_step(core, unit, deadline)
        if step is None:
            break
        if isinstance(step, str):
            return step
        await asyncio.sleep(step)
    end = min(deadline, perf_counter() + _marks.COMMAND_LIMIT)
    return await _take_list(core, unit, end, _list_cancelled(core, unit, end))


async def _run_listing(
    core: _ACore, unit: _Unit, job: ListJob, deadline: float
) -> None:
    """The task of the regular list: run the commands of ``job`` by ``deadline``.

    A command cut by the stop flag or by the deadline fails the list as late.
    After a kill the outcome is not used. After a stop a list that succeeded
    (its last command ended before the stop could cut it) is still handed over
    as the reader ends if this task is done by then (`_settle_listing`); a
    failed one, a command cut short by the stop included, is discarded. The
    pacing to the next list counts from when the first command starts.
    """

    def cancelled() -> bool:
        return core.cancelled() or perf_counter() >= deadline

    job.started = perf_counter()
    while not job.finished:
        limit = deadline - perf_counter()
        if limit <= 0:
            job.fail(_scheduled_late())
            break
        try:
            result = await _run_command(core, unit, job.argv, limit, cancelled)
        except (_adb.Cancelled, TimeoutError):
            job.fail(_scheduled_late())
        except (LogprobeError, OSError) as error:
            job.fail(f"failed ({error})")
        else:
            job.take(result.exit_status, result.stdout, result.stderr)


def _start_listing(core: _ACore, unit: _AUnit) -> None:
    """Start the regular list as a task of its own; the reader goes on."""
    attributor = unit.attributor
    assert attributor is not None  # noqa: S101
    now = perf_counter()
    job = attributor.list_started(now)
    task = asyncio.create_task(
        _run_listing(core, unit, job, now + _marks.COMMAND_LIMIT),
        name=f"logprobe-list-{unit.serial}",
    )
    unit.alisting = _AListing(job, task)


def _collect_listing(core: _ACore, unit: _AUnit) -> bool:
    """Hand a regular list whose task is done to the attributor.

    Returns False while the list runs, True when none runs (any more).

    Raises:
        Exception: The task failed unexpectedly (a bug).
    """
    listing = unit.alisting
    if listing is None:
        return True
    if not listing.task.done():
        return False
    unit.alisting = None
    listing.task.result()
    _take_listing(core, unit, listing.job)
    return True


async def _wait_listing(core: _ACore, unit: _AUnit, deadline: float) -> str | None:
    """Wait for the regular list that runs, for a read (see the blocking one)."""
    while True:
        step = _listing_wait_step(core, unit, deadline)
        if isinstance(step, str):
            return step
        if _collect_listing(core, unit):
            return None
        listing = unit.alisting
        assert listing is not None  # noqa: S101
        await asyncio.wait((listing.task,), timeout=step)


def _tend_listing(core: _ACore, unit: _AUnit) -> None:
    """Hand over a regular list that ended, and start the next one when it is due."""
    if _collect_listing(core, unit) and _list_is_due(core, unit):
        _start_listing(core, unit)


def _cancel_once(task: asyncio.Task[Any]) -> None:
    """Cancel ``task`` unless it is done or being cancelled already.

    A second cancel would cut the task's own cleanup short (`_cancellable`
    awaits its child task after the first one).
    """
    if not task.done() and not task.cancelling():
        task.cancel()


def _settle_listing(
    core: _ACore, unit: _AUnit, error: LogprobeError | None
) -> LogprobeError | None:
    """The reader ends: hand over a regular list whose task is done already.

    As the blocking `_settle_listing`: not after a kill, after a stop only a
    list that succeeded, and a task that failed is left to `_drop_listing`.
    Returns the reader's error, or the handover's unexpected failure when the
    reader has none (`_settle_failed`).
    """
    listing = unit.alisting
    if listing is None:
        return error
    task = listing.task
    if not task.done() or task.cancelled() or task.exception() is not None:
        return error
    unit.alisting = None
    try:
        _take_listing(core, unit, listing.job)
    except Exception as failure:  # noqa: BLE001  (a bug; the reader still ends)
        return _settle_failed(unit, error, failure)
    return error


def _drop_listing(unit: _AUnit) -> asyncio.Task[None] | None:
    """The reader ends: cancel the regular list's task and return it.

    Its outcome is never used. The caller awaits the task when it can; until
    the task is done it stays in ``unit.dropped``, for `AsyncLogStream._reap`.
    """
    listing = unit.alisting
    if listing is None:
        return None
    unit.alisting = None
    task = listing.task
    unit.dropped = task
    _cancel_once(task)
    task.add_done_callback(partial(_report_left, unit.serial))
    return task


def _report_left(serial: str, task: asyncio.Task[None]) -> None:
    """Log the unexpected failure of a regular list's task that was dropped.

    The done callback of the task once its reader ended: nobody else takes
    its exception. A log handler that fails here is not passed on to the
    event loop's exception handler.
    """
    if task.cancelled():
        return
    error = task.exception()
    if error is not None:
        with contextlib.suppress(Exception):
            _LOG.error(
                "%s: the regular package list failed after the reader had ended",
                serial,
                exc_info=error,
            )


async def _judged(
    core: _ACore, unit: _AUnit, segments: list[Segment], received: float
) -> list[Segment]:
    """One routed chunk of a read, judged (see the blocking `_judged`)."""
    if core.outbox.killed:
        return []
    attributor = unit.attributor
    assert attributor is not None  # noqa: S101
    judged = cast("list[_attribution.Segment]", segments)
    cause: str | None = None
    if attributor.needs_list(judged, running=unit.alisting is not None):
        cause = await _list_for_read(
            core, unit, judged, received + _attribution.LIST_WAIT
        )
        if core.outbox.killed:
            return []
        _flush_overran(core, unit, cause)
    return _judge_read(unit, judged, cause)


# -- reading ---------------------------------------------------------------------


class Batch:
    """The output events one wait for the device brought, ready to be fed."""

    __slots__ = ("broken", "ended", "err", "out", "size")

    def __init__(self) -> None:
        self.out: list[bytes] = []
        self.err: list[bytes] = []
        self.size = 0
        self.ended = False  # the connection ended (the exit status is known)
        self.broken: LogprobeError | None = None  # the protocol broke after them

    def add(self, event: ShellEvent) -> None:
        kind, data = event
        (self.out if kind == "stdout" else self.err).append(data)
        self.size += len(data)

    def __bool__(self) -> bool:
        return bool(self.out or self.err)


async def gather(stream: AsyncShellStream, limit: float | None) -> Batch:
    """Wait up to ``limit`` seconds for output, then take all that is ready.

    With ``limit`` None the wait has no limit of its own; a per-read limit set
    with ``stream.set_timeout`` that runs out ends it too, with nothing taken.

    What arrived of a packet is taken at once, as the blocking reader sees it.

    The first event may take the whole time; after it only what the stream has
    decoded already is taken, never a new network read. So a batch holds the
    output of one network read at most, all of which arrived at the same time
    (``stream.received_at``, after a batch that started a new read). The
    reader then feeds the whole batch in one piece, as the blocking reader
    does with one receive.

    A read that needs a new network read after a stop ends the batch too (see
    `AsyncShellStream.set_cancelled`), even when the last network read
    brought only part of a packet.
    """
    batch = Batch()
    try:
        async with asyncio.timeout(limit):
            while batch.size < _BATCH_BYTES:
                if batch and stream.needs_read():
                    break
                event = await stream.read_part()
                if event is None:
                    batch.ended = True
                    break
                batch.add(event)
    except (TimeoutError, _adb.Cancelled):
        pass  # nothing more is ready, or the stream stopped
    except LogprobeError as broken:
        batch.broken = broken
    return batch


async def _queue_read(
    core: _ACore, unit: _AUnit, run: _ARun, chunks: list[Chunk], batch: Batch | None
) -> None:
    """Queue what one read yielded (see the blocking `_queue_read`).

    ``batch`` is the batch the chunks were fed from; None for chunks that no
    read brought (the feeder's end of a resume check).

    The batches the stream decoded from one network read belong to one read,
    as one receive does on the blocking stream: they share what is left of the
    stall limit and of the read's wait for a package list, counted from when
    that read returned, and only a new read starts both again. A batch holds
    output of a new read exactly when it has more events than the stream had
    decoded after the batch before; chunks that come from no batch (``batch``
    None) count as a new read that arrived now.

    Raises:
        LogprobeError: The start marker did not come back in time.
    """
    if batch is None:
        run.received = perf_counter()
        run.left = unit.stall_after
    elif len(batch.out) + len(batch.err) > run.decoded:
        run.received = run.stream.received_at
        run.left = unit.stall_after
    run.decoded = run.stream.decoded()
    if unit.stall_after is None:
        await _enqueue(core, unit, chunks, run.received)
    else:
        await _enqueue_limited(core, unit, run, chunks)


async def _enqueue(
    core: _ACore, unit: _AUnit, chunks: list[Chunk], received: float
) -> None:
    """Queue the chunks' segments that the device's markers let through.

    A put that has to wait for room is interrupted by a flush request, as in the
    blocking reader: the marker is written first, and the same chunk is put
    again. ``received`` is when the read the chunks came from was received
    (``perf_counter``).

    Raises:
        LogprobeError: The start marker did not come back in time.
    """
    outbox = core.outbox
    attributor = unit.attributor
    for segments, charge in _routed(unit, chunks):
        if attributor is not None:
            segments = await _judged(core, unit, segments, received)
            if not segments:
                continue
        waited = await outbox.put(segments, charge, unit.serial, interruptible=True)
        if waited is None:
            await _marking(core, unit)
            await outbox.put(segments, charge, unit.serial)


async def _enqueue_limited(
    core: _ACore, unit: _AUnit, run: _ARun, chunks: list[Chunk]
) -> None:
    """The blocking `_enqueue_limited`: close the connection after waiting too long.

    The limit holds for the waits since the stream last received output from
    the device, as on the blocking stream, not for each batch: ``run.left`` is
    what the read's earlier batches left of it (see `_queue_read`). After a
    stall the reader queues the rest of the read too (`_queue_decoded`).

    Raises:
        LogprobeError: The start marker did not come back in time.
    """
    outbox = core.outbox
    serial = unit.serial
    left = run.left
    attributor = unit.attributor
    for segments, charge in _routed(unit, chunks):
        if attributor is not None:
            segments = await _judged(core, unit, segments, run.received)
            if not segments:
                continue
        began = perf_counter()
        waited = await outbox.put(
            segments, charge, serial, interruptible=True, limit=left
        )
        if waited is None:
            if left is not None:
                left -= perf_counter() - began
            await _marking(core, unit)
            waited = await outbox.put(segments, charge, serial, limit=left)
        if waited is STALLED:
            run.stall()
            left = None
            await outbox.put(segments, charge, serial)
        elif left is not None:
            left -= waited
    run.left = left


async def _queue_decoded(core: _ACore, unit: _AUnit, run: _ARun) -> None:
    """The reader leaves the connection: close, then feed and queue what it decoded.

    Closing first means nothing more is read from the device (after a stall the
    reader closed the connection already, so logd no longer holds lines back).
    The events of the last network read that no batch took yet are still in
    the stream, and closing does not drop them. They go in without a limit,
    like the rest of a receive on the blocking stream, so the feeder counts
    their lines and a resume starts after them. What the device sent after
    that read is not delivered, as on the blocking stream.

    Raises:
        LogprobeError: The shell protocol broke after those events (they were
            queued first).
    """
    stream = run.stream
    stream.close()
    rest = Batch()
    try:
        # The stream is closed: this takes what it holds and never waits.
        while (event := await stream.read_part()) is not None:
            rest.add(event)
    except LogprobeError as error:
        run.broken = error
    if rest:
        err = b"".join(rest.err)
        out = b"".join(rest.out)
        await _enqueue(core, unit, _feed_output(unit, run, err, out), run.received)
    run.exit_status = stream.exit_status
    if run.broken is not None:
        raise run.broken


async def _discard_decoded(run: _ARun, broken: LogprobeError | None = None) -> None:
    """After a kill: close, and drop what the stream decoded.

    A protocol error among those events is still raised; ``broken`` is one
    the last batch found already. (The blocking reader raises such an error
    only from a receive it decoded before it saw the kill.)

    Raises:
        LogprobeError: The shell protocol broke in what the reader took.
    """
    stream = run.stream
    stream.close()
    try:
        # The stream is closed: this takes what it holds and never waits.
        while await stream.read_part() is not None:
            pass
    except LogprobeError as error:
        broken = error
    if broken is not None:
        raise broken


async def _end_read(core: _ACore, unit: _AUnit, run: _ARun) -> None:
    """The reader leaves the connection: queue what it decoded, or drop it on a kill.

    Raises:
        LogprobeError: The shell protocol broke in what the reader took.
    """
    if core.outbox.killed:
        await _discard_decoded(run)
    else:
        await _queue_decoded(core, unit, run)


async def _take_decoded(stream: AsyncShellStream) -> Batch:
    """The next batch of what the stream decoded already; it reads nothing new."""
    batch = Batch()
    while batch.size < _BATCH_BYTES and stream.decoded():
        event = await stream.read_part()
        if event is None:  # not reached: decoded events come back first
            break
        batch.add(event)
    return batch


async def _read(core: _ACore, unit: _AUnit, run: _ARun) -> None:
    """Read one connection until it ends, the stream stops or the flush ends.

    The loop of the blocking ``_read``: look at the markers, wait for output (at
    most ``TICK`` seconds), look at the flags, feed the stdout bytes to the
    feeder and queue what it returns. While a resume check is pending, every
    wait that brings no data counts toward its idle time.

    The blocking reader handles a whole receive before it looks at the flags
    and the markers again; this one feeds a network read in batches. So
    whenever it leaves the connection for a reason other than a kill (a stop,
    a stall, a flush that ended), it first queues the batches of the last
    network read that it did not feed yet, and reads nothing more
    (`_queue_decoded`); a kill drops them (`_discard_decoded`). A start marker
    that is late fails the stream only once those batches are fed, since one
    of them may hold the marker, and not when the read ended with an exit
    status: the connection then ends as on the blocking reader. After a stop
    no new read starts.

    Raises:
        LogprobeError: The shell protocol broke (the output before it was
            queued), or the start marker did not come back in time.
    """
    outbox = core.outbox
    stream = run.stream
    while True:
        limit: float | None = TICK
        late = False
        try:
            limit = await _before_read(core, unit, run)
        except LogprobeError as error:  # the start marker is late
            if not stream.decoded():
                await _end_late(core, unit, run, error)
                return
            late = True  # the rest of the last network read comes first
        # None: the stream stopped or the flush ended; a stop may also have
        # come after the last look. Either way no new read starts.
        if limit is None or outbox.stopping:
            await _end_read(core, unit, run)
            return
        began = monotonic()
        batch = await (_take_decoded(stream) if late else gather(stream, limit))
        run.broken = batch.broken
        await asyncio.sleep(0)  # a fast device must not starve the other tasks
        if not batch and not batch.ended and batch.broken is None:
            if await _quiet(core, unit, run, monotonic() - began):
                return
            continue
        if outbox.killed:
            # Drop the batch and the rest, but still raise a protocol error.
            await _discard_decoded(run, batch.broken)
            return
        check = run.pending()
        if check is not None and batch:
            check.received()
        err = b"".join(batch.err)
        out = b"".join(batch.out)
        chunks = _feed_output(unit, run, err, out)
        await _queue_read(core, unit, run, chunks, batch)
        if batch.ended:  # whatever follows the exit packet was ignored
            run.exit_status = stream.exit_status
            return
        if batch.broken is not None:  # the output before it was queued already
            raise batch.broken
        if run.stalled or outbox.stopping:
            await _end_read(core, unit, run)
            return


async def _end_late(
    core: _ACore, unit: _AUnit, run: _ARun, late: LogprobeError
) -> None:
    """The start marker is late and the last network read is fed: leave.

    The stream fails with ``late``, unless that read ended with logcat's exit
    status: the connection then ends as on the blocking reader, which handles
    the exit status of a receive before it looks at the time again.

    Raises:
        LogprobeError: ``late``, or a protocol error in what the reader decoded.
    """
    await _end_read(core, unit, run)
    if run.exit_status is None:
        raise late


async def _before_read(core: _ACore, unit: _AUnit, run: _ARun) -> float | None:
    """Do what the markers ask, and look after the regular list (see the blocking one).

    The regular list is looked after only before a batch that needs a new
    network read, so a list that ends while the batches of one network read
    are judged is taken in before the next network read. A batch that needs a
    list waits for the running one instead (`_list_for_read`) and takes it in
    when it ends: the batches before it were judged with the older list,
    where the blocking reader judges a receive of up to `_feed.CHUNK_ENTRIES`
    lines in one piece.

    Raises:
        LogprobeError: The start marker did not come back in time.
        Exception: The task of the regular list failed (a bug).
    """
    limit = await _marks_limit(core, unit)
    if limit is not None and unit.attributor is not None and not run.stream.decoded():
        _tend_listing(core, unit)
    return limit


async def _marks_limit(core: _ACore, unit: _Unit) -> float | None:
    """`_marking` when a marker is pending, else ``TICK`` (see the blocking one).

    Raises:
        LogprobeError: The start marker did not come back in time.
    """
    if core.flush is not None or unit.marks.phase is Phase.SKIPPING:
        return await _marking(core, unit)
    return TICK


async def _quiet(core: _ACore, unit: _AUnit, run: _ARun, waited: float) -> bool:
    """A wait found no data for ``waited`` seconds; True when to stop reading."""
    outbox = core.outbox
    if outbox.stopping:
        return True
    if _idle_ended(run, waited):
        await _queue_read(core, unit, run, unit.feeder.end_check(), None)
        return outbox.stopping or run.stalled
    return False


async def _marking(core: _ACore, unit: _Unit) -> float | None:
    """Do what the markers ask before the next read (see the blocking `_marking`).

    Raises:
        LogprobeError: The start marker did not come back in time.
    """
    while True:
        step = _marking_step(core, unit)
        if step.act is not Act.WRITE:
            return _read_limit(step)
        await _write_marker(core, unit, step)


async def _write_marker(core: _ACore, unit: _Unit, step: Step) -> None:
    """Write the flush marker of ``step``; its outcome goes to the unit's marks.

    A command that stops because the stream stopped leaves no outcome, and
    neither does one that ended while the stream stopped: the stop wins, and
    the caller sees the flag.
    """
    argv, limit = _marker_command(unit, step)
    try:
        result = await _run_command(core, unit, argv, limit)
    except _adb.Cancelled:
        return
    except (TimeoutError, LogprobeError, OSError):  # no exit status
        unit.marks.command_done(None)
        return
    if core.cancelled():  # a stop that came while the command ended wins
        return
    unit.marks.command_done(result.exit_status)


# -- starting ----------------------------------------------------------------------


async def _one_shot(core: _ACore, unit: _Unit, argv: list[str]) -> ShellResult:
    """Run a command the start needs; return its result (exit status 0 only).

    Raises:
        LogprobeError: ``device_command_failed`` when the command exits with a
            non-zero status, ends without one or takes longer than the limit.
    """
    try:
        result = await _run_command(core, unit, argv, _marks.COMMAND_LIMIT)
    except TimeoutError:
        raise _command_timed_out(unit, argv) from None
    return _succeeded(unit, argv, result)


async def _check_logd(core: _ACore, unit: _Unit) -> None:
    """Read the device's API level and set its stall limit (see the blocking one).

    Raises:
        LogprobeError: The device or the adb server failed.
    """
    try:
        result = await _run_command(
            core, unit, list(_SDK_COMMAND), _marks.COMMAND_LIMIT
        )
    except TimeoutError:
        result = None
    _judge_logd(unit, result)


async def _read_boundary(core: _ACore, unit: _Unit) -> None:
    """Read the device clock that tells the backlog from new lines (``since`` None).

    Raises:
        LogprobeError: The device or the adb server failed.
    """
    try:
        result = await _run_command(core, unit, _BOUNDARY_COMMAND, _marks.COMMAND_LIMIT)
    except TimeoutError:
        result = None
    _set_boundary(unit, result)


async def _prepare(
    core: _ACore, unit: _Unit, *, since: bool, detect_skips: bool
) -> None:
    """Step one of the start for one device: the checks, the package list and
    the start marker (see the blocking `_prepare`)."""
    await _cancellable(
        arequire_shell_v2(unit.device._address, unit.serial), core.cancelled
    )
    if detect_skips:
        await _check_logd(core, unit)
    if unit.attributor is not None:
        if not since:
            await _read_boundary(core, unit)
        deadline = perf_counter() + _marks.COMMAND_LIMIT
        late = _start_list_late()
        await _take_list(core, unit, deadline, core.cancelled, late=late, starting=True)
    if since:
        argv = list(_BOUNDARY_COMMAND)
        result = await _one_shot(core, unit, argv)
        clock = _device_clock(unit, argv, result)
        await _one_shot(core, unit, _begin_start_marker(unit, clock))


async def _open_first(core: _ACore, unit: _AUnit, *, since: bool) -> AsyncShellStream:
    """Step two of the start for one device: open its first logcat connection."""
    stream = await _open_logcat(unit, _first_argv(unit), core.cancelled)
    unit.stream = stream
    _arm_start_marker(unit, since=since)
    return stream


# -- one device across its connections --------------------------------------------


async def _pause(core: _ACore, unit: _Unit, delay: float) -> bool:
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
        await asyncio.sleep(step)


async def _serve(core: _ACore, unit: _AUnit) -> LogprobeError | None:
    """Read one device across its connections; return the error that ended it.

    The flow of the blocking ``_serve``: read a connection, decide from how it
    ended whether to stop or to reconnect (after a stall, once the queue is half
    empty), wait, and open the next one.
    """
    policy = ReconnectPolicy(unit.reconnect)
    stream = unit.stream
    assert stream is not None  # noqa: S101
    check: ResumeCheck | None = None
    first = True
    while True:
        run = _ARun(stream, unit.serial, check)
        stream.set_cancelled(core.cancelled)  # after a stop no network read starts
        try:
            await _read(core, unit, run)
        except asyncio.CancelledError:
            unit.broken = await _decoded_error(run)
            raise
        finally:
            stream.close()
            stream.set_cancelled(None)  # the stream must not keep the core alive
        ended = _connection_ended(core, unit, run, policy, first=first)
        if not isinstance(ended, _Retry):
            return ended
        if ended.kind is EndKind.STALLED and not await core.outbox.wait_half_empty(
            unit.serial
        ):
            return None
        decision = ended.decision
        while True:
            if not await _pause(core, unit, decision.delay):
                return None
            attempt = _next_attempt(core, unit, ended)
            if attempt is None:
                return None
            try:
                stream = await _open_logcat(
                    unit,
                    attempt.argv,
                    _attempt_cancelled(core, unit),
                    attempt.deadline,
                )
                break
            except (_adb.Cancelled, LogprobeError, OSError) as failure:
                failed = _attempt_failed(core, unit, run, policy, failure)
                if not isinstance(failed, Decision):
                    return failed
                decision = failed
        unit.stream = stream
        check = _begin_connection(unit, attempt)
        first = False


async def _decoded_error(run: _ARun) -> LogprobeError | None:
    """A cancelled reader is killed: drop what it decoded; return a protocol error.

    The error is one in what the stream decoded, or one the reader found and
    had not raised yet (``run.broken``), as `_discard_decoded` raises it after
    a kill. Nothing here waits.
    """
    try:
        await _discard_decoded(run, run.broken)
    except LogprobeError as error:
        return error
    return None


async def _settle(tasks: list[asyncio.Task[None]]) -> None:
    """Wait until ``tasks`` (cancelled already) are done, whatever interrupts.

    Each ends within a few steps of the loop; a cancellation of the caller
    meanwhile only makes it wait again (the caller raises its own afterwards).
    """
    pending = [task for task in tasks if not task.done()]
    while pending:
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait(pending)
        pending = [task for task in pending if not task.done()]


def _retrieve(task: asyncio.Task[None]) -> None:
    """Take the exception of an ended reader task, so that none goes unretrieved.

    Only ``KeyboardInterrupt`` and ``SystemExit`` can be there: the reader
    turns every other failure into the stream's error.
    """
    if not task.cancelled():
        task.exception()


async def _reader(core: _ACore, unit: _AUnit) -> None:
    """Read one device's logcat until the stream stops or it cannot go on.

    When the task ends its connection is closed, the first error (if any) stops
    the other readers, and the end of this device is queued. A cancelled reader
    closes its connection, kills the stream (nobody would take what it queued)
    and lets ``CancelledError`` pass; a protocol error it had decoded already
    (``unit.broken``) still ends the device, as after a kill.
    """
    error: LogprobeError | None = None
    listing: asyncio.Task[None] | None = None
    try:
        error = await _serve(core, unit)
    except Exception as failure:  # noqa: BLE001  (every failure ends the stream)
        error = _failure_of(unit, failure)
    except (asyncio.CancelledError, KeyboardInterrupt, SystemExit):
        core.outbox.request_kill()
        if unit.broken is not None:  # decoded before the cancellation
            error = _failure_of(unit, unit.broken)
        raise
    finally:
        if unit.stream is not None:
            unit.stream.close()
        error = _settle_listing(core, unit, error)
        listing = _drop_listing(unit)
        # A flush noted on another thread counts even if the loop has not run
        # the handed-over call yet (a stop of the same thread may end this
        # reader first).
        core.apply_asked_flush()
        _finish(core, unit, error)
    try:
        if listing is not None:
            # Cancelled: it ends at its next step. No task of this device is
            # left once the device's end is queued.
            await asyncio.wait((listing,))
        await core.outbox.put([_DeviceEnded(unit.serial)], 0, unit.serial)
    except asyncio.CancelledError:  # nobody would take what is queued
        core.outbox.request_kill()
        raise


# -- iteration ---------------------------------------------------------------------


class _AsyncIteration:
    """One pass over a stream's output, on the loop that runs the stream.

    A class with ``__anext__`` and not an async generator, so that nothing
    waits for the loop to finalize it. A cancelled ``__anext__`` ends the pass
    (another may start) and loses nothing: what was taken from the queue is kept
    in the stream's shared buffer.
    """

    def __init__(self, owner: AsyncLogStream, *, gaps: bool) -> None:
        self._owner = owner  # keeps the stream alive while it is iterated
        self._core = owner._core
        self._gaps = gaps
        self._done = False

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> LogEntry | Gap:
        core = self._core
        while not self._done:
            if core.rest_pos < len(core.rest):
                item = core.rest[core.rest_pos]
                core.rest_pos += 1
                if core.outbox.killed:
                    break
                if self._gaps or type(item) is not Gap:
                    return item
            else:
                try:
                    more = await self._refill()
                except BaseException:
                    self.close()
                    raise
                if not more:
                    break
        self.close()
        error = core.error
        if error is not None:
            raise error
        raise StopAsyncIteration

    async def _refill(self) -> bool:
        """Wait for the next chunk; False when there will be no more.

        The loop is given to the other tasks first, so that a consumer that
        never waits for anything else cannot hold it for as long as the queue
        stays full.
        """
        await asyncio.sleep(0)
        core = self._core
        buf = core.rest = []
        core.rest_pos = 0
        while not buf:
            if core.drained:
                return False
            chunk = await core.outbox.take(TICK)
            if chunk is not None:
                _unpack(core, buf, chunk)
        return True

    def close(self) -> None:
        """End this iteration, so that another one may start."""
        if not self._done:
            self._done = True
            self._core.iterating = False

    def __del__(self) -> None:
        self.close()


class AsyncLogStream:
    """The live log of one or more devices, for code that runs on asyncio.

    Create it with `logprobe.astream` or `Device.astream`. It is not started
    yet: use it in an ``async with`` statement or ``await`` `start`. A stream is
    used once; after it ended it cannot be started again.

    Iterate it with ``async for entry in stream``, or with `items` to get `Gap`
    records as well. It reads every device on a task of the running event loop
    with the asyncio adb client: no thread, no process and no executor is ever
    started, and the blocking calls of the library are not used while it runs.
    One stream lives on one event loop (the one that was running when it was
    started).

    `stop` and `kill` only set a flag; they never block and may be called from
    any thread or signal handler. All waits of the stream are cut into slices
    of 0.25 seconds, and a flag is seen within one slice.

    Attributes:
        serials: The serials of the devices, in the order given.
    """

    def __init__(
        self,
        devices: list[Device],
        condition: Condition | None,
        reconnect: float,
        buffer_lines: int,
        buffer_bytes: int,
        since: Literal["now"] | None = None,
        *,
        detect_skips: bool = False,
    ) -> None:
        units = [_AUnit(device, condition, reconnect) for device in devices]
        self._units = units
        self._core = _ACore(units, AsyncOutbox(buffer_lines, buffer_bytes))
        self._since = since
        self._detect_skips = detect_skips
        self._phase = _Phase.NEW
        self._loop: asyncio.AbstractEventLoop | None = None
        self.serials: tuple[str, ...] = tuple(unit.serial for unit in units)
        # An abandoned stream stops its readers: this only sets the kill flag.
        weakref.finalize(self, self._core.outbox.request_kill)

    # -- starting ---------------------------------------------------------------

    async def start(self) -> Self:
        """Check the devices, open every connection and start the readers.

        The same three steps as `LogStream.start`: each device is prepared in
        turn (``shell_v2`` check, with ``detect_skips`` the device's API level,
        with a condition on the app the device clock (``since`` None) and the
        package list, and with ``since="now"`` the device clock and the start
        marker), then
        all logcat connections are opened back to back, then all reader tasks
        start (all or none). The readers wait for the start marker, not
        ``start()``. When `stop` or `kill` is called, before or during the
        start, nothing is left open and no reader starts; the stream then ends
        at once without an error.

        If the task that awaits ``start()`` is cancelled, everything that was
        opened is closed and the stream is killed: it counts as ended early
        (iteration ends at once, `join` returns the summary without an error, a
        second `start` raises ``RuntimeError``), and ``CancelledError`` goes on.

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
        self._loop = asyncio.get_running_loop()  # before the phase: see `stop`
        self._phase = _Phase.STARTING
        core = self._core
        since = self._since is not None
        opened: list[AsyncShellStream] = []
        working = self._units[0]
        now = datetime.now(UTC)
        for unit in self._units:
            unit.started_at = now
        try:
            if core.outbox.stopping:
                raise _adb.Cancelled
            for working in self._units:
                await _prepare(
                    core, working, since=since, detect_skips=self._detect_skips
                )
            for working in self._units:
                opened.append(await _open_first(core, working, since=since))
            if core.outbox.stopping:
                raise _adb.Cancelled
            self._launch()
        except _adb.Cancelled:
            self._end_early(opened)
        except asyncio.CancelledError:
            core.outbox.request_kill()
            self._end_early(opened)
            raise
        except BaseException as error:
            for stream in opened:
                stream.close()
            self._phase = _Phase.FAILED
            reported = _start_failure(core, error, working)
            if reported is error:
                raise
            raise reported from error
        else:
            self._phase = _Phase.RUNNING
        return self

    def _end_early(self, opened: list[AsyncShellStream]) -> None:
        """Close what the start opened; the stream ends without having run."""
        for stream in opened:
            stream.close()
        self._phase = _Phase.ENDED_EARLY
        for unit in self._core.units:
            unit.ended_at = datetime.now(UTC)

    def _launch(self) -> None:
        """Start the reader tasks."""
        core = self._core
        loop = asyncio.get_running_loop()
        core.expected = len(self._units)
        for unit in self._units:
            unit.task = loop.create_task(
                _reader(core, unit), name=f"logprobe-reader-{unit.serial}"
            )
            unit.task.add_done_callback(_retrieve)

    async def __aenter__(self) -> Self:
        return await self.start()

    # -- consuming ----------------------------------------------------------------

    def __aiter__(self) -> AsyncIterator[LogEntry]:
        """Iterate the entries (one iteration at a time).

        The iteration ends when every reader ended and the queue is empty. When
        the stream failed, the error is raised after the queued entries were
        delivered; `join` and the ``async with`` exit raise the same object. A
        ``__anext__`` that is cancelled (for example by ``asyncio.timeout``)
        takes and repeats nothing, ends that iteration so that another may
        start, and leaves the stream running.

        Raises:
            RuntimeError: The stream was not started (or its start failed), or
                another iteration is running.
        """
        return cast("AsyncIterator[LogEntry]", self._iterate(gaps=False))

    def items(self) -> AsyncIterator[LogEntry | Gap]:
        """Like iterating, but also yields the `Gap` records in place.

        Raises:
            RuntimeError: As for iterating.
        """
        return self._iterate(gaps=True)

    def _iterate(self, *, gaps: bool) -> _AsyncIteration:
        if self._phase not in {_Phase.RUNNING, _Phase.ENDED_EARLY}:
            msg = "the stream is not running; start it first"
            raise RuntimeError(msg)
        if self._core.iterating:
            msg = "the stream is already being iterated"
            raise RuntimeError(msg)
        self._core.iterating = True
        return _AsyncIteration(self, gaps=gaps)

    # -- stopping -----------------------------------------------------------------

    def stop(self, flush: float | None = None) -> None:
        """Ask the stream to end. Never waits; any thread, any number of times.

        Without ``flush`` this only sets a flag, so it is safe to call from a
        signal handler. The readers notice at their next check (at least every
        0.25 seconds while they wait for data), process every complete line of
        the network reads they took, deliver the matching entries (up to the
        device's pending flush marker, if it is among them) and end. Once a
        reader sees the stop, it starts no further read; a read already under
        way may still bring lines, and those are handled the same way. Output
        not read, and a line whose end has not arrived (unless it was already
        cut at the 64 KiB line limit), are not delivered. A stop before `start`
        makes the stream end at once without connecting. A stop while a flush
        is pending ends the flush as ``cancelled``, even if the marker command
        ends just then, unless the marker is in the output the readers took
        (then ``done``).

        With ``flush`` every device gets a marker line written into its log
        after the call, and its reader queues the matching entries it reads up
        to the marker and ends; a `Gap` before the marker still means lines
        may be missing. The connections stay open until then, and the stream
        ends by itself. The meaning of ``flush``, the states a device ends in
        (``summary``) and the rules are those of `LogStream.stop`. On the
        loop's thread the request takes effect at once; from another thread it
        is handed to the loop. It must not be called from a signal handler. If
        the loop is closed it does nothing.

        ``stop(flush=)`` does nothing after a ``stop()`` and after an earlier
        ``stop(flush=)``, and before `start` it is the same as ``stop()``.

        Raises:
            TypeError: ``flush`` is not a number (a bool is not).
            ValueError: ``flush`` is NaN, infinite, zero or negative.
        """
        if flush is None:
            self._core.outbox.request_stop()
            return
        seconds = _marks.check_flush(flush)
        loop = self._loop
        if loop is None:
            self._core.outbox.request_stop()  # nothing is connected: nothing to flush
            return
        try:
            on_loop = asyncio.get_running_loop() is loop
        except RuntimeError:  # called from a thread that runs no loop
            on_loop = False
        if on_loop:
            # A request noted on another thread came first and wins, even if
            # the loop has not applied it yet.
            self._core.apply_asked_flush()
            self._core.request_flush(seconds)
        else:
            # Noted here, in call order with a stop() or kill() of the same
            # thread, and applied on the loop.
            self._core.ask_flush(seconds)
            with contextlib.suppress(RuntimeError):  # the loop is closed
                loop.call_soon_threadsafe(self._core.apply_asked_flush)

    def kill(self) -> None:
        """End the stream now. Never blocks; any thread, any number of times.

        The readers end at their next check and queue nothing more; what is
        queued is dropped. After ``kill()`` returned no new entry is handed to
        the consumer, except one that was already being handed over when it
        was called from another thread.
        """
        self._core.outbox.request_kill()

    async def join(self, timeout: float | None = None) -> StreamSummary:
        """Wait for the stream to end and return its summary.

        Readers can end only when the queue is consumed or the stream is
        stopped.

        Raises:
            TimeoutError: ``timeout`` seconds passed; the stream keeps running.
            RuntimeError: Not started.
            LogprobeError: The error that ended the stream (the same object
                every time).
        """
        if self._phase is _Phase.NEW or self._phase is _Phase.STARTING:
            msg = "the stream is not started"
            raise RuntimeError(msg)
        await self._wait_ended(timeout)
        error = self._core.error
        if error is not None:
            raise error
        return self.summary

    async def _wait_ended(self, timeout: float | None) -> None:
        """Wait until every reader task ended; ``TimeoutError`` after ``timeout``."""
        tasks = [task for task in self._tasks() if not task.done()]
        if tasks:
            try:
                async with asyncio.timeout(timeout):
                    await asyncio.wait(tasks)
            except TimeoutError:
                msg = "the stream did not end in time"
                raise TimeoutError(msg) from None

    def _tasks(self) -> list[asyncio.Task[None]]:
        return [u.task for u in self._units if u.task is not None]

    def _abort(self) -> None:
        """Kill the stream and abort every open connection. Does not wait."""
        self._core.outbox.request_kill()
        for unit in self._units:
            if unit.stream is not None:
                unit.stream.close()

    def _list_tasks(self) -> list[asyncio.Task[None]]:
        """The tasks of the regular lists that are not done.

        Those that run (their readers drop them), and those that a reader
        dropped when it ended and may not have awaited to the end.
        """
        tasks = []
        for unit in self._units:
            if unit.alisting is not None:
                tasks.append(unit.alisting.task)
            if unit.dropped is not None:
                tasks.append(unit.dropped)
        return [task for task in tasks if not task.done()]

    async def _reap(self) -> None:
        """Kill the stream, cancel the readers and their lists, and wait a little.

        A cancelled reader cancels its list task but does not await it, so the
        list tasks are taken before the readers are cancelled, and waited for
        with them. A list task is cancelled once only: its own cleanup awaits
        the command it runs.
        """
        self._abort()
        lists = self._list_tasks()
        for task in lists:
            _cancel_once(task)
        readers = [task for task in self._tasks() if not task.done()]
        for task in readers:
            task.cancel()
        if readers or lists:
            await asyncio.wait([*readers, *lists], timeout=_REAP_WAIT)
        for unit in self._units:
            # A task cancelled before its first step never ran its own ending.
            if unit.ended_at is None and unit.task is not None and unit.task.done():
                # As in `_reader`: a flush noted on another thread just before
                # the kill counts, even if its handed-over call was queued
                # behind these cancellations and has not run yet.
                self._core.apply_asked_flush()
                _finish(self._core, unit, None)

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Leave the block: a drained stream is joined, anything else is killed.

        After a body that ended normally a drained stream is joined. Otherwise
        (the stream is not drained, the body raised, or the task is cancelled)
        the stream is killed: first the flag is set and every open connection
        aborted, without waiting, then the readers and their package lists are
        cancelled and awaited for a short time. When the task is cancelled (or
        interrupted) while it leaves, the stream is killed, and every reader
        and package list task is cancelled (once: a task cancelled already is
        not cancelled again) and awaited to the end before the interruption
        goes on; each ends within a few steps of the loop, once the command it
        runs (a reader's own package list) has closed, so no command is left
        running. A body that ended normally then raises the stream's error,
        after the join and after the kill alike (after a kill, for example, a
        protocol error a reader had decoded already). An exception of the body
        goes on unchanged, and an error of the stream that happened meanwhile
        is logged. ``KeyboardInterrupt``, ``SystemExit`` and ``CancelledError``
        are never swallowed, except that a further cancellation while those
        tasks are awaited after an interruption is not delivered: the first
        interruption goes on.
        """
        core = self._core
        try:
            if exc is not None or not core.drained:
                await self._reap()
            else:
                await self._wait_ended(None)
        except BaseException:  # cancelled while leaving: nothing may stay open
            self._abort()
            lists = self._list_tasks()
            readers = [task for task in self._tasks() if not task.done()]
            # Once each: a second cancel would cut short the cleanup of a
            # command that a list task or a reader (its own list) awaits.
            for task in [*lists, *readers]:
                _cancel_once(task)
            await _settle([*lists, *readers])
            raise
        error = core.error
        if error is None:
            return
        if exc is None:
            raise error
        if error is not exc:
            if isinstance(exc, KeyboardInterrupt):
                _LOG.error("the stream ended with an error", exc_info=error)
            else:
                _LOG.error(
                    "the stream ended with an error while the with block "
                    "was leaving with another",
                    exc_info=error,
                )

    # -- reading state ------------------------------------------------------------

    @property
    def summary(self) -> StreamSummary:
        """A copy of what each device's stream did so far.

        Taken without any protection: while the stream runs it may be slightly
        old; once the readers ended it is exact. Before `start` the
        ``started_at`` of each device is the time the stream was created.
        """
        return StreamSummary(tuple(unit.summary() for unit in self._core.units))


def astream(
    devices: Iterable[Device | str],
    where: Condition | None = None,
    *,
    level: LogLevel | None = None,
    tag: str | list[str] | tuple[str, ...] | None = None,
    message: str | None = None,
    package: str | list[str] | tuple[str, ...] | None = None,
    pid: int | list[int] | tuple[int, ...] | None = None,
    since: Literal["now"] | None = None,
    reconnect: float = 60.0,
    detect_skips: bool = False,
    buffer_lines: int = 10_000,
    buffer_bytes: int = 4 * 1024 * 1024,
) -> AsyncLogStream:
    """Read the log of one or more devices live, on asyncio.

    The stream is returned without being started: use ``async with`` or
    ``await stream.start()``. This is `logprobe.stream` for code that runs on an
    event loop: every argument means the same, and so do the entries, the `Gap`
    records, the counters in ``summary`` and the errors, except that there is no
    ``on_entry``. See `logprobe.stream` for them.

    This function is not a coroutine, and it does not wait for the device: but
    a serial given as a string becomes ``Device(serial)`` here, and that
    constructor is blocking (it talks to the adb server and may start it). In an
    async program, create the `Device` objects beforehand, before the event
    loop runs, and pass them instead of serial strings.

    Raises:
        TypeError: An argument has the wrong type (a bool is not a number).
        ValueError: A value is out of range (``reconnect`` is NaN or negative,
            ``since`` is a string other than ``"now"``), ``devices`` is empty or
            repeats a serial, or a shortcut value is invalid.
        LogprobeError: A serial string names no usable device (see `Device`).
    """
    condition, budget = _check_arguments(
        where,
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
    )
    return AsyncLogStream(
        _devices(devices),
        condition,
        budget,
        buffer_lines,
        buffer_bytes,
        since,
        detect_skips=detect_skips,
    )
