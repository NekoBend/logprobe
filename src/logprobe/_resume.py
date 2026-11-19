"""The decisions a live stream reader makes when its logcat connection ends.

Everything here is pure: no sockets, no sleeping and no clock. A reader passes
the times it measured (seconds on a monotonic clock, and host datetimes for
gaps) and acts on the answers, so a blocking reader and an asyncio reader share
this code unchanged.

Ending a connection
-------------------

`classify_end` names how a connection ended (`EndKind`) from the exit status of
the remote command, the tail of its stderr and what the reader knows.
`ReconnectPolicy` turns that into a `Decision`: stop, or reconnect after a
delay. Delays follow ``min(2 ** n, 30)`` seconds. The budget of ``reconnect``
seconds is counted from the first failure after the last stable connection; a
connection that delivered output for `STABLE_AFTER` seconds is stable and
resets both the delay and the budget. A connection that logd cut off
(`EndKind.RELEASED`) or that the reader closed because its queue stayed full
(`EndKind.STALLED`) is resumed without a delay (a reader that closed its
connection first waits until its queue is half empty) and is no failure, unless
`QUICK_LIMIT` connections in a row ended that way within `QUICK_END` seconds of
opening; the count is by connection length, so lines logd writes about the
connection itself never reset it. With ``reconnect=0`` nothing is recovered
after a lost connection, an ended logcat or a failed logcat, while cut-off and
stalled connections are still resumed.

Older logd versions
-------------------

`skips_silently` tells from the API level whether the device's logd skips lines
of a reader that does not keep up, without any notice, instead of cutting it
off. With ``detect_skips`` such a reader closes its connection itself once it
has waited `STALL_AFTER` seconds for room in its queue since it last received
from the device (`stall_limit`), and resumes as from any other disconnect.

Resuming without losing or repeating lines
------------------------------------------

`plan_resume` decides where the new connection starts, ``T`` = newest time read
minus `OVERLAP`, and builds a `ResumeCheck` from the lines the feeder remembers.
The new connection replays the lines since ``T``; the check drops the ones that
were already read (counting identical lines by occurrence, so three equal lines
in one microsecond are dropped three times and a fourth is new) and passes the
rest on. It ends when a line newer than the cursor arrives, when a new line
arrives after every expected line came back, or when the reader reports
`RESUME_IDLE` seconds without data. At the end it reports at most one `Gap`:

- ``ring_rotated`` when some line read before the disconnect was not replayed,
  so the device no longer has it;
- else ``continuity_unknown`` when the remembered history did not reach back to
  ``T``, or when a line older than ``T`` that had not been read before arrived;
- else nothing.

A check that is cut short by another disconnect is dropped; its flags
(`ResumeCheck.flags`) are handed to `plan_resume` again, which starts over from
the same ``T``.

The final error
---------------

When the stream cannot go on, `end_error` builds the `LogprobeError` from what
ended (an `EndKind` or the code of a `Decision`), the serial, the exit status,
the stderr tail and, for a reconnect attempt that failed before a connection
existed, the exception of the last attempt (`attempt_error_code` names the code
such an exception stands for): ``device_lost`` when the device did not come
back, ``adb_server_unavailable`` when the last attempt could not reach the adb
server, ``adb_error`` when the server answered with another failure or broke
the protocol, ``logcat_failed`` when logcat ended in a way that is not a known
connection end or kept ending quickly.

What is not promised
--------------------

The check reports a gap only when it can tell. It does not detect, and so does
not report:

- Lines that reached logd later than `OVERLAP` after their time stamp, or after
  the device clock stepped back, and that logd leaves out of the replay. When no
  such line is visible in the new connection, they are missing without a gap.
- Lines lost from a buffer in which no line was read during the last `OVERLAP`
  before the disconnect, because the check only verifies buffers that have lines
  in the overlap. Deletions in the middle of a ring (logd pruning chatty
  sources, another tool running ``logcat -c``) that remove only unread lines are
  missed the same way.
- Lines that an older logd skipped without a notice while the reader was slow:
  all of them without ``detect_skips``; with it, those skipped before the
  reader had waited `STALL_AFTER` seconds for room in its queue.
- Lines that do not parse: they are neither matched nor checked. A replayed one
  is delivered twice without a gap, and one that does not come back goes
  unnoticed.

It may report too much:

- When the ring dropped only lines that had already been read, the gap is still
  reported as ``ring_rotated``, and the number lost can be zero.
- When logd restarts the replay before ``T`` and the remembered history no longer
  holds those older lines, they are delivered a second time and the gap is
  ``continuity_unknown``.
- When the history was too short to cover ``T``, duplicates may be delivered; the
  gap is ``continuity_unknown``.
- When a line was delivered twice (the check had ended before it came back) it
  is remembered twice, and a reconnect while it is still within `OVERLAP` of
  the cursor expects it twice; even a complete replay is then reported as
  ``ring_rotated``.
"""

from __future__ import annotations

import enum
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, Literal, Protocol

from ._errors import LogprobeError
from ._feed import OVERLAP
from ._framing import decode_line
from ._parse import ParseContext, ThreadTimeLogParser
from ._records import Gap

if TYPE_CHECKING:
    from ._framing import FramedLine
    from ._records import GapCause, GapReason

__all__ = [
    "BACKOFF_CAP",
    "QUICK_END",
    "QUICK_LIMIT",
    "RESUME_IDLE",
    "STABLE_AFTER",
    "STALL_AFTER",
    "Decision",
    "EndKind",
    "ErrorCode",
    "ReconnectPolicy",
    "ResumeCheck",
    "ResumeFlags",
    "ResumePlan",
    "attempt_error_code",
    "backoff",
    "cause_of",
    "classify_end",
    "end_error",
    "parse_sdk",
    "plan_resume",
    "skips_silently",
    "stall_limit",
    "t_arg",
]

#: A connection that delivered output for this many seconds is stable.
STABLE_AFTER: Final = 10.0
#: The longest wait between two reconnects, in seconds.
BACKOFF_CAP: Final = 30.0
#: A resumable connection that ended within this many seconds of opening is quick.
QUICK_END: Final = 1.0
#: This many quick resumable ends in a row count as failures.
QUICK_LIMIT: Final = 3
#: Seconds without data on a new connection after which the resume check ends.
RESUME_IDLE: Final = 1.0
#: Seconds a reader may wait for room in the queue, since it last received from
#: the device, before it closes the connection itself; only where logd skips
#: lines of a slow reader.
STALL_AFTER: Final = 1.0

_EOF_TEXT: Final = "unexpected eof"
_SIGNAL_EXIT: Final = 128
_SDK_DIGITS: Final = 4  # an API level has fewer digits for a long time to come
_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)

type ErrorCode = Literal[
    "device_lost", "logcat_failed", "adb_server_unavailable", "adb_error"
]


class EndKind(enum.Enum):
    """How a logcat connection ended."""

    #: The reader asked for the stop.
    STOPPED = "stopped"
    #: logd cut the reader off: exit status 1 and logcat's EOF message.
    RELEASED = "released"
    #: The reader closed the connection because its queue stayed full.
    STALLED = "stalled"
    #: The connection closed without an exit packet.
    LOST = "lost"
    #: logcat ended: exit status 0, or 128 and above (a signal, such as 143).
    ENDED = "ended"
    #: A non-zero exit before any output on the first connection.
    FAILED_START = "failed_start"
    #: Any other non-zero exit.
    FAILED = "failed"


def classify_end(
    exit_status: int | None,
    stderr_tail: str,
    *,
    stop_requested: bool,
    stalled: bool,
    output_seen: bool,
    first_connection: bool,
) -> EndKind:
    """Name how a connection ended.

    Args:
        exit_status: The exit status from the exit packet, or None when the
            connection closed without one.
        stderr_tail: The last lines the command wrote to stderr.
        stop_requested: The reader was asked to stop.
        stalled: The reader closed the connection itself because its queue
            stayed full. When the exit packet had arrived before that close,
            its exit status names the end instead: logcat had ended on its own.
        output_seen: The connection delivered at least one line of output.
        first_connection: This was the first connection of the stream.
    """
    if stop_requested:
        return EndKind.STOPPED
    if exit_status is None:
        return EndKind.STALLED if stalled else EndKind.LOST
    if exit_status == 1 and _EOF_TEXT in stderr_tail.lower():
        return EndKind.RELEASED
    if exit_status == 0 or exit_status >= _SIGNAL_EXIT:
        return EndKind.ENDED
    if first_connection and not output_seen:
        return EndKind.FAILED_START
    return EndKind.FAILED


def cause_of(kind: EndKind) -> GapCause:
    """The gap cause for a connection that ended as ``kind``.

    Raises:
        ValueError: ``kind`` is not an end that is resumed from.
    """
    match kind:
        case EndKind.RELEASED:
            return "released"
        case EndKind.STALLED:
            return "stalled"
        case EndKind.LOST | EndKind.ENDED | EndKind.FAILED:
            return "disconnected"
        case _:
            msg = f"a connection that ended as {kind.name} is not resumed"
            raise ValueError(msg)


def parse_sdk(stdout: bytes) -> int | None:
    """The API level from the output of ``getprop ro.build.version.sdk``, or None.

    Only ASCII decimal digits, with white space around them, are a level, and
    at most `_SDK_DIGITS` of them: a longer number is no API level, and
    ``int`` refuses a very long one.
    """
    text = stdout.strip()
    # bytes.isdigit accepts ASCII digits only
    if not text.isdigit() or len(text) > _SDK_DIGITS:
        return None
    return int(text)


def skips_silently(sdk: int | None) -> bool:
    """True when logd at API level ``sdk`` may skip lines of a slow reader unnoticed.

    Measured: levels 24 and 30 skip lines of a reader that does not keep up
    and leave the connection open; levels 26, 28, 29, 31, 32 and 36 cut such a
    reader off, which a stream always notices. The levels in between follow
    their neighbours: 25 and below skip, 27 and 33 and above cut off. A level
    that could not be read (None) is treated as one that skips.
    """
    return sdk is None or sdk <= 25 or sdk == 30


def stall_limit(sdk: int | None) -> float | None:
    """Seconds a reader of a device at ``sdk`` may wait for room; None: no limit."""
    return STALL_AFTER if skips_silently(sdk) else None


def attempt_error_code(error: BaseException) -> ErrorCode:
    """The code a failed reconnect attempt stands for if the budget runs out.

    ``adb_server_unavailable`` and ``adb_error`` stay what they are. A device
    that the adb server no longer knows, or that is offline or unauthorized, is
    a lost device. Anything else that went wrong before a connection existed (a
    timeout, a broken socket, an unexpected reply) is an ``adb_error``.
    """
    if isinstance(error, LogprobeError):
        if error.code in {"adb_server_unavailable", "adb_error"}:
            return error.code
        if error.code in {"device_not_found", "device_offline", "device_unauthorized"}:
            return "device_lost"
    return "adb_error"


def end_error(
    ended: EndKind | ErrorCode,
    serial: str,
    exit_status: int | None,
    stderr: list[str],
    *,
    attempt: BaseException | None = None,
) -> LogprobeError | None:
    """The error that ends a stream, or None for a requested stop.

    Args:
        ended: How the last connection ended, or the error code of the
            `Decision` that gave up.
        serial: The device.
        exit_status: The exit status of the last connection, or None.
        stderr: The lines the last connection wrote to stderr (the tail).
        attempt: The exception of the last reconnect attempt, when the stream
            gave up after attempts that failed before a connection existed.
            ``adb_server_unavailable`` and ``adb_error`` attempts are returned
            as they are (with the serial added to their details); for the
            other codes it becomes the ``__cause__`` of the new error.
    """
    if isinstance(ended, EndKind):
        if ended is EndKind.STOPPED:
            return None
        code: ErrorCode = (
            "device_lost" if ended in {EndKind.LOST, EndKind.ENDED} else "logcat_failed"
        )
    else:
        code = ended
    if attempt is not None:
        return _attempt_error(code, serial, attempt)
    details: dict[str, object] = {"serial": serial, "exit_status": exit_status}
    if code == "logcat_failed":
        details["stderr"] = stderr
        return LogprobeError(code, f"logcat on {serial} ended with an error", details)
    return LogprobeError(code, f"the log connection to {serial} ended", details)


def _attempt_error(
    code: ErrorCode, serial: str, attempt: BaseException
) -> LogprobeError:
    if isinstance(attempt, LogprobeError) and attempt.code == code:
        attempt.details.setdefault("serial", serial)
        return attempt
    if code == "adb_error":  # a timeout, a broken socket: no LogprobeError of its own
        error = LogprobeError(
            code,
            f"the adb server failed while reconnecting to {serial}: {attempt!r}",
            {"serial": serial},
        )
    else:
        error = LogprobeError(
            code,
            f"{serial} did not come back: {attempt}",
            {"serial": serial},
        )
    error.__cause__ = attempt
    return error


def backoff(failures: int) -> float:
    """The wait in seconds before the reconnect after ``failures`` earlier waits.

    ``min(2 ** failures, 30)``: 1, 2, 4, 8, 16, 30, 30 ...
    """
    if failures < 0:
        msg = f"failures must not be negative, got {failures}"
        raise ValueError(msg)
    if failures >= 5:  # 2 ** 5 is already above the cap
        return BACKOFF_CAP
    return min(float(2**failures), BACKOFF_CAP)


@dataclass(frozen=True, slots=True)
class Decision:
    """What to do after a connection (or an attempt) ended.

    Attributes:
        retry: True to connect again after ``delay`` seconds.
        delay: Seconds to wait first; 0 means at once.
        error: When ``retry`` is False and the stream failed, the error code to
            end it with; None for a requested stop.
    """

    retry: bool
    delay: float = 0.0
    error: ErrorCode | None = None


class ReconnectPolicy:
    """Delay, budget and quick-end bookkeeping for the connections of one stream.

    Times are seconds on any monotonic clock the reader chooses; the policy
    never reads a clock.

    Args:
        reconnect: The budget in seconds for recovering from lost, ended or
            failed connections, counted from the first failure after the last
            stable connection. 0 means no recovery from those.

    Raises:
        ValueError: ``reconnect`` is negative or not a number.
    """

    __slots__ = (
        "_failing_since",
        "_free_used",
        "_quick",
        "_reconnect",
        "_waits",
    )

    def __init__(self, reconnect: float) -> None:
        if math.isnan(reconnect) or reconnect < 0:
            msg = f"reconnect must be a number of seconds, 0 or more, got {reconnect}"
            raise ValueError(msg)
        self._reconnect = reconnect
        self._failing_since: float | None = None
        self._waits = 0
        self._free_used = False
        self._quick = 0

    def connection_ended(
        self,
        kind: EndKind,
        *,
        opened_at: float,
        ended_at: float,
        output_since: float | None,
    ) -> Decision:
        """Decide what follows a connection that ended as ``kind``.

        Args:
            kind: From `classify_end`.
            opened_at: When the connection was opened.
            ended_at: When it ended.
            output_since: When its first output arrived, or None for none.
        """
        if kind is EndKind.STOPPED:
            return Decision(retry=False)
        if output_since is not None and ended_at - output_since >= STABLE_AFTER:
            self._failing_since = None
            self._waits = 0
            self._free_used = False
            self._quick = 0
        if kind in {EndKind.RELEASED, EndKind.STALLED}:
            if ended_at - opened_at <= QUICK_END:
                self._quick += 1
            else:
                self._quick = 0
            if self._quick < QUICK_LIMIT:
                return Decision(retry=True)
            return self._fail(ended_at, "logcat_failed", free=False)
        self._quick = 0
        if kind is EndKind.FAILED_START:
            return Decision(retry=False, error="logcat_failed")
        if kind is EndKind.FAILED:
            return self._fail(ended_at, "logcat_failed", free=False)
        return self._fail(ended_at, "device_lost", free=kind is EndKind.ENDED)

    def attempt_failed(
        self, now: float, *, error: ErrorCode = "device_lost"
    ) -> Decision:
        """Decide what follows a reconnect attempt that failed before a connection.

        Args:
            now: When the attempt failed.
            error: The code to end the stream with if the budget is used up.
        """
        return self._fail(now, error, free=False)

    def _fail(self, now: float, error: ErrorCode, *, free: bool) -> Decision:
        if self._reconnect <= 0:
            return Decision(retry=False, error=error)
        if self._failing_since is None:
            self._failing_since = now
        remaining = self._failing_since + self._reconnect - now
        if remaining <= 0:
            return Decision(retry=False, error=error)
        if free and not self._free_used:
            # A logcat that ended by itself is tried again at once, once.
            self._free_used = True
            return Decision(retry=True)
        wait = min(backoff(self._waits), remaining)
        self._waits += 1
        return Decision(retry=True, delay=wait)


def t_arg(moment: datetime) -> str:
    """Format ``moment`` as the epoch value of logcat's ``-T`` option.

    Seconds, a dot and exactly 6 digits of microseconds, such as
    ``"1700000000.123456"``; the dot is required because logcat reads a number
    without one as a line count. A datetime has microsecond resolution, so
    nothing is rounded. A moment before 1970 is clamped to ``"0.000000"``.

    Raises:
        ValueError: ``moment`` is naive.
    """
    if moment.tzinfo is None or moment.utcoffset() is None:
        msg = "moment must be timezone-aware"
        raise ValueError(msg)
    delta = moment - _EPOCH
    if delta.days < 0:
        return "0.000000"
    return f"{delta.days * 86400 + delta.seconds}.{delta.microseconds:06d}"


@dataclass(frozen=True, slots=True)
class ResumeFlags:
    """What an unfinished resume check had learned, to carry to the next one.

    Attributes:
        short: The history did not reach back to the start of the replay.
        older_unread: A line older than the start of the replay that had not
            been read before arrived.
    """

    short: bool = False
    older_unread: bool = False


class ResumeCheck:
    """Drops the replayed lines of a reconnect and finds the gap, if any.

    Implements the resume check hook of the feeder (``admit``, ``finished``,
    ``gap`` and ``end``); create it with `plan_resume`. ``idle`` is for the
    reader: it reports receive waits without data.

    Args:
        serial: The device.
        cursor: The newest time read before the disconnect.
        start: Where the new connection starts replaying (``T``).
        expected: Lines read at or after ``start``, as bytes to occurrence count.
        older: Lines read before ``start``, as bytes to occurrence count.
        cause: How the previous connection ended.
        detected_at: The host time to stamp the gap with.
        flags: What an interrupted check had learned, plus whether the history
            fell short.
    """

    __slots__ = (
        "_cause",
        "_cursor",
        "_detected_at",
        "_expected",
        "_finished",
        "_idle",
        "_left",
        "_older",
        "_older_unread",
        "_serial",
        "_short",
        "_start",
    )

    def __init__(
        self,
        *,
        serial: str,
        cursor: datetime,
        start: datetime,
        expected: dict[bytes, int],
        older: dict[bytes, int],
        cause: GapCause,
        detected_at: datetime,
        flags: ResumeFlags | None = None,
    ) -> None:
        self._serial = serial
        self._cursor = cursor
        self._start = start
        self._expected = dict(expected)
        self._older = dict(older)
        self._left = sum(self._expected.values())
        self._cause = cause
        self._detected_at = detected_at
        carried = flags or ResumeFlags()
        self._short = carried.short
        self._older_unread = carried.older_unread
        self._finished = False
        self._idle = 0.0

    @property
    def finished(self) -> bool:
        """True once the check has decided; ``gap`` is then valid."""
        return self._finished

    @property
    def flags(self) -> ResumeFlags:
        """What the check has learned so far (to carry over if it is dropped)."""
        return ResumeFlags(self._short, self._older_unread)

    def admit(self, line: FramedLine, logged_at: datetime | None, /) -> bool:
        """Return False for a replayed line, True for a new one.

        A line without a time (a divider, or one that did not parse) is never
        matched and never marks an older unread line, but once every expected
        line has come back it ends the check like any other new line. A line
        whose time has a zone when the cursor's has none, or the reverse,
        counts as a line without a time (`comparable`).
        """
        self._idle = 0.0
        if self._finished:
            return True
        if logged_at is not None and comparable(logged_at, self._cursor):
            data = line.data
            count = self._expected.get(data, 0)
            if count:
                self._expected[data] = count - 1
                self._left -= 1
                return False
            count = self._older.get(data, 0)
            if count:
                self._older[data] = count - 1
                return False
            if logged_at < self._start:
                self._older_unread = True
            if logged_at > self._cursor:
                self._finished = True
        if self._left == 0:
            self._finished = True
        return True

    def received(self) -> None:
        """Note that data arrived on the new connection.

        Call this for every piece of data received, even when it completes no
        line: a half line is data too, and the feeder only reports whole lines.
        """
        self._idle = 0.0

    def idle(self, waited: float) -> bool:
        """Add ``waited`` seconds of a receive wait that brought no data.

        Any data resets the count: call `received` whenever bytes arrive, even
        when they do not complete a line (a completed line resets it as well).
        Returns True once `RESUME_IDLE` seconds have
        passed without data; the reader should then end the check
        (``Feeder.end_check``). Only receive waits count, not time spent
        waiting on a full queue or on a device command.
        """
        self._idle += waited
        return self._idle >= RESUME_IDLE

    def end(self) -> None:
        """End the check without a new line."""
        self._finished = True

    def gap(self) -> Gap | None:
        """The gap the check found, or None.

        Raises:
            RuntimeError: The check has not finished.
        """
        if not self._finished:
            msg = "the resume check has not finished"
            raise RuntimeError(msg)
        if self._left > 0:
            reason: GapReason = "ring_rotated"
        elif self._short or self._older_unread:
            reason = "continuity_unknown"
        else:
            return None
        return Gap(
            self._serial,
            reason,
            self._cause,
            self._detected_at,
            self._start,
        )


class _History(Protocol):
    """The part of the feeder `plan_resume` reads."""

    @property
    def serial(self) -> str: ...

    @property
    def cursor(self) -> datetime | None: ...

    @property
    def short_until(self) -> datetime | None: ...

    def history_since(self, moment: datetime, /) -> list[FramedLine]: ...


@dataclass(frozen=True, slots=True)
class ResumePlan:
    """How to open the next connection.

    Attributes:
        start: ``T``, where the connection should start; None when nothing with
            a time has been read, so the first connection's arguments are used
            and no check is needed.
        t_arg: ``start`` formatted for ``-T``, or None.
        check: The resume check to install, or None.
    """

    start: datetime | None
    t_arg: str | None
    check: ResumeCheck | None


def comparable(moment: datetime, other: datetime) -> bool:
    """True when ``moment`` and ``other`` can be compared: both have a zone or
    neither has.

    logcat prints the zone (``-v zone``) on every line, so a line without one
    among lines with one (or the reverse) comes from a broken producer; the
    resume check treats such a line as having no time, as the feeder's cursor
    ignores it.
    """
    return (moment.tzinfo is None) == (other.tzinfo is None)


def plan_resume(
    feeder: _History,
    cause: GapCause,
    detected_at: datetime,
    *,
    carried: ResumeFlags | None = None,
) -> ResumePlan:
    """Plan the reconnect of a stream (see the module docs).

    Args:
        feeder: The device's `Feeder`.
        cause: How the previous connection ended (see `cause_of`).
        detected_at: The host time to stamp a gap with.
        carried: The flags of a check that another disconnect interrupted.
    """
    cursor = feeder.cursor
    if cursor is None:
        return ResumePlan(None, None, None)
    try:
        start = cursor - OVERLAP
    except OverflowError:  # a cursor at year 1: nothing is older
        start = cursor
    # Every remembered line is parsed completely, as the feeder parses the new
    # connection's lines, so a line counts as timed here exactly when it does in
    # `ResumeCheck.admit`. This costs tens of milliseconds for a full history.
    parser = ThreadTimeLogParser()
    ctx = ParseContext(serial=feeder.serial)
    expected: dict[bytes, int] = {}
    older: dict[bytes, int] = {}
    for framed in feeder.history_since(start):
        text = decode_line(framed.data, cut=framed.truncated)
        entry = parser.parse(text, ctx)
        if entry is None or not comparable(entry.logged_at, start):
            continue
        bucket = expected if entry.logged_at >= start else older
        bucket[framed.data] = bucket.get(framed.data, 0) + 1
    short_until = feeder.short_until
    flags = carried or ResumeFlags()
    if short_until is not None and short_until >= start:
        flags = ResumeFlags(short=True, older_unread=flags.older_unread)
    check = ResumeCheck(
        serial=feeder.serial,
        cursor=cursor,
        start=start,
        expected=expected,
        older=older,
        cause=cause,
        detected_at=detected_at,
        flags=flags,
    )
    return ResumePlan(start, t_arg(start), check)
