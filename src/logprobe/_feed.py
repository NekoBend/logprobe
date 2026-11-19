"""The shared, I/O-free core of a live stream reader: bytes in, ordered chunks out.

A `Feeder` belongs to one device. A reader (blocking or asyncio) does the
socket work and hands every piece of logcat's stdout to `Feeder.feed`; the
feeder frames the bytes into lines, decodes and parses them, drops logcat's
buffer dividers and the library's own markers, applies the condition and
returns the entries in order. It never reads a socket or sleeps, and the only
clocks it touches are the host time stamped on lines that do not parse and on
notices of lines the device dropped, so the two kinds of reader share it
unchanged.

What `Feeder.feed` returns
--------------------------

A list of `Chunk` objects, each a list of *segments* in the order things
happened plus the charge to queue it with. Usually there is one chunk holding
one list of entries, charged with the byte count of the read, ``len(out)``:
lines the condition removes and a line that continues into the next read are
part of that count, and nothing measures a line. A `Gap` or a `MarkerArrived`
takes its own place among the segments, so entries before it and after it stay
on their side.

A chunk holds at most `CHUNK_ENTRIES` entries. A read that yields more is
divided into several chunks; their charges are shares of the read's charge in
proportion to their entry counts and add up to it exactly. Queue
each chunk with its own charge, in order. A read that completes no line returns
no chunk; its bytes are charged to the read that completes the line.

Connections
-----------

``cursor`` and the history belong to the device and live across connections;
the framer, the parse session and the pending resume check belong to one
connection. `Feeder.begin_connection` starts a connection with a fresh
`Framer` and a fresh `ParseContext` (carrying the device's serial); the
bytes of an unfinished line of the old connection are dropped, never joined to
the new connection's bytes.

Cursor and history
------------------

``cursor`` is the newest timestamp with a zone among the lines read, including
lines the condition removed and marker lines; lines without a timestamp
(dividers, unparsed lines) and lines whose timestamp has no zone do not count.
Lines a resume check drops as replays are not read at all.

For every read the feeder keeps one history group: the lines the read ended
(the `FramedLine` objects the framer already made), the cursor at the end of
the read, the byte count and the line count. A group whose cursor is older than
the current cursor by more than `OVERLAP` can no longer be needed and is
dropped. If what remains exceeds `HISTORY_BYTES` or `HISTORY_LINES`, the oldest
groups go too, and when a group dropped this way was still inside the overlap
window, ``short_until`` is set to its cursor: the history does not reach back
that far. The caps hold also while no line has a timestamp yet; then there is
no window, so ``short_until`` stays unset. The bytes of a read that completed
no line count toward the group of the read that completes the line. Nothing is
done per line for this, only per read.

The resume check
----------------

After a reconnect the new connection replays lines the feeder has already seen.
A *resume check* (installed with `Feeder.begin_connection`) sorts them out. It is
any object with these members (`ResumeCheck`):

- ``admit(line, logged_at)``: called for every framed line of the new
  connection, in order, before anything else looks at the line: before the
  cursor, the counters, marker detection and the condition. ``logged_at`` is the
  line's timestamp, or None for a divider or a line that did not parse. Return
  False to drop the line as a replay; the feeder then does not count it, does
  not keep it in the history and does not deliver it. Return True for a new
  line.
- ``finished``: True once the check has seen enough. The feeder reads it after
  every ``admit``; once it is True the feeder takes the check's result and stops
  calling it, so a finished check costs nothing per line.
- ``gap()``: called once, when ``finished`` turned True after an ``admit``. The
  `Gap` it returns (or None) is placed in the output *before* the line that
  ended the check (or before the next line, when that line was dropped).
- ``end()``: called by `Feeder.end_check` when the connection stayed silent and
  the reader decides the check is over without a new line. It makes ``finished``
  True and ``gap()`` valid.

Without a check (the default, and the case from the first connection on) the
per-line cost of the hook is one test of a local variable.

Markers
-------

The reader proves that it has read up to a point by writing a marker line into
the device log (tag `MARKER_TAG`, message ``start-<32 hex digits>`` or
``flush-<32 hex digits>``, made by `new_marker`). A marker line of any
token, also one an earlier run left in the log, is never delivered and is not
counted as a line. ``expect(token)`` names the marker the reader waits for;
when it arrives the output gets a `MarkerArrived` at its exact place and
``arrived`` turns True. Only lines with the marker tag are examined, so while no
marker is awaited the cost is one string comparison per line. Trailing
whitespace of the message is ignored (Android 7 adds a space).

The chatty notice
-----------------

An old logd (Android 7) writes a line with the tag ``chatty`` when it drops the
lines of a source that logged too much: ``uid=10014(com.example) expire 26
lines`` (the name in parentheses, and words such as a thread name before
``expire``, may be missing; the count may be ``1 line``). `Feeder` reports each
such notice as ``Gap(serial, "device_reported", "notice", detected_at=<host
time now>, start_at=<the notice's own time>, lost=N)``, placed in the output
right before the notice's entry, because the notice is the point where the
reader learned of the loss. The gap is produced even when the condition removes
the notice line, and the line itself is delivered exactly when the condition
passes it. A notice that a resume check drops as a replayed line yields no gap,
so a loss is reported once however often the connection is replayed. Gaps and
``lost`` are counted once. ``identical N lines`` notices say that lines were
folded into one, not lost, and are not reported. A line that is not a ``chatty``
notice pays one more comparison of its tag.

The condition
-------------

A condition without package terms is compiled once and applied to every entry
here. A condition with package terms cannot be decided from the line alone: the
feeder passes every entry on unfiltered (still counted), and a later stage that
knows the apps decides.
"""

from __future__ import annotations

import contextlib
import logging
import re
import secrets
from collections import deque
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, Literal, NamedTuple, Protocol

from ._framing import DEFAULT_MAX_LINE_BYTES, FramedLine, Framer, decode_line
from ._parse import ParseContext, ThreadTimeLogParser
from ._parse.fallback import is_divider, unparsed_entry
from ._records import Gap, GapReason

if TYPE_CHECKING:
    from ._conditions import Condition
    from ._entry import LogEntry
    from ._parse import LogParser

_LOG = logging.getLogger(__name__)

__all__ = [
    "CHATTY_TAG",
    "CHUNK_ENTRIES",
    "HISTORY_BYTES",
    "HISTORY_LINES",
    "MARKER_TAG",
    "OVERLAP",
    "Chunk",
    "Feeder",
    "MarkerArrived",
    "ResumeCheck",
    "Segment",
    "chatty_loss",
    "has_zone",
    "new_marker",
]

#: The most entries in one list of a chunk; a longer run is split.
CHUNK_ENTRIES: Final = 2048
#: How far before the newest line a reconnect starts reading again.
OVERLAP: Final = timedelta(seconds=1)
#: The history keeps at most this many input bytes ...
HISTORY_BYTES: Final = 2 * 1024 * 1024
#: ... and at most this many lines.
HISTORY_LINES: Final = 20_000
#: The tag of the marker lines the library writes into the device log.
MARKER_TAG: Final = "logprobe"
#: The tag of the notices an old logd writes about dropped lines.
CHATTY_TAG: Final = "chatty"

_MARKER = re.compile(r"(?:start|flush)-[0-9a-f]{32}")
# The count has at most 18 digits: far more lines than any log buffer holds,
# and short enough that int() never refuses it (Python limits conversions to
# 4,300 digits by default). After n notices the lost total is below n * 10**18,
# so it stays far below that limit in any real run. A longer number is not a
# notice logd wrote: the line is an ordinary entry (filtered, and dropped as a
# replay, like any other).
_EXPIRE = re.compile(r"uid=\d+(?:\([^)]*\))?(?: .*)? expire (\d{1,18}) lines?")


def has_zone(moment: datetime) -> bool:
    """True when ``moment`` has a zone (is aware).

    logcat prints the zone (``-v zone``) on every line, so a line without one
    comes from a broken producer. The feeder's cursor moves only on times with
    a zone, and the resume check treats a line without one as a line without a
    time, so no aware time is ever compared with a naive one.
    """
    return moment.utcoffset() is not None


def chatty_loss(message: str) -> int | None:
    """The number of lines a ``chatty`` notice says were dropped, or None.

    Only ``expire`` notices count (``uid=1000(system) expire 3 lines``); an
    ``identical`` notice, a count of more than 18 digits and any other message
    give None. Trailing whitespace is ignored.
    """
    found = _EXPIRE.fullmatch(message.rstrip())
    return None if found is None else int(found[1])


@dataclass(frozen=True, slots=True)
class MarkerArrived:
    """The place in the output where the awaited marker line was read.

    It tells the reader where to cut (drop the lines before a start marker,
    stop after a flush marker); the reader removes it before queueing a chunk,
    so consumers never see it.

    Attributes:
        token: The marker text that was awaited.
    """

    token: str


#: One element of a chunk.
type Segment = list[LogEntry] | Gap | MarkerArrived


class Chunk(NamedTuple):
    """Segments to queue together, with the byte charge to queue them with.

    Attributes:
        segments: The segments, in the order things happened.
        charge: Input bytes to charge for this chunk.
    """

    segments: list[Segment]
    charge: int


class ResumeCheck(Protocol):
    """What the feeder needs from a resume check (see the module docs)."""

    @property
    def finished(self) -> bool:
        """True once the check has decided; the feeder then asks `gap`."""
        ...

    def admit(self, line: FramedLine, logged_at: datetime | None, /) -> bool:
        """Return False for a replayed line to drop, True for a new line."""
        ...

    def gap(self) -> Gap | None:
        """The gap the check found, or None; called once after it finished."""
        ...

    def end(self) -> None:
        """End the check without a new line (the connection stayed silent)."""
        ...


def new_marker(kind: Literal["start", "flush"]) -> str:
    """Return a fresh marker text: ``start-`` or ``flush-`` and 32 hex digits."""
    return f"{kind}-{secrets.token_hex(16)}"


class _Group(NamedTuple):
    """The lines one read ended, with what the trimming rules need."""

    lines: list[FramedLine]
    cursor: datetime | None
    nbytes: int
    nlines: int


def _chunks(segments: list[Segment], entries: int, charge: int) -> list[Chunk]:
    """Pack ``segments`` into chunks of at most `CHUNK_ENTRIES` entries each.

    The ``charge`` is shared out in proportion to the entry counts, so the
    charges add up to ``charge``. The common case (one small chunk) is cheap.
    """
    if not segments:
        return []
    if entries <= CHUNK_ENTRIES:
        return [Chunk(segments, charge)]
    packed: list[tuple[list[Segment], int]] = []
    current: list[Segment] = []
    room = CHUNK_ENTRIES
    for segment in segments:
        if type(segment) is not list:
            current.append(segment)
            continue
        start = 0
        while start < len(segment):
            part = segment[start : start + room]
            current.append(part)
            start += len(part)
            room -= len(part)
            if room == 0:
                packed.append((current, CHUNK_ENTRIES))
                current, room = [], CHUNK_ENTRIES
    if current:
        packed.append((current, CHUNK_ENTRIES - room))
    chunks: list[Chunk] = []
    done = 0
    paid = 0
    for chunk_segments, count in packed:
        done += count
        owed = charge * done // entries
        chunks.append(Chunk(chunk_segments, owed - paid))
        paid = owed
    return chunks


class Feeder:
    """Turns the stdout of one device's logcat into ordered chunks of entries.

    One feeder per device, used by one reader at a time (not thread-safe). See
    the module docs for the rules. The counters below are plain attributes that
    only the feeder writes; read them, do not assign them.

    Attributes:
        serial: The device's adb serial, carried by every entry.
        lines: Physical lines read: every line that was not dropped as a replay
            and was not a marker (dividers and unparsed lines count).
        entries: Entries handed on. With a package condition they are counted
            before that condition is applied.
        unparsed: Lines that did not parse (they become entries with
            ``parsed=False``).
        truncated: Lines cut at ``max_line_bytes``.
        duplicates: Lines a resume check dropped as replays.
        markers: Marker lines read, of any token.
        gaps: Gaps produced: by a resume check and by ``chatty`` notices.
        lost: The sum of the known ``lost`` counts of those gaps.
        reconnects: Connections begun after the first.
    """

    __slots__ = (
        "_awaited",
        "_carry",
        "_check",
        "_ctx",
        "_cursor",
        "_framer",
        "_gaps_later",
        "_hbytes",
        "_history",
        "_hlines",
        "_max_line_bytes",
        "_parser",
        "_predicate",
        "_short_until",
        "arrived",
        "deferred",
        "duplicates",
        "entries",
        "gaps",
        "lines",
        "lost",
        "markers",
        "reconnects",
        "serial",
        "truncated",
        "unparsed",
    )

    def __init__(
        self,
        serial: str,
        *,
        condition: Condition | None = None,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    ) -> None:
        """Start the feeder of one device and its first connection.

        Args:
            serial: The device's adb serial.
            condition: The entry filter. Compiled here. When it tests the app of a
                line (``Package``) it is not applied (see the module docs) and
                ``deferred`` is True.
            max_line_bytes: The longest line kept whole; trusted, the caller
                validates it (see `Framer`).
        """
        self.serial = serial
        self.deferred = condition is not None and condition._has_package()  # noqa: SLF001
        self._predicate = (
            condition.compile() if condition is not None and not self.deferred else None
        )
        self._max_line_bytes = max_line_bytes
        self._parser: LogParser = ThreadTimeLogParser()
        self._framer = Framer(max_line_bytes)
        self._ctx = ParseContext(serial=serial)
        self._check: ResumeCheck | None = None
        self._cursor: datetime | None = None
        self._short_until: datetime | None = None
        self._history: deque[_Group] = deque()
        self._hbytes = 0
        self._hlines = 0
        self._carry = 0
        self._awaited: str | None = None
        self.arrived = False
        self.lines = self.entries = self.unparsed = self.truncated = 0
        self.duplicates = self.markers = self.gaps = self.lost = self.reconnects = 0
        # The reasons of the gaps logged so far, each with the number of later
        # gaps of that reason, which are only counted (`tell_later_gaps`).
        self._gaps_later: dict[GapReason, int] = {}

    # -- what the feeder remembers ------------------------------------------------

    @property
    def cursor(self) -> datetime | None:
        """The newest timestamp with a zone read so far (see the module docs),
        or None."""
        return self._cursor

    @property
    def short_until(self) -> datetime | None:
        """The history does not reach back to this moment (or any earlier one
        that was inside the overlap window when its group was dropped); None
        while nothing within the window was ever dropped."""
        return self._short_until

    @property
    def history_bytes(self) -> int:
        """The input bytes of the history groups."""
        return self._hbytes

    @property
    def history_lines(self) -> int:
        """The lines of the history groups."""
        return self._hlines

    def history_since(self, moment: datetime) -> list[FramedLine]:
        """The lines of every history group whose cursor is ``moment`` or later.

        Oldest first. A group may also hold lines older than ``moment``; the
        caller reads each line's own timestamp.
        """
        found: list[FramedLine] = []
        for group in self._history:
            if group.cursor is not None and group.cursor >= moment:
                found.extend(group.lines)
        return found

    # -- connections and markers ----------------------------------------------------

    def begin_connection(self, check: ResumeCheck | None = None) -> None:
        """Start a new connection: a fresh framer and parse session.

        The unfinished line of the previous connection is dropped. The first
        connection is begun by the constructor; call this for every later one.
        The cursor, the history, the counters and the awaited marker stay.

        Args:
            check: The resume check for this connection, or None.

        Raises:
            ValueError: ``check`` is already finished.
        """
        if check is not None and check.finished:
            msg = "the resume check is already finished"
            raise ValueError(msg)
        self._framer = Framer(self._max_line_bytes)
        self._ctx = ParseContext(serial=self.serial)
        self._check = check
        self._carry = 0
        self.reconnects += 1

    def end_check(self) -> list[Chunk]:
        """End the pending resume check without a new line.

        For a reader that saw the connection stay silent. Returns the segment
        holding the check's gap (counted), or an empty list; nothing when no
        check is pending.
        """
        check = self._check
        if check is None:
            return []
        self._check = None
        check.end()
        gap = check.gap()
        if gap is None:
            return []
        self._count_gap(gap)
        return [Chunk([gap], 0)]

    def expect(self, token: str) -> None:
        """Wait for the marker line ``token`` (also resets ``arrived``).

        Raises:
            ValueError: ``token`` is not shaped like `new_marker`'s output.
        """
        if _MARKER.fullmatch(token) is None:
            msg = f"not a marker text: {token!r}"
            raise ValueError(msg)
        self._awaited = token
        self.arrived = False

    # -- the work ---------------------------------------------------------------------

    def feed(self, out: bytes) -> list[Chunk]:
        """Read ``out``, a piece of logcat's stdout, and return what it completes.

        The charges of the returned chunks add up to ``len(out)`` plus the bytes
        of earlier reads that completed no line. A read that completes no line
        returns an empty list and its bytes are charged later; a read whose
        lines the condition all removes also returns an empty list, and its
        bytes are charged to nothing, since nothing is queued.

        Raises:
            RuntimeError: `finish` ended this connection's input already.
        """
        return self._process(self._framer.feed(out), len(out))

    def finish(self) -> list[Chunk]:
        """End the input of a one-shot read: the bytes after the last LF are a line.

        A live stream does not call this; an unfinished line of a lost
        connection is dropped by `begin_connection`.
        """
        return self._process(self._framer.finish(), 0)

    def _count_gap(self, gap: Gap) -> None:
        self.gaps += 1
        if gap.lost is not None:
            self.lost += gap.lost
        later = self._gaps_later
        if gap.reason in later:
            later[gap.reason] += 1
            return
        later[gap.reason] = 0
        if gap.reason == "device_reported":
            what = f"the device dropped {gap.lost} lines"
        else:
            what = f"lines may be missing or repeated after a reconnect ({gap.cause})"
        # Best effort: a logging handler that raises must not end the read.
        with contextlib.suppress(Exception):
            _LOG.warning(
                "%s: a gap in the log (%s): %s; later gaps of this kind are "
                "counted and told once when the read ends",
                self.serial,
                gap.reason,
                what,
            )

    def tell_later_gaps(self) -> None:
        """Log, in one WARNING, how many gaps came after the first of each reason.

        Called when the device's read ends; nothing is logged when there were
        none. The counts start again from zero before the message is logged,
        and a logging handler that raises does not stop the caller (the read
        is ending; the message is only lost).
        """
        later = self._gaps_later
        counts = {reason: n for reason, n in sorted(later.items()) if n}
        if not counts:
            return
        for reason in later:
            later[reason] = 0
        with contextlib.suppress(Exception):
            _LOG.warning(
                "%s: %d more gaps in the log after the first of each kind (%s)",
                self.serial,
                sum(counts.values()),
                ", ".join(f"{reason} {n}" for reason, n in counts.items()),
            )

    def _process(self, framed: list[FramedLine], nbytes: int) -> list[Chunk]:  # noqa: PLR0912, PLR0915  (one flat loop: the per-line hot path)
        if not framed:
            self._carry += nbytes  # the line these bytes belong to ends later
            return []
        nbytes += self._carry
        self._carry = 0
        segments: list[Segment] = []
        entries: list[LogEntry] = []
        parse = self._parser.parse
        ctx = self._ctx
        predicate = self._predicate
        cursor = self._cursor
        awaited = self._awaited
        check = self._check
        kept = [] if check is not None else framed
        checked = unparsed = truncated = duplicates = markers = 0
        for line in framed:
            data, cut = line
            text = (
                decode_line(data, cut=True) if cut else data.decode("utf-8", "replace")
            )
            entry = parse(text, ctx)
            if check is not None:
                checked += 1
                admitted = check.admit(line, None if entry is None else entry.logged_at)
                if check.finished:
                    if entries:
                        segments.append(entries)
                        entries = []
                    gap = check.gap()
                    if gap is not None:
                        segments.append(gap)
                        self._count_gap(gap)
                    check = self._check = None
                if not admitted:
                    duplicates += 1
                    continue
                kept.append(line)
            if entry is None:
                if is_divider(text):
                    continue
                entry = unparsed_entry(text, ctx)
                unparsed += 1
            else:
                moment = entry.logged_at
                # Only a time with a zone moves the cursor: a resume needs one
                # (logcat -T), and logcat prints the zone on every line, so a
                # line without one comes from a broken producer.
                if has_zone(moment) and (cursor is None or moment > cursor):
                    cursor = moment
                tag = entry.tag
                if tag == MARKER_TAG:
                    token = entry.message.rstrip()
                    if _MARKER.fullmatch(token) is not None:
                        markers += 1
                        if token == awaited:
                            awaited = self._awaited = None
                            self.arrived = True
                            if entries:
                                segments.append(entries)
                                entries = []
                            segments.append(MarkerArrived(token))
                        continue
                elif tag == CHATTY_TAG:
                    lost = chatty_loss(entry.message)
                    if lost is not None:
                        if entries:
                            segments.append(entries)
                            entries = []
                        gap = Gap(
                            self.serial,
                            "device_reported",
                            "notice",
                            datetime.now(UTC),
                            moment,
                            lost,
                        )
                        segments.append(gap)
                        self._count_gap(gap)
            if cut:
                entry = replace(entry, truncated=True)
                truncated += 1
            if predicate is None or predicate(entry):
                entries.append(entry)
        if entries:
            segments.append(entries)
        if kept is not framed:
            kept.extend(framed[checked:])
        self._cursor = cursor
        self.lines += len(framed) - duplicates - markers
        self.unparsed += unparsed
        self.truncated += truncated
        self.duplicates += duplicates
        self.markers += markers
        delivered = 0
        for segment in segments:
            if type(segment) is list:
                delivered += len(segment)
        self.entries += delivered
        if kept:
            self._remember(_Group(kept, cursor, nbytes, len(kept)))
        return _chunks(segments, delivered, nbytes)

    def _remember(self, group: _Group) -> None:
        """Add one read's group to the history and trim it (see the module docs)."""
        history = self._history
        history.append(group)
        self._hbytes += group.nbytes
        self._hlines += group.nlines
        cursor = self._cursor
        horizon = None
        if cursor is not None:
            try:
                horizon = cursor - OVERLAP
            except OverflowError:  # a cursor at year 1: nothing is older
                horizon = cursor
            while history and (
                history[0].cursor is None or history[0].cursor < horizon
            ):
                self._drop_oldest()
        while history and (
            self._hbytes > HISTORY_BYTES or self._hlines > HISTORY_LINES
        ):
            dropped = self._drop_oldest()
            if (
                horizon is not None
                and dropped.cursor is not None
                and dropped.cursor >= horizon
            ):
                short = self._short_until
                if short is None or dropped.cursor > short:
                    self._short_until = dropped.cursor

    def _drop_oldest(self) -> _Group:
        group = self._history.popleft()
        self._hbytes -= group.nbytes
        self._hlines -= group.nlines
        return group
