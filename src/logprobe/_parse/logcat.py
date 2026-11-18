"""Parsers for the text formats of ``adb logcat -v <format>``.

The line shapes follow AOSP ``liblog/logprint.c`` (``android_log_formatLogLine``,
nougat-release; checked against API 24 and API 36 recordings in
``tests/fixtures/device``):

=========== ===================================================================
format      line
=========== ===================================================================
threadtime  ``<time> [<uid>] <pid:5> <tid:5> <level> <tag:-8>: <message>``
brief       ``<level>/<tag:-8>([<uid>:]<pid:5>): <message>``
process     ``<level>([<uid>:]<pid:5>) <message>  (<tag>)``
tag         ``<level>/<tag:-8>: <message>``
raw         ``<message>``
=========== ===================================================================

Every parser strips only the line terminator and the one separator space after
the tag: a message keeps its leading whitespace and trailing spaces.
Parsers keep no state between lines; what a session needs (the year of a
yearless date, the host clock) comes from the :class:`ParseContext` passed to
each call.
"""

from __future__ import annotations

import re
from abc import abstractmethod
from datetime import UTC, datetime, timedelta, timezone
from functools import lru_cache
from typing import TYPE_CHECKING, Protocol, cast

from .._entry import LogEntry

# Imported at run time, not only for type checking, so that
# typing.get_type_hints() resolves the parse() signatures; context.py imports
# only the standard library, so there is no cycle.
from .context import ParseContext  # noqa: TC001
from .fallback import strip_terminator
from .uid import parse_uid

if TYPE_CHECKING:
    from .._entry import LogLevel

__all__ = [
    "BriefLogParser",
    "LogParser",
    "ProcessLogParser",
    "RawLogParser",
    "TagLogParser",
    "ThreadTimeLogParser",
]

_LEVELS = frozenset("VDIWEF")
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_US_DIGITS = 6
# The longest -v zone offset that timezone() accepts: strictly under 24 h.
_MAX_ZONE_HOURS = 23
_MINUTES_PER_HOUR = 60
# The pid column in parentheses, shared by brief and process. ``-v uid`` puts
# ``<uid:5>:`` before the pid. An unknown uid prints six spaces and no colon, so
# the column is ``(<pid:5>)``, ``(      <pid:5>)`` or ``(<uid:5>:<pid:5>)``. The uid
# token is at most 10 characters (a 32-bit number) and never holds a colon, a
# parenthesis or a space. The group is lazy because most lines have no uid, and
# trying the pid first is the faster path for them.
_PID_COLUMN = r"\( *(?:([^\s:()]{1,10}): *)??(\d{1,7})\)"


class LogParser(Protocol):
    """What a parser provides: one line in, one entry (or None) out.

    A parser is stateless: anything that depends on earlier lines (the year of
    a yearless date) or on the host (the time of a line without a timestamp)
    comes from ``ctx``. One parser object may serve any number of sessions at
    once.

    To parse another format, write a class with these two members; there is no
    base class to inherit from::

        class CsvParser:
            logcat_format = "csv"

            def parse(self, line: str, ctx: ParseContext) -> LogEntry | None:
                ...  # return None for a line this format does not describe

    A class that names ``LogParser`` as its base anyway must define both
    members: both are abstract, so a subclass that defines only one raises
    TypeError when instantiated instead of returning None for every line.
    """

    @property
    @abstractmethod
    def logcat_format(self) -> str:
        """The ``adb logcat -v`` format the parser reads, such as ``"threadtime"``."""
        ...

    @abstractmethod
    def parse(self, line: str, ctx: ParseContext, /) -> LogEntry | None:
        """Split ``line`` into an entry.

        Args:
            line: One line, with or without its terminator (LF or CR LF).
            ctx: The parse session the line belongs to.

        Returns:
            The entry, carrying ``ctx.serial`` as its serial, or None when the
            line is not in this parser's format.
            The caller decides what an unrecognised line becomes (the readers
            yield an entry with ``parsed=False``).

        """
        ...


def _split_tag(rest: str) -> tuple[str, str] | None:
    """Split ``<tag padded with spaces>: <message>`` at the first ``": "``.

    An empty message whose trailing space was stripped (``<tag>:`` at the end)
    is accepted too. None when there is no separator.
    """
    sep = rest.find(": ")
    if sep >= 0:
        return rest[:sep].rstrip(" "), rest[sep + 2 :]
    if rest.endswith(":"):
        return rest[:-1].rstrip(" "), ""
    return None


@lru_cache(maxsize=64)
def _zone(text: str) -> timezone | None:
    """The tzinfo of a ``-v zone`` offset such as ``+0530``; None if impossible."""
    hours = int(text[1:3])
    minutes = int(text[3:5])
    if hours > _MAX_ZONE_HOURS or minutes >= _MINUTES_PER_HOUR:
        return None
    offset = timedelta(hours=hours, minutes=minutes)
    if not offset:
        return UTC
    return timezone(-offset if text[0] == "-" else offset)


def _microseconds(fraction: str) -> int:
    """The microseconds of a 3 (ms), 6 (us) or 9 (ns) digit fraction."""
    if len(fraction) >= _US_DIGITS:
        return int(fraction[:_US_DIGITS])  # nanoseconds are truncated
    return int(fraction) * 10 ** (_US_DIGITS - len(fraction))


class ThreadTimeLogParser:
    """Parser for ``-v threadtime`` with every modifier logcat combines with it.

    The time column takes any of these shapes, each with 3 (default), 6
    (``-v usec``) or 9 (``-v nsec``) fraction digits:

    - ``MM-DD hh:mm:ss.fff`` (the default): naive device-local time. The year
      comes from the session's :class:`ParseContext`.
    - ``YYYY-MM-DD hh:mm:ss.fff`` (``-v year``): naive device-local time.
    - either of the above followed by `` +hhmm`` (``-v zone``): timezone-aware.
    - ``<seconds>.fff`` right-aligned (``-v epoch``): aware, UTC. ``-v monotonic``
      prints seconds since boot in the same shape, so such a line parses as
      that many seconds after the epoch.

    A ``-v uid`` column between the time and the pid fills ``uid_raw`` with the
    column as printed and ``uid`` with its number: digits as they are,
    ``u<user>_a<n>`` and ``u<user>_i<n>`` by Android's naming, short platform
    names from this package's copy of the AID table, anything else None.

    The live wire format, ``-v threadtime -v year -v usec -v zone -v uid``,
    is one of these combinations. The tag ends at the first ``": "``
    after the level and loses its padding, so a tag may contain spaces
    (kernel lines on API 36) or be empty. ``-v printable`` and
    ``-v descriptive`` change only the message; ``-v color`` wraps the line in
    escape codes, which this parser does not recognise.
    """

    __slots__ = ()

    logcat_format = "threadtime"

    _HEADER = re.compile(
        r" *(?:"
        r"(?:(\d{4})-)?(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)"  # [year-]month-day time
        r"|(\d{1,12})"  # or epoch seconds
        r")\.(\d{3,9})"  # fraction
        r"(?: ([+-]\d{4}))?"  # -v zone
        r"(?: +(\S+))?"  # -v uid
        r" +(\d{1,7}) +(\d{1,7}) ([VDIWEF]) "  # pid, tid, level
    )

    def parse(self, line: str, ctx: ParseContext, /) -> LogEntry | None:
        """Parse one threadtime line; None when it is not one (see the class docs)."""
        text = strip_terminator(line)
        match = self._HEADER.match(text)
        if match is None:
            return None
        split = _split_tag(text[match.end() :])
        if split is None:
            return None
        timestamp = _threadtime_timestamp(match, ctx)
        if timestamp is None:
            return None
        uid_raw = match[10]
        # Positional arguments (logged_at, pid, tid, level, tag, message, raw, uid,
        # uid_raw, serial): measurably faster than keywords. The other parsers do
        # the same.
        return LogEntry(
            timestamp,
            int(match[11]),
            int(match[12]),
            cast("LogLevel", match[13]),
            split[0],
            split[1],
            text,
            None if uid_raw is None else parse_uid(uid_raw),
            uid_raw,
            ctx.serial,
        )


def _from_epoch(seconds: int, us: int, tzinfo: timezone | None) -> datetime | None:
    """``-v epoch`` seconds as an aware datetime (UTC unless a zone is given).

    None when the moment, or its wall clock in the given zone, is outside the
    years 1..9999.
    """
    try:
        moment = _EPOCH + timedelta(seconds=seconds, microseconds=us)
        return moment if tzinfo is None else moment.astimezone(tzinfo)
    except OverflowError:
        return None


def _threadtime_timestamp(match: re.Match[str], ctx: ParseContext) -> datetime | None:
    """The timestamp of a matched threadtime header; None if it is impossible.

    Resolving a yearless date commits the session's year state, so it is the
    last step that can reject the line.
    """
    us = _microseconds(match[8])
    zone = match[9]
    tzinfo = None if zone is None else _zone(zone)
    if zone is not None and tzinfo is None:
        return None
    epoch = match[7]
    if epoch is not None:
        return _from_epoch(int(epoch), us, tzinfo)
    month, day = int(match[2]), int(match[3])
    hour, minute, second = int(match[4]), int(match[5]), int(match[6])
    year = match[1]
    if year is not None:
        try:
            timestamp = datetime(
                int(year), month, day, hour, minute, second, us, tzinfo=tzinfo
            )
        except ValueError:
            return None
        ctx.observe(timestamp)
        return timestamp
    naive = ctx.resolve_yearless(month, day, hour, minute, second, us)
    if naive is None or tzinfo is None:
        return naive
    return naive.replace(tzinfo=tzinfo)


class BriefLogParser:
    """Parser for ``-v brief``: ``<level>/<tag>(<pid>): <message>``.

    The format has no time and no thread id: entries carry the host time
    (:meth:`ParseContext.now`) and ``tid=0``.

    A ``-v uid`` column inside the parentheses, ``(<uid>:<pid>)``, fills
    ``uid_raw`` with the column as printed and ``uid`` with its number (see
    :class:`ThreadTimeLogParser`); a blank column leaves both None.

    Ambiguity: the tag ends at the first ``(<digits>): `` or
    ``(<uid>:<digits>): `` in the line, because brief output cannot tell a
    tag's own parentheses from the pid column. A tag that itself contains
    ``( <digits>): `` therefore splits there, and the entry gets the digits
    inside the tag as its pid and the rest of the line as its message. A tag
    with other parentheses, such as ``Foo(Bar)``, parses as expected, and so
    does a message that contains ``( <digits>): `` or ``(<uid>:<digits>): ``.
    """

    __slots__ = ()

    logcat_format = "brief"

    _PID = re.compile(_PID_COLUMN + r":(?: |$)")

    def parse(self, line: str, ctx: ParseContext, /) -> LogEntry | None:
        """Parse one brief line; None when it is not one."""
        text = strip_terminator(line)
        if len(text) < 2 or text[0] not in _LEVELS or text[1] != "/":
            return None
        match = self._PID.search(text, 2)
        if match is None:
            return None
        uid_raw = match[1]
        return LogEntry(
            ctx.now(),
            int(match[2]),
            0,
            cast("LogLevel", text[0]),
            text[2 : match.start()].rstrip(" "),
            text[match.end() :],
            text,
            None if uid_raw is None else parse_uid(uid_raw),
            uid_raw,
            ctx.serial,
        )


class ProcessLogParser:
    """Parser for ``-v process``: ``<level>(<pid>) <message>  (<tag>)``.

    logcat appends the tag in parentheses after two spaces (as recorded on
    API 24 and 36). The message may hold parentheses itself, so the tag is the
    last ``  (...)`` group of a line that ends with ``)``. A line without that
    suffix parses with an empty tag. The format has no time and no thread id:
    entries carry the host time (:meth:`ParseContext.now`) and ``tid=0``.

    A ``-v uid`` column inside the parentheses, ``(<uid>:<pid>)``, fills
    ``uid_raw`` and ``uid`` as it does for brief lines; a blank column leaves
    both None.
    """

    __slots__ = ()

    logcat_format = "process"

    _HEAD = re.compile(r"([VDIWEF])" + _PID_COLUMN + r"(?: |$)")

    def parse(self, line: str, ctx: ParseContext, /) -> LogEntry | None:
        """Parse one process line; None when it is not one."""
        text = strip_terminator(line)
        match = self._HEAD.match(text)
        if match is None:
            return None
        message = text[match.end() :]
        tag = ""
        if message.endswith(")"):
            open_at = message.rfind("  (")
            if open_at >= 0:
                message, tag = message[:open_at], message[open_at + 3 : -1]
        uid_raw = match[2]
        return LogEntry(
            ctx.now(),
            int(match[3]),
            0,
            cast("LogLevel", match[1]),
            tag,
            message,
            text,
            None if uid_raw is None else parse_uid(uid_raw),
            uid_raw,
            ctx.serial,
        )


class TagLogParser:
    """Parser for ``-v tag``: ``<level>/<tag>: <message>``.

    The tag ends at the first ``": "``. The format has no time, pid or thread
    id: entries carry the host time (:meth:`ParseContext.now`), ``pid=0`` and
    ``tid=0``.
    """

    __slots__ = ()

    logcat_format = "tag"

    def parse(self, line: str, ctx: ParseContext, /) -> LogEntry | None:
        """Parse one tag line; None when it is not one."""
        text = strip_terminator(line)
        if len(text) < 2 or text[0] not in _LEVELS or text[1] != "/":
            return None
        split = _split_tag(text[2:])
        if split is None:
            return None
        tag, message = split
        return LogEntry(
            ctx.now(),
            0,
            0,
            cast("LogLevel", text[0]),
            tag,
            message,
            text,
            None,
            None,
            ctx.serial,
        )


class RawLogParser:
    """Parser for ``-v raw``: the line is the message.

    Every line parses. Entries carry the host time (:meth:`ParseContext.now`),
    level ``I`` and no pid, tid or tag.
    """

    __slots__ = ()

    logcat_format = "raw"

    def parse(self, line: str, ctx: ParseContext, /) -> LogEntry:
        """Return the line as an entry."""
        text = strip_terminator(line)
        return LogEntry(
            ctx.now(),
            0,
            0,
            "I",
            "",
            text,
            text,
            None,
            None,
            ctx.serial,
        )
