"""Reading log lines: `parse_lines` for strings and `read_file` for files.

Both go through the same stages for every line: the line terminator is
stripped, logcat's ``--------- beginning of <buffer>`` dividers are skipped,
the parser of the chosen format splits the line, and a line the parser does not
recognise becomes a fallback entry (``parsed=False``). `read_file` first frames
the bytes of the file into lines and decodes them.
"""

from __future__ import annotations

import logging
import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from ._framing import (
    DEFAULT_MAX_LINE_BYTES,
    MIN_MAX_LINE_BYTES,
    FramedLine,
    Framer,
    decode_line,
)
from ._parse import (
    BriefLogParser,
    LogParser,
    ParseContext,
    ProcessLogParser,
    RawLogParser,
    TagLogParser,
    ThreadTimeLogParser,
)
from ._parse.fallback import is_divider, unparsed_entry

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from typing import BinaryIO

    from ._entry import LogEntry

__all__ = ["parse_lines", "read_file"]

logger = logging.getLogger("logprobe.read")

# The size of one read from the file. The framer bounds what it keeps of a
# line, so the chunk size bounds nothing and only sets the syscall rate.
_CHUNK_BYTES = 64 * 1024

_PARSERS: dict[str, type[LogParser]] = {
    "threadtime": ThreadTimeLogParser,
    "brief": BriefLogParser,
    "process": ProcessLogParser,
    "tag": TagLogParser,
    "raw": RawLogParser,
}


def parse_lines(
    lines: Iterable[str],
    *,
    format: str = "threadtime",  # noqa: A002  (the public name)
    year: int | None = None,
) -> Iterator[LogEntry]:
    """Parse lines of text lazily, one entry per line.

    For log text that is already in memory: a REPL session, standard input, the
    output of another tool. Each call places yearless dates on its own, starting
    from ``year`` or the host clock, so two calls over the same lines give the
    same years.

    - A trailing LF is stripped, then any CRs before it, as `read_file` does
      (CR LF and CR CR LF read like LF); a CR inside a line stays in its
      message. ``io.StringIO(text)``, files opened with ``newline="\n"`` and
      ``sys.stdin`` on Linux split at LF only and work as they are; ``open()``
      with its default ``newline`` (or ``newline=""``) also splits at a bare
      CR, which cuts a line that contains one. For a str,
      use ``io.StringIO(text)`` or ``text.split("\n")``; the latter gives a
      trailing ``""`` (an empty unparsed entry) when the text ends with LF.
      Do not use ``str.splitlines()``: it also splits at a bare CR, U+2028 and
      other characters, which cuts one log line into several entries.
    - logcat's ``--------- beginning of <buffer>`` dividers are skipped.
    - A line the format does not describe is yielded as an entry with
      ``parsed=False`` whose ``message`` and ``raw`` are the whole line.
    - Lines without a timestamp (every format but ``"threadtime"``) and
      unrecognised lines are dated with the host clock when they are parsed.

    Args:
        lines: The lines, as an iterable of str. A single str is refused: it
            would be read one character at a time. Binary input (a file opened
            with ``"rb"``, ``sys.stdin.buffer``) is not accepted: use
            `read_file`, or decode the lines first.
        format: The ``adb logcat -v`` format of the lines: ``"threadtime"``
            (default; every variant with a year, ``usec``, ``nsec``,
            ``epoch``, ``zone`` or ``uid``), ``"brief"`` and ``"process"`` (both
            also read lines printed with ``-v uid``), ``"tag"`` or ``"raw"``.
        year: The year of the first line that carries no year (yearless
            ``-v threadtime``), unless a line with a printed year comes before
            it. With None and no printed year before it, the line is placed no later
            than two days after the host clock.

    Returns:
        An iterator over the entries.

    Raises:
        ValueError: ``format`` is not one of the above, or ``year`` is outside
            1..9999. Raised by this call, not by the first ``next()``.
        TypeError: ``lines`` is not iterable or is a str or bytes, or ``year``
            is not an int. Raised by this call.

    """
    parser = _parser(format)
    if isinstance(lines, str | bytes | bytearray | memoryview):
        msg = (
            f"lines must be an iterable of str, not {type(lines).__name__}: "
            'pass one str per line, such as io.StringIO(text) or text.split("\\n")'
        )
        raise TypeError(msg)
    # iter() raises TypeError for a non-iterable here; it reads nothing.
    iterator = iter(lines)
    ctx = ParseContext(year=year)  # a bad year fails here, not at the first line
    return _parse_lines(iterator, parser, ctx)


def _parse_lines(
    lines: Iterator[str], parser: LogParser, ctx: ParseContext
) -> Iterator[LogEntry]:
    for line in lines:
        # Strip as the framer of read_file does: one LF, then every CR before it.
        entry = _entry(line.removesuffix("\n").rstrip("\r"), parser, ctx)
        if entry is not None:
            yield entry


def read_file(
    path: str | os.PathLike[str],
    *,
    format: str = "threadtime",  # noqa: A002  (the public name)
    year: int | None = None,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
) -> Iterator[LogEntry]:
    """Read a log file lazily, one entry per line.

    The arguments are checked when ``read_file`` is called; the file is opened
    at the first ``next()`` and read in one pass, and it is closed when it is
    exhausted or the iterator is closed. Every call is a parse session of its
    own, so reading a file twice resolves its yearless dates the same way.
    Lines without a timestamp (every format but ``"threadtime"``) and
    unrecognised lines are dated with the host clock when they are read, so a
    second read gives them other timestamps.

    How lines are read:

    - A line ends at LF only. The CRs before the LF are stripped (CR LF and CR
      CR LF files read like LF files); a CR inside a line stays in its message.
    - A UTF-8 BOM at the start of the file is skipped. Each line is decoded as
      UTF-8; an undecodable byte becomes U+FFFD.
    - A line longer than ``max_line_bytes`` keeps its first ``max_line_bytes``
      bytes and gives an entry with ``truncated=True``; the next line is read
      as usual. When the cut falls inside a character, the entry ends before
      that character (at most 3 bytes are dropped), not with a U+FFFD.
    - logcat's ``--------- beginning of <buffer>`` dividers are skipped.
    - A line the format does not describe is yielded as an entry with
      ``parsed=False`` whose message is the whole line.

    At the end of a read, or when the iterator is closed early, one WARNING on
    the logger ``logprobe.read`` reports the lines that were not recognised (a
    format mismatch), and another the cut lines, each only if there were any.

    Args:
        path: The log file.
        format: The ``adb logcat -v`` format of the file: ``"threadtime"``
            (default; every variant with a year, ``usec``, ``nsec``,
            ``epoch``, ``zone`` or ``uid``), ``"brief"`` and ``"process"`` (both
            also read lines printed with ``-v uid``), ``"tag"`` or ``"raw"``.
        year: The year of the first line that carries no year (yearless
            ``-v threadtime``), unless a line with a printed year comes before
            it. With None and no printed year before it, the line is placed no
            later than two days after the file's modification time (or the
            host clock when the modification time is not a valid local
            datetime).
        max_line_bytes: The longest line kept whole, in bytes; >= 4096.

    Returns:
        An iterator over the entries.

    Raises:
        TypeError: ``path`` is not a path, ``year`` is not an int, or
            ``max_line_bytes`` is not an int.
        ValueError: ``format`` is not one of the above; ``year`` is outside
            1..9999; ``max_line_bytes`` is below 4096; ``path`` contains a NUL
            character.
        OSError: From the first ``next()``: the file cannot be opened or read.

    """
    parser = _parser(format)
    file_path = Path(path)
    if "\x00" in str(file_path):
        # open() would raise this ValueError only at the first next().
        msg = "path must not contain a NUL character"
        raise ValueError(msg)
    ParseContext(year=year)  # a bad year fails here, not at the first line
    _check_max_line_bytes(max_line_bytes)
    return _read(file_path, parser, year, max_line_bytes)


def _read(
    path: Path, parser: LogParser, year: int | None, max_line_bytes: int
) -> Iterator[LogEntry]:
    """The generator behind `read_file`, for checked arguments."""
    framer = Framer(max_line_bytes, strip_bom=True)
    unparsed = truncated = lines = 0
    with path.open("rb", buffering=0) as file:
        # The mtime anchors the first yearless line only without year=.
        anchor = None if year is not None else _mtime(file.fileno())
        ctx = ParseContext(year=year, anchor=anchor)
        try:
            for line in _framed(file, framer):
                lines += 1
                truncated += line.truncated
                entry = _entry(decode_line(line.data, cut=line.truncated), parser, ctx)
                if entry is None:
                    continue
                unparsed += not entry.parsed
                yield replace(entry, truncated=True) if line.truncated else entry
        finally:
            _report(
                path, parser.logcat_format, unparsed, truncated, lines, max_line_bytes
            )


def _framed(file: BinaryIO, framer: Framer) -> Iterator[FramedLine]:
    """The lines of ``file``, framed."""
    while chunk := file.read(_CHUNK_BYTES):
        yield from framer.feed(chunk)
    yield from framer.finish()


def _report(
    path: Path,
    format_: str,
    unparsed: int,
    truncated: int,
    lines: int,
    max_line_bytes: int,
) -> None:
    """Log one WARNING each for unrecognised lines and for cut lines."""
    if unparsed:
        logger.warning(
            "%d of %d lines in %s are not in the %r format; "
            "they were read as unparsed entries (parsed=False).",
            unparsed,
            lines,
            path,
            format_,
        )
    if truncated:
        logger.warning(
            "%d of %d lines in %s are longer than max_line_bytes=%d; "
            "their entries hold at most the first %d bytes (truncated=True).",
            truncated,
            lines,
            path,
            max_line_bytes,
            max_line_bytes,
        )


def _entry(text: str, parser: LogParser, ctx: ParseContext) -> LogEntry | None:
    """The entry of one line without its terminator; None for a divider."""
    if is_divider(text):
        return None
    entry = parser.parse(text, ctx)
    if entry is None:
        return unparsed_entry(text, ctx)
    return entry


def _mtime(fd: int) -> datetime | None:
    """The modification time of the open file ``fd``, as naive host-local time.

    None when it cannot be read or is no datetime in host-local time (an mtime
    far outside the years 1..9999, or one the platform's time functions
    refuse); the first yearless line is then placed before the host clock.
    """
    try:
        moment = datetime.fromtimestamp(os.fstat(fd).st_mtime, tz=UTC)
        return moment.astimezone().replace(tzinfo=None)
    except (OSError, OverflowError, ValueError):
        return None


def _parser(format_: str) -> LogParser:
    """A parser for ``format_``.

    Raises:
        ValueError: ``format_`` is not a supported format.

    """
    parser_class = _PARSERS.get(format_) if isinstance(format_, str) else None
    if parser_class is None:
        names = ", ".join(repr(name) for name in _PARSERS)
        msg = f"Unsupported format: {format_!r}; expected one of {names}"
        raise ValueError(msg)
    return parser_class()


def _check_max_line_bytes(value: object) -> None:
    """Check that ``value`` is an int of at least 4096.

    Raises:
        TypeError: ``value`` is not an int (a bool is not).
        ValueError: ``value`` is below 4096.

    """
    if isinstance(value, bool) or not isinstance(value, int):
        msg = f"max_line_bytes must be an int, not {type(value).__name__}"
        raise TypeError(msg)
    if value < MIN_MAX_LINE_BYTES:
        msg = f"max_line_bytes must be at least {MIN_MAX_LINE_BYTES}, not {value}"
        raise ValueError(msg)
