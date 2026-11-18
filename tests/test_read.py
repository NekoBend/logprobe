"""Tests for read_file and parse_lines."""

from __future__ import annotations

import io
import logging
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest

from logprobe import LogEntry, _read, parse_lines, read_file

if TYPE_CHECKING:
    from collections.abc import Generator

CAP = 4096  # the smallest max_line_bytes
BOM = "\ufeff"  # U+FEFF, the UTF-8 BOM once encoded


@pytest.fixture
def sample_log_content() -> str:
    """Provide sample log content with mixed valid and invalid lines."""
    return (
        "11-19 12:34:56.789  1000  2000 D TagA   : Message A\n"
        "Invalid Line That Does Not Match Regex\n"
        "11-19 12:34:57.000  1000  2000 I TagB   : Message B\n"
    )


@pytest.fixture
def sample_log_file(tmp_path: Path, sample_log_content: str) -> Path:
    """Create a temporary log file with sample content."""
    log_file = tmp_path / "test.log"
    log_file.write_text(sample_log_content, encoding="utf-8")
    return log_file


def _write_lines(path: Path, *lines: str) -> Path:
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    return path


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


# -- reading ---------------------------------------------------------------------------


def test_read_file_yields_parsed_and_unparsed_entries(sample_log_file: Path) -> None:
    """Every line gives an entry; an unrecognised one has parsed=False."""
    entries = list(read_file(sample_log_file))

    assert [(e.tag, e.message, e.level, e.parsed) for e in entries] == [
        ("TagA", "Message A", "D", True),
        ("", "Invalid Line That Does Not Match Regex", "I", False),
        ("TagB", "Message B", "I", True),
    ]


def test_read_file_not_found() -> None:
    """Test that FileNotFoundError is raised for non-existent files."""
    non_existent_file = Path("non_existent_file.log")

    with pytest.raises(FileNotFoundError):
        list(read_file(non_existent_file))


def test_file_is_opened_at_the_first_next(tmp_path: Path) -> None:
    """The call checks the arguments only; opening the file waits for next()."""
    lazy = read_file(tmp_path / "later.log")
    _write_lines(tmp_path / "later.log", "11-19 12:34:56.789  1  1 D T: a")

    assert [e.message for e in lazy] == ["a"]


def test_unparsed_line_becomes_fallback_entry(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A line the parser rejects is yielded whole as a parsed=False entry.

    Nothing previews, sanitizes or logs the line itself: control characters
    stay in the entry, and the only log record is the one mismatch WARNING.
    """
    line = "BAD\x00\x1b[31mCTRL" + "X" * 3000
    log_file = _write_lines(tmp_path / "malformed.log", line)

    with caplog.at_level(logging.DEBUG, logger="logprobe"):
        (entry,) = read_file(log_file)

    assert (entry.parsed, entry.message, entry.raw) == (False, line, line)
    assert (entry.pid, entry.tid, entry.tag, entry.level) == (0, 0, "", "I")
    assert len(caplog.records) == 1
    assert "\x1b" not in caplog.records[0].getMessage()


def test_divider_lines_are_skipped(tmp_path: Path) -> None:
    """logcat's buffer dividers are not entries."""
    log_file = _write_lines(
        tmp_path / "dividers.log",
        "--------- beginning of main",
        "11-19 12:34:56.789  1000  2000 D TagA   : a",
        "--------- switch to crash",
    )

    assert [e.message for e in read_file(log_file, year=2026)] == ["a"]


# -- the format-mismatch warning -----------------------------------------------


def test_format_mismatch_warns_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Lines in another format give one WARNING per read, with their count.

    logcat's buffer dividers are neither entries nor counted as unparsed, but
    they are lines of the file; the other lines are yielded as unparsed entries.
    """
    log_file = _write_lines(
        tmp_path / "brief.log",
        "--------- beginning of main",
        "D/Tag( 1234): one",
        "D/Tag( 1234): two",
        "11-19 12:34:56.789  1000  2000 D TagA   : threadtime",
        "D/Tag( 1234): three",
    )

    with caplog.at_level(logging.WARNING, logger="logprobe.read"):
        entries = list(read_file(log_file, year=2026))
    warnings = _warnings(caplog)

    assert [e.parsed for e in entries] == [False, False, True, False]
    assert [e.message for e in entries][:2] == [
        "D/Tag( 1234): one",
        "D/Tag( 1234): two",
    ]
    assert len(warnings) == 1
    assert warnings[0].startswith("3 of 5 lines in ")
    assert "'threadtime'" in warnings[0]

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="logprobe.read"):
        list(read_file(log_file, year=2026))
    assert len(_warnings(caplog)) == 1


def test_matching_file_and_dividers_do_not_warn(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A file in the parser's format, dividers included, logs no warning."""
    log_file = _write_lines(
        tmp_path / "ok.log",
        "--------- beginning of main",
        "11-19 12:34:56.789  1000  2000 D TagA   : a",
        "--------- switch to crash",
        "11-19 12:34:57.000  1000  2000 E TagB   : b",
    )

    with caplog.at_level(logging.WARNING, logger="logprobe.read"):
        entries = list(read_file(log_file, year=2026))

    assert [e.parsed for e in entries] == [True, True]
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_mismatch_warning_is_logged_when_the_read_stops_early(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Closing the reader early still reports the lines read so far."""
    log_file = _write_lines(tmp_path / "raw.log", "not a log line", "neither")

    with caplog.at_level(logging.WARNING, logger="logprobe.read"):
        entries = cast("Generator[LogEntry]", read_file(log_file))
        next(entries)
        entries.close()

    (warning,) = _warnings(caplog)
    assert warning.startswith("1 of 1 lines in ")


# -- framing in files ------------------------------------------


def test_oversized_line_is_one_truncated_entry(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A line over max_line_bytes is one entry with truncated=True, holding its first
    max_line_bytes bytes, and the next line is read as usual.
    """
    head = "11-19 12:34:56.789  1000  2000 D Long: "
    long_line = head + "x" * (2 * CAP)
    log_file = _write_lines(
        tmp_path / "long.log", long_line, "11-19 12:34:57.000  1  1 I Next: after"
    )

    with caplog.at_level(logging.WARNING, logger="logprobe.read"):
        entries = list(read_file(log_file, year=2026, max_line_bytes=CAP))

    assert [(e.tag, e.truncated) for e in entries] == [("Long", True), ("Next", False)]
    assert entries[0].raw == long_line[:CAP]
    assert entries[1].message == "after"
    (warning,) = _warnings(caplog)
    assert warning.startswith("1 of 2 lines in ")
    assert f"max_line_bytes={CAP}" in warning


def test_entries_from_files_and_text_have_no_serial(tmp_path: Path) -> None:
    """Parsed, unparsed and truncated entries all keep serial=None."""
    lines = [
        "11-19 12:34:56.789  1000  2000 D Long: " + "x" * (2 * CAP),
        "11-19 12:34:57.000  1  1 I Next: after",
        "not a log line",
    ]
    log_file = _write_lines(tmp_path / "serial.log", *lines)

    from_file = list(read_file(log_file, year=2026, max_line_bytes=CAP))
    from_text = list(parse_lines(lines, year=2026))

    assert [e.parsed for e in from_file] == [True, True, False]
    assert from_file[0].truncated
    assert len(from_text) == 3
    assert all(e.serial is None for e in [*from_file, *from_text])


def test_line_of_exactly_max_line_bytes_is_whole(tmp_path: Path) -> None:
    """The cap counts the line without its terminator, CR LF included."""
    head = "11-19 12:34:56.789  1000  2000 D Edge: "
    line = head + "y" * (CAP - len(head))
    log_file = tmp_path / "edge.log"
    log_file.write_bytes(f"{line}\r\n{line}y\r\n".encode())

    entries = list(read_file(log_file, year=2026, max_line_bytes=CAP))

    assert [(len(e.raw), e.truncated) for e in entries] == [(CAP, False), (CAP, True)]


@pytest.mark.parametrize("char", ["日", "\U0001f600"], ids=["3b", "4b"])
def test_cut_inside_a_character_adds_no_replacement(tmp_path: Path, char: str) -> None:
    """A cut that falls inside a character ends the entry before it: the
    entry holds no U+FFFD that the file does not hold.
    """
    head = "11-19 12:34:56.789  1000  2000 D Long: "
    size = len(char.encode())
    for pad in range(size):
        line = head + "a" * pad + char * CAP
        log_file = _write_lines(
            tmp_path / "cut.log", line, "11-19 12:34:57.000  1  1 I N: b"
        )
        kept = (CAP - len(head) - pad) // size

        cut, after = read_file(log_file, year=2026, max_line_bytes=CAP)

        assert (cut.truncated, cut.message) == (True, "a" * pad + char * kept), pad
        assert cut.raw == line[: len(head) + pad + kept]
        assert after.message == "b"


@pytest.mark.parametrize("chunk", [1, 2, 3, 7, 4096])
def test_small_reads_give_the_same_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, chunk: int
) -> None:
    """Chunk boundaries inside a BOM, a CR LF or a character change nothing."""
    data = (
        b"\xef\xbb\xbf"
        + "11-19 12:34:56.789  1  1 D T: café 日本\r\n".encode()
        + b"11-19 12:34:57.000  2  2 I T: bare\rcr\r\r\n"
        + b"11-19 12:34:58.000  3  3 W T: no lf at the end"
    )
    log_file = tmp_path / "chunks.log"
    log_file.write_bytes(data)
    expected = [(e.pid, e.message) for e in read_file(log_file, year=2026)]
    monkeypatch.setattr(_read, "_CHUNK_BYTES", chunk)

    entries = [(e.pid, e.message) for e in read_file(log_file, year=2026)]

    assert entries == expected
    assert entries == [
        (1, "café 日本"),
        (2, "bare\rcr"),
        (3, "no lf at the end"),
    ]


def test_bom_after_offset_0_stays(tmp_path: Path) -> None:
    """Only a BOM at the very start of the file is skipped."""
    line = "11-19 12:34:56.789  1  1 D T: a"
    log_file = tmp_path / "bom.log"
    log_file.write_bytes(f"{line}\n{BOM}{line}\n".encode())

    entries = list(read_file(log_file, year=2026))

    assert [e.parsed for e in entries] == [True, False]
    assert entries[1].raw == f"{BOM}{line}"


# -- year ------------------------------------------------------------------------------


def _set_mtime(path: Path, moment: datetime) -> None:
    os.utime(path, (moment.timestamp(), moment.timestamp()))


def test_yearless_lines_are_dated_before_the_file_mtime(tmp_path: Path) -> None:
    """Without year=, the first yearless line is placed before the file's mtime.

    A capture across New Year saved on Jan 2 starts in the old year; a March
    capture copied in November (a later mtime) stays in that year's March,
    although the next March would be nearer to the mtime.
    """
    new_year = _write_lines(
        tmp_path / "new_year.log",
        "12-30 08:00:00.000  1000  2000 D T: a",
        "12-31 23:59:59.000  1000  2000 D T: b",
        "01-01 00:00:01.000  1000  2000 D T: c",
    )
    _set_mtime(new_year, datetime(2027, 1, 2, 12, 0, tzinfo=UTC))
    spring = _write_lines(
        tmp_path / "spring.log",
        "03-15 10:00:00.000  1000  2000 D T: a",
        "03-15 10:00:01.000  1000  2000 D T: b",
    )
    _set_mtime(spring, datetime(2026, 11, 4, 12, 0, tzinfo=UTC))

    assert [e.logged_at.year for e in read_file(new_year)] == [2026, 2026, 2027]
    assert [e.logged_at.year for e in read_file(spring)] == [2026, 2026]


def test_year_argument_dates_the_first_yearless_line(tmp_path: Path) -> None:
    """year= gives the first yearless line its year, whatever the mtime."""
    log_file = _write_lines(
        tmp_path / "y.log",
        "12-31 23:59:59.000  1000  2000 D T: a",
        "01-01 00:00:01.000  1000  2000 D T: b",
    )

    assert [e.logged_at.year for e in read_file(log_file, year=2019)] == [2019, 2020]


@pytest.mark.parametrize("year", [0, 10_000])
def test_year_out_of_range_is_rejected(tmp_path: Path, year: int) -> None:
    """A year outside 1..9999 raises ValueError when read_file is called."""
    with pytest.raises(ValueError, match="year"):
        read_file(tmp_path / "x.log", year=year)


@pytest.mark.parametrize(
    "mtime",
    [
        pytest.param(253_402_300_800.0, id="year-10000"),
        pytest.param(1e20, id="past-time_t"),
        pytest.param(-1e20, id="before-time_t"),
    ],
)
def test_mtime_without_a_datetime_does_not_fail_the_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mtime: float
) -> None:
    """An mtime outside what datetime holds is no error, with or without year=.

    With year= the mtime is not used at all; without it the first yearless
    line is placed before the host clock instead. The mtime is patched in,
    because a file system may refuse to store such a value.
    """
    log_file = _write_lines(tmp_path / "far.log", "12-31 23:59:59.000  1  1 D T: a")
    real_fstat = os.fstat

    def fstat(fd: int) -> SimpleNamespace:
        # Everything else that asks (the interpreter does) gets the real values.
        status = real_fstat(fd)
        fields = {name: getattr(status, name) for name in dir(status)}
        return SimpleNamespace(**{**fields, "st_mtime": mtime})

    monkeypatch.setattr(os, "fstat", fstat)

    with_year = list(read_file(log_file, year=2024))
    without = list(read_file(log_file))

    assert [e.logged_at.year for e in with_year] == [2024]
    assert len(without) == 1
    assert without[0].parsed
    assert without[0].logged_at <= datetime.now(UTC).astimezone().replace(
        tzinfo=None
    ) + timedelta(days=2)


# -- argument checks -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "error", "match"),
    [
        ({"format": "xml"}, ValueError, "Unsupported format.*'threadtime'"),
        ({"format": None}, ValueError, "Unsupported format"),
        ({"year": "2026"}, TypeError, "year"),
        ({"year": 0}, ValueError, "year"),
        ({"max_line_bytes": True}, TypeError, "int"),
        ({"max_line_bytes": 4096.0}, TypeError, "int"),
        ({"max_line_bytes": CAP - 1}, ValueError, "at least 4096"),
    ],
    ids=[
        "format",
        "format-none",
        "year-str",
        "year-0",
        "cap-bool",
        "cap-float",
        "cap-small",
    ],
)
def test_bad_arguments_raise_at_the_call(
    tmp_path: Path, kwargs: dict[str, Any], error: type[Exception], match: str
) -> None:
    """Every argument is checked when read_file is called, before any I/O."""
    with pytest.raises(error, match=match):
        read_file(tmp_path / "missing.log", **kwargs)


def test_arguments_are_keyword_only(tmp_path: Path) -> None:
    """Only the path is positional."""
    with pytest.raises(TypeError):
        read_file(tmp_path / "x.log", "brief")  # ty: ignore[too-many-positional-arguments]


@pytest.mark.parametrize("kind", ["str", "path"])
def test_path_with_a_nul_raises_at_the_call(tmp_path: Path, kind: str) -> None:
    """A NUL in the path is a ValueError of the call, like the other checks,
    not one of the first next().
    """
    path = tmp_path / "a\x00b.log"

    with pytest.raises(ValueError, match="NUL"):
        read_file(str(path) if kind == "str" else path)


def test_file_is_closed_when_exhausted_and_when_the_iterator_is_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file does not stay open after the last entry or after close()."""
    opened: list[Any] = []
    real_open = Path.open

    def tracking_open(self: Path, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        file = real_open(self, *args, **kwargs)
        opened.append(file)
        return file

    log_file = _write_lines(
        tmp_path / "two.log",
        "11-19 12:34:56.789  1  1 D T: a",
        "11-19 12:34:57.789  1  1 D T: b",
    )
    monkeypatch.setattr(Path, "open", tracking_open)

    assert len(list(read_file(log_file, year=2026))) == 2
    partial = cast("Generator[LogEntry]", read_file(log_file, year=2026))
    next(partial)
    assert [file.closed for file in opened] == [True, False]
    partial.close()

    assert [file.closed for file in opened] == [True, True]


# -- format selection ------------------------------------------------------------------

# One line per format, and what each yields: (pid, tid, level, tag, message).
FORMAT_LINES = {
    "threadtime": (
        "11-19 12:34:56.789  1234  5678 W MyTag   : hello",
        (1234, 5678, "W", "MyTag", "hello"),
    ),
    "brief": ("W/MyTag( 1234): hello", (1234, 0, "W", "MyTag", "hello")),
    "process": ("W( 1234) hello  (MyTag)", (1234, 0, "W", "MyTag", "hello")),
    "tag": ("W/MyTag   : hello", (0, 0, "W", "MyTag", "hello")),
    "raw": ("hello", (0, 0, "I", "", "hello")),
}


@pytest.mark.parametrize("fmt", list(FORMAT_LINES))
def test_read_file_format_selects_the_parser(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, fmt: str
) -> None:
    """Each format reads its own lines, and the file is read in that format."""
    line, expected = FORMAT_LINES[fmt]
    log_file = _write_lines(tmp_path / "x.log", line)

    with caplog.at_level(logging.WARNING, logger="logprobe.read"):
        (entry,) = read_file(log_file, format=fmt, year=2026)

    assert not _warnings(caplog)

    assert entry.parsed
    assert (entry.pid, entry.tid, entry.level, entry.tag, entry.message) == expected
    assert entry.raw == line


def test_read_file_format_mismatch_is_unparsed(tmp_path: Path) -> None:
    """A brief line read as threadtime is a fallback entry, not an error."""
    log_file = _write_lines(tmp_path / "brief.log", "D/Tag( 1234): one")

    (entry,) = read_file(log_file, format="threadtime")

    assert (entry.parsed, entry.message) == (False, "D/Tag( 1234): one")


def test_format_mismatch_warning_names_the_chosen_format(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    log_file = _write_lines(
        tmp_path / "tt.log", "11-19 12:34:56.789  1000  2000 D TagA   : m"
    )

    with caplog.at_level(logging.WARNING, logger="logprobe.read"):
        (entry,) = read_file(log_file, format="brief", year=2026)

    assert not entry.parsed
    (warning,) = _warnings(caplog)
    assert "'brief'" in warning
    assert "'threadtime'" not in warning


# -- parse_lines -----------------------------------------------------------------------


@pytest.mark.parametrize("fmt", list(FORMAT_LINES))
def test_parse_lines_format_selects_the_parser(fmt: str) -> None:
    line, expected = FORMAT_LINES[fmt]

    (entry,) = parse_lines([line], format=fmt, year=2026)

    assert entry.parsed
    assert (entry.pid, entry.tid, entry.level, entry.tag, entry.message) == expected
    assert entry.raw == line


def test_parse_lines_default_format_is_threadtime() -> None:
    (entry,) = parse_lines(["11-19 12:34:56.789  1  2 D T: a"], year=2026)

    assert (entry.logged_at, entry.pid, entry.tid, entry.message) == (
        datetime(2026, 11, 19, 12, 34, 56, 789000),  # noqa: DTZ001  (naive device time)
        1,
        2,
        "a",
    )


@pytest.mark.parametrize(
    ("line", "aware", "uid"),
    [
        ("2026-11-04 05:11:16.661446 +0900 10065  1234  1234 I Tag: m", True, 10065),
        ("2026-11-04 05:11:16.661446123  1234  1234 I Tag: m", False, None),
        ("1762233076.661  1234  1234 I Tag: m", True, None),
        ("11-04 05:11:16.661  1234  1234 I Tag: m", False, None),
    ],
    ids=["year-usec-zone-uid", "year-nsec", "epoch", "yearless"],
)
def test_parse_lines_reads_every_threadtime_variant(
    line: str, *, aware: bool, uid: int | None
) -> None:
    (entry,) = parse_lines([line], year=2026)

    assert entry.parsed
    assert (entry.logged_at.tzinfo is not None) is aware
    assert entry.uid == uid
    assert (entry.pid, entry.message) == (1234, "m")


def test_parse_lines_strips_line_terminators() -> None:
    lines = ["D/T( 1): a\n", "D/T( 1): b\r\n", "D/T( 1): c", "D/T( 1): d\r"]

    entries = list(parse_lines(lines, format="brief"))

    assert [e.message for e in entries] == ["a", "b", "c", "d"]
    assert [e.raw for e in entries] == [f"D/T( 1): {c}" for c in "abcd"]


_EPOCH = datetime(2000, 1, 1)  # noqa: DTZ001  (naive, as parsed entries are)

PARITY_DATA = [
    b"..T: a\r\n..T: b\rc\r\r\n",  # CR LF, a bare CR inside, CR CR LF
    b"..T: a\r\n..T: tail\r\r",  # trailing CRs at EOF
    "..T: a\u2028b\n..T: c\n".encode(),  # U+2028 is not a line end
    b"..T: a\n\nnot logcat\r\n",  # an empty line and an unparsed one
]


@pytest.mark.parametrize("data", PARITY_DATA)
def test_parse_lines_over_stringio_reads_like_read_file(
    tmp_path: Path, data: bytes
) -> None:
    """The same bytes give the same entries through both readers."""
    prefix = b"11-19 12:34:56.789  1  1 D "
    data = data.replace(b"..T", prefix + b"T")
    log_file = tmp_path / "x.log"
    log_file.write_bytes(data)

    from_file = list(read_file(log_file, year=2026))
    from_text = list(parse_lines(io.StringIO(data.decode()), year=2026))

    def comparable(entry: LogEntry) -> LogEntry:
        # Unparsed entries are dated with the host clock when they are read.
        return entry if entry.parsed else replace(entry, logged_at=_EPOCH)

    assert [comparable(e) for e in from_text] == [comparable(e) for e in from_file]
    assert from_text  # the data is not empty


def test_parse_lines_keeps_a_bare_cr_and_u2028_inside_a_message() -> None:
    text = "11-19 12:34:56.789  1  1 D T: b\rc\u2028d\r\r\n"

    (entry,) = parse_lines(io.StringIO(text), year=2026)

    assert (entry.parsed, entry.message) == (True, "b\rc\u2028d")


def test_read_file_empty_input_gives_no_entries(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    for data in (b"", b"\xef\xbb\xbf"):
        log_file = tmp_path / "empty.log"
        log_file.write_bytes(data)
        with caplog.at_level(logging.WARNING, logger="logprobe.read"):
            assert list(read_file(log_file)) == []
    assert not _warnings(caplog)
    assert list(parse_lines([])) == []


@pytest.mark.parametrize("data", [b"\n", b"\xef\xbb\xbf\n"])
def test_read_file_blank_line_is_one_unparsed_entry(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, data: bytes
) -> None:
    log_file = tmp_path / "blank.log"
    log_file.write_bytes(data)

    with caplog.at_level(logging.WARNING, logger="logprobe.read"):
        entries = list(read_file(log_file))

    assert [(e.parsed, e.message) for e in entries] == [(False, "")]
    assert len(_warnings(caplog)) == 1


def test_parse_lines_unrecognised_lines_become_fallback_entries() -> None:
    entries = list(parse_lines(["not logcat\n", "11-19 12:34:56.789  1  1 D T: ok"]))

    assert [(e.parsed, e.message, e.raw) for e in entries] == [
        (False, "not logcat", "not logcat"),
        (True, "ok", "11-19 12:34:56.789  1  1 D T: ok"),
    ]
    assert (entries[0].pid, entries[0].tid, entries[0].tag, entries[0].level) == (
        0,
        0,
        "",
        "I",
    )


def test_parse_lines_skips_dividers() -> None:
    lines = [
        "--------- beginning of main\n",
        "11-19 12:34:56.789  1  1 D T: a",
        "--------- switch to crash",
    ]

    assert [e.message for e in parse_lines(lines, year=2026)] == ["a"]


def test_parse_lines_keeps_dashes_in_a_raw_message() -> None:
    """Only logcat's own divider shape is skipped."""
    lines = ["--------- not a divider", "--------- beginning of main"]

    assert [e.message for e in parse_lines(lines, format="raw")] == [
        "--------- not a divider"
    ]


def test_parse_lines_is_lazy() -> None:
    """Nothing is read before the first next(); lines are consumed one by one."""
    consumed: list[str] = []

    def source() -> Any:  # noqa: ANN401
        for line in ("D/T( 1): a", "D/T( 1): b"):
            consumed.append(line)
            yield line

    entries = parse_lines(source(), format="brief")
    assert consumed == []
    next(entries)
    assert consumed == ["D/T( 1): a"]


def test_parse_lines_accepts_any_iterable_of_str() -> None:
    assert [e.message for e in parse_lines(iter(("a", "b")), format="raw")] == [
        "a",
        "b",
    ]
    assert [e.message for e in parse_lines(("a",), format="raw")] == ["a"]


def test_parse_lines_year_places_the_first_yearless_line() -> None:
    lines = [
        "12-31 23:59:59.000  1  1 D T: a",
        "01-01 00:00:01.000  1  1 D T: b",
    ]

    assert [e.logged_at.year for e in parse_lines(lines, year=2019)] == [2019, 2020]


@pytest.mark.parametrize(
    ("kwargs", "error", "match"),
    [
        ({"format": "xml"}, ValueError, "Unsupported format.*'threadtime'"),
        ({"format": "ThreadTime"}, ValueError, "Unsupported format"),
        ({"year": 0}, ValueError, "year"),
        ({"year": 10_000}, ValueError, "year"),
        ({"year": "2026"}, TypeError, "year"),
        ({"lines": None}, TypeError, "iterable"),
        ({"lines": 5}, TypeError, "iterable"),
        ({"lines": bytearray(b"ab")}, TypeError, "iterable of str"),
        ({"lines": "a line\n"}, TypeError, "iterable of str"),
        ({"lines": b"a line\n"}, TypeError, "iterable of str"),
    ],
)
def test_parse_lines_checks_its_arguments_at_the_call(
    kwargs: dict[str, Any], error: type[Exception], match: str
) -> None:
    """Raised by the call itself, not by the first next()."""
    arguments: dict[str, Any] = {"lines": ["x"], **kwargs}

    with pytest.raises(error, match=match):
        parse_lines(**arguments)


def test_parse_lines_arguments_after_lines_are_keyword_only() -> None:
    with pytest.raises(TypeError):
        parse_lines(["x"], "brief")  # ty: ignore[too-many-positional-arguments]


def test_parse_lines_exception_from_the_source_propagates() -> None:
    def source() -> Any:  # noqa: ANN401
        yield "a"
        raise OSError("gone")

    entries = parse_lines(source(), format="raw")

    assert next(entries).message == "a"
    with pytest.raises(OSError, match="gone"):
        next(entries)
