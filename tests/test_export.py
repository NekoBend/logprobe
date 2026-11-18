"""Tests for ``export_logs``.

Every format writes UTF-8 with no newline translation, through a temporary file
in the destination directory, so a failed export leaves the destination as it
was.
"""

from __future__ import annotations

import csv
import dataclasses
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, cast

import pytest

import logprobe
from logprobe import LogEntry, export_logs, read_file

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from pathlib import Path


ExportFormat = Literal["json", "jsonl", "csv", "text"]
FORMATS: tuple[ExportFormat, ...] = ("json", "jsonl", "csv", "text")

# Lines of the live wire format as a live stream's entries hold them.
WIRE_A = "2026-11-04 05:11:16.661446 +0000 10065  1234  1234 I Tag: first"
WIRE_B = (
    "2026-11-04 05:11:17.000001 +0000  1000   669   770 E Other: é日本 \rstill one line"
)


# The fields every entry needs, for a subclass's constructor.
_FIELDS: dict[str, Any] = {
    "logged_at": datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
    "pid": 1,
    "tid": 2,
    "level": "I",
    "tag": "T",
    "message": "m",
    "raw": "m",
}


def _with_raw(raw: str) -> dict[str, Any]:
    return {**_FIELDS, "raw": raw}


def _entry(message: str = "m", **fields: Any) -> LogEntry:  # noqa: ANN401
    values: dict[str, Any] = {**_FIELDS, "message": message, "raw": message, **fields}
    return LogEntry(**values)


def _records(path: Path, fmt: ExportFormat) -> list[str]:
    """The messages of the entries in an export (``raw`` for ``text``)."""
    data = path.read_bytes().decode()
    if fmt == "json":
        return [record["message"] for record in json.loads(data)]
    if fmt == "jsonl":
        return [json.loads(line)["message"] for line in data.splitlines()]
    if fmt == "csv":
        return [row["message"] for row in _csv_rows(path)]
    return data.splitlines()


def _csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))


def _then_raise(items: Iterable[LogEntry], error: BaseException) -> Iterator[LogEntry]:
    yield from items
    raise error


@pytest.fixture
def sample_entries() -> list[LogEntry]:
    """Create a list of sample LogEntry objects."""
    return [
        LogEntry(
            logged_at=datetime(2023, 1, 1, 12, 0, 0, tzinfo=UTC).replace(tzinfo=None),
            pid=1001,
            tid=2001,
            level="D",
            tag="TestTag",
            message="Debug message",
            raw="raw log line 1",
        ),
        LogEntry(
            logged_at=datetime(2023, 1, 1, 12, 0, 1, tzinfo=UTC).replace(tzinfo=None),
            pid=1002,
            tid=2002,
            level="E",
            tag="ErrorTag",
            message="Error message",
            raw="raw log line 2",
        ),
    ]


# -- json --------------------------------------------------------------------------


def test_json_exporter(tmp_path: Path, sample_entries: list[LogEntry]) -> None:
    """Test exporting logs to JSON."""
    output_file = tmp_path / "logs.json"
    export_logs(sample_entries, output_file, format="json", indent=2)

    assert output_file.exists()

    with output_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    assert isinstance(data, list)
    assert len(data) == 2

    entry1 = data[0]
    assert entry1["pid"] == 1001
    assert entry1["tag"] == "TestTag"
    assert entry1["level"] == "D"
    assert entry1["schema"] == "logprobe.entry/1"
    assert "raw" not in entry1
    # logged_at is ISO 8601; the sample's datetime is naive, so no offset.
    assert entry1["logged_at"] == "2023-01-01T12:00:00"


def test_json_exporter_compact_without_indent(
    tmp_path: Path, sample_entries: list[LogEntry]
) -> None:
    """Test JSON exporter writes compact JSON when indent is None."""
    output_file = tmp_path / "logs_compact.json"
    export_logs(sample_entries, output_file, format="json", indent=None)

    content = output_file.read_text(encoding="utf-8")
    data = json.loads(content)

    assert isinstance(data, list)
    assert len(data) == 2
    assert "\n" not in content
    assert '": ' not in content


def test_json_exporter_default_is_compact_for_cost_control(
    tmp_path: Path, sample_entries: list[LogEntry]
) -> None:
    """Default JSON export should be compact to minimize output size."""
    output_file = tmp_path / "logs_default.json"

    export_logs(sample_entries, output_file, format="json")

    content = output_file.read_text(encoding="utf-8")
    data = json.loads(content)

    assert isinstance(data, list)
    assert len(data) == 2
    assert "\n" not in content
    assert '": ' not in content


@pytest.mark.parametrize("indent", [0, 1, 2, 4])
@pytest.mark.parametrize("count", [0, 1, 2])
def test_export_logs_indent(tmp_path: Path, indent: int, count: int) -> None:
    """``indent=`` gives what ``json.dumps(the array, indent=)`` gives,
    though the array is written one entry at a time."""
    dest = tmp_path / "out.json"

    assert (
        export_logs(
            [_entry(f"m{i}é") for i in range(count)],
            dest,
            format="json",
            indent=indent,
        )
        == count
    )

    data = dest.read_bytes().decode()
    assert data == json.dumps(json.loads(data), indent=indent, ensure_ascii=False)
    assert "\r" not in data


@pytest.mark.parametrize("fmt", ["jsonl", "csv", "text"])
def test_indent_is_refused_where_it_means_nothing(
    tmp_path: Path, fmt: ExportFormat
) -> None:
    """A JSON Lines record is one line, and csv and text have no structure to
    indent: ``indent=`` there is a ValueError, before the input is read."""
    dest = tmp_path / "out"
    dest.write_bytes(b"previous")
    read: list[LogEntry] = []

    def items() -> Iterator[LogEntry]:
        read.append(_entry())
        yield _entry()

    with pytest.raises(ValueError, match="indent= applies to format='json' only"):
        export_logs(items(), dest, format=fmt, indent=2)

    assert read == []
    assert dest.read_bytes() == b"previous"
    assert [path.name for path in tmp_path.iterdir()] == ["out"]


@pytest.mark.parametrize(
    ("indent", "error"),
    [
        (True, TypeError),
        ("  ", TypeError),
        (1.5, TypeError),
        (-1, ValueError),
    ],
    ids=["bool", "str", "float", "negative"],
)
def test_indent_takes_a_non_negative_int(
    tmp_path: Path, indent: object, error: type[Exception]
) -> None:
    """``indent`` is an int of at least 0, or None."""
    dest = tmp_path / "out.json"

    with pytest.raises(error, match="indent"):
        export_logs([_entry()], dest, format="json", indent=cast("Any", indent))

    assert not dest.exists()


def test_export_writes_non_ascii_as_is(tmp_path: Path) -> None:
    """Non-ASCII text is written as UTF-8, not escaped, whatever the locale."""
    dest = tmp_path / "out.json"

    export_logs([_entry("テスト")], dest, format="json")

    assert "テスト" in dest.read_bytes().decode("utf-8")


def test_lone_surrogate_in_text_is_its_escape(tmp_path: Path) -> None:
    dest = tmp_path / "out.log"

    export_logs([LogEntry(**_with_raw("a\ud800"))], dest, format="text")

    assert dest.read_bytes() == b"a\\ud800\n"


@pytest.mark.parametrize("fmt", ["json", "jsonl", "csv"])
def test_lone_surrogate_is_written_as_an_escape(
    tmp_path: Path, fmt: ExportFormat
) -> None:
    dest = tmp_path / "out"

    export_logs([_entry("a\ud800")], dest, format=fmt)

    text = dest.read_bytes().decode("utf-8")
    if fmt == "csv":
        row = next(csv.DictReader(text.splitlines(keepends=True)))
        assert (row["message"], row["raw"]) == ("a\\ud800", "a\\ud800")
    else:
        loaded = json.loads(text)
        record = loaded[0] if fmt == "json" else loaded
        assert record["message"] == "a\ud800"


# -- format selection ------------------------------------------------------------


def test_default_format_is_jsonl(
    tmp_path: Path, sample_entries: list[LogEntry]
) -> None:
    dest = tmp_path / "out"

    assert export_logs(sample_entries, dest) == 2

    lines = dest.read_text(encoding="utf-8").split("\n")
    assert lines[2] == ""
    assert [json.loads(line) for line in lines[:2]] == [
        entry.to_dict() for entry in sample_entries
    ]


@pytest.mark.parametrize("fmt", ["json", "jsonl"])
def test_json_forms_hold_to_dict(
    tmp_path: Path, sample_entries: list[LogEntry], fmt: ExportFormat
) -> None:
    """Optional fields are omitted and raw is absent, as in ``to_dict()``."""
    dest = tmp_path / "out"
    entries = [*sample_entries, _entry("é", uid=1, uid_raw="u0_a1", package="p")]

    export_logs(entries, dest, format=fmt)

    text = dest.read_text(encoding="utf-8")
    records = (
        json.loads(text)
        if fmt == "json"
        else list(map(json.loads, text.split("\n")[:-1]))
    )
    assert records == [entry.to_dict() for entry in entries]
    assert "raw" not in records[0]
    assert "uid" not in records[0]
    assert records[2]["uid"] == 1


def test_csv_columns_are_the_entry_fields_in_order(tmp_path: Path) -> None:
    dest = tmp_path / "out.csv"
    entry = _entry("m", uid=7, uid_raw="7", serial="s", package="p", truncated=True)

    export_logs([entry], dest, format="csv")

    (row,) = _csv_rows(dest)
    assert list(row) == [field.name for field in dataclasses.fields(LogEntry)]
    assert row["raw"] == "m"
    assert (row["uid"], row["uid_raw"], row["serial"], row["package"]) == (
        "7",
        "7",
        "s",
        "p",
    )
    assert (row["parsed"], row["truncated"]) == ("True", "True")


@pytest.mark.parametrize("fmt", ["JSON", "xml", "", "ndjson"])
def test_unknown_format_is_refused(tmp_path: Path, fmt: str) -> None:
    dest = tmp_path / "out"

    with pytest.raises(ValueError, match="Unsupported export format"):
        export_logs([_entry()], dest, format=cast("Any", fmt))

    assert not dest.exists()


# -- jsonl -------------------------------------------------------------------------


def test_jsonl_is_one_compact_object_per_line(tmp_path: Path) -> None:
    """One JSON object per LF-terminated line, also for a message with line
    breaks; the file ends with a newline."""
    dest = tmp_path / "out.jsonl"
    messages = ["plain", "two\nlines", "carriage\rreturn", "para\u2028graph"]

    assert export_logs([_entry(m) for m in messages], dest, format="jsonl") == 4

    data = dest.read_bytes()
    assert data.endswith(b"\n")
    assert b"\r" not in data
    lines = data.decode().split("\n")[:-1]
    assert [json.loads(line)["message"] for line in lines] == messages
    assert all(": " not in line.split('"message"')[0] for line in lines)


def test_jsonl_escapes_what_line_readers_stop_at(tmp_path: Path) -> None:
    """U+0085, U+2028 and U+2029 are line ends to ``str.splitlines`` and Node's
    readline: one record stays one line for them, and reads back unchanged."""
    dest = tmp_path / "out.jsonl"
    messages = ["a\u2028b", "c\u2029d", "e\x85f", "g"]
    tag = "key\u2028\x85"

    export_logs([_entry(m, tag=tag) for m in messages], dest, format="jsonl")

    lines = dest.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines]
    assert [record["message"] for record in records] == messages
    assert all(record["tag"] == tag for record in records)
    assert "\\u2028" in lines[0]


@pytest.mark.parametrize(
    ("fmt", "indent"), [("json", None), ("json", 2), ("jsonl", None)]
)
def test_json_exports_escape_the_unsafe_characters(
    tmp_path: Path, fmt: ExportFormat, indent: int | None
) -> None:
    """C1 controls, U+2028/2029 and the bidi controls are escapes in both JSON
    formats, with or without indentation; the values read back unchanged."""
    unsafe = "\x80\x85\x9f\u061c\u200e\u200f\u2028\u2029\u202a\u202e\u2066\u2069"
    messages = [f"a{unsafe}b", "plain caf\u00e9"]
    dest = tmp_path / "out"

    export_logs(
        [_entry(m, tag=unsafe) for m in messages], dest, format=fmt, indent=indent
    )

    text = dest.read_text(encoding="utf-8")
    assert not set(unsafe) & set(text)
    assert "caf\u00e9" in text
    assert _records(dest, fmt) == messages


# -- text --------------------------------------------------------------------------


def test_text_writes_raw_lines_with_lf(tmp_path: Path) -> None:
    """``text`` writes each ``raw`` and one LF, on every platform."""
    dest = tmp_path / "out.txt"
    entries = [_entry("a", raw=WIRE_A), _entry("b", raw=WIRE_B)]

    assert export_logs(entries, dest, format="text") == 2

    assert dest.read_bytes() == f"{WIRE_A}\n{WIRE_B}\n".encode()


def test_text_is_readable_by_read_file(tmp_path: Path) -> None:
    """The save-on-failure format reads back as the same lines; a
    bare CR stays inside its line."""
    dest = tmp_path / "out.txt"
    entries = [_entry("a", raw=WIRE_A), _entry("b", raw=WIRE_B)]

    export_logs(entries, dest, format="text")

    read = list(read_file(dest))
    assert [entry.raw for entry in read] == [WIRE_A, WIRE_B]
    assert [entry.tag for entry in read] == ["Tag", "Other"]
    assert [entry.parsed for entry in read] == [True, True]
    assert read[1].message == "é日本 \rstill one line"


def test_text_can_replace_the_file_it_reads(tmp_path: Path) -> None:
    """``read_file`` holds its source open until the last entry, and the replace
    comes after that, so a file can be rewritten from itself, also on Windows."""
    source = tmp_path / "app.log"
    source.write_bytes(f"{WIRE_A}\n{WIRE_B}\n".encode())

    def first_tag_only() -> Iterator[LogEntry]:
        for entry in read_file(source):
            if entry.tag == "Tag":
                yield entry

    assert export_logs(first_tag_only(), source, format="text") == 1

    assert source.read_bytes() == f"{WIRE_A}\n".encode()


# -- csv ---------------------------------------------------------------------------


def test_csv_exporter(tmp_path: Path, sample_entries: list[LogEntry]) -> None:
    """Test exporting logs to CSV."""
    output_file = tmp_path / "logs.csv"
    export_logs(sample_entries, output_file, format="csv")

    assert output_file.exists()

    with output_file.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 2

    row1 = rows[0]
    assert row1["pid"] == "1001"
    assert row1["tag"] == "TestTag"
    assert row1["level"] == "D"
    assert row1["raw"] == "raw log line 1"
    assert row1["uid"] == ""
    assert row1["parsed"] == "True"
    assert row1["logged_at"] == "2023-01-01T12:00:00"


def test_csv_exporter_sanitizes_formula_injection(tmp_path: Path) -> None:
    """CSV export prefixes a quote to values that start with a formula char."""
    output_file = tmp_path / "logs_injection.csv"
    entries = [
        LogEntry(
            logged_at=datetime(2023, 1, 1, 12, 0, 0, tzinfo=UTC).replace(tzinfo=None),
            pid=1001,
            tid=2001,
            level="W",
            tag="@evil",
            message="=cmd|calc!A1",
            raw="raw log line",
        )
    ]

    export_logs(entries, output_file, format="csv")

    with output_file.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 1
    row = rows[0]
    assert row["message"] == "'=cmd|calc!A1"
    assert row["tag"] == "'@evil"


def test_csv_exporter_sanitizes_whitespace_led_formula(tmp_path: Path) -> None:
    """A formula char behind leading whitespace is still neutralized.

    Spreadsheets trim leading whitespace before evaluating a cell, so " =cmd"
    and "\t=cmd" are as dangerous as "=cmd" and must also be quoted.
    """
    output_file = tmp_path / "logs_ws_injection.csv"
    entries = [
        LogEntry(
            logged_at=datetime(2023, 1, 1, 12, 0, 0, tzinfo=UTC).replace(tzinfo=None),
            pid=1001,
            tid=2001,
            level="W",
            tag="\t@evil",
            message=" =cmd|calc!A1",
            raw="raw log line",
        )
    ]

    export_logs(entries, output_file, format="csv")

    with output_file.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 1
    row = rows[0]
    assert row["message"] == "' =cmd|calc!A1"
    assert row["tag"] == "'\t@evil"


@pytest.mark.parametrize("lead", ["=", "+", "-", "@", " =", " +", "\t-", " @"])
def test_csv_quotes_every_formula_lead(tmp_path: Path, lead: str) -> None:
    """Each character a spreadsheet takes for a formula, also behind whitespace."""
    dest = tmp_path / "out.csv"
    value = f"{lead}1+1"

    export_logs([_entry(value)], dest, format="csv")

    (row,) = _csv_rows(dest)
    assert row["message"] == f"'{value}"


@pytest.mark.parametrize("count", [0, 1, 2])
def test_csv_lines_end_in_crlf(tmp_path: Path, count: int) -> None:
    """The header and each row end in CRLF and nothing else, on every platform."""
    dest = tmp_path / "out.csv"

    export_logs([_entry(f"m{i}") for i in range(count)], dest, format="csv")

    data = dest.read_bytes()
    assert data.count(b"\r\n") == count + 1
    assert data.count(b"\n") == count + 1
    assert data.count(b"\r") == count + 1


def test_csv_without_entries_has_the_base_header(tmp_path: Path) -> None:
    """No entries: the header is there, the columns are the `LogEntry` fields."""
    dest = tmp_path / "out.csv"

    assert export_logs([], dest, format="csv") == 0

    with dest.open(encoding="utf-8", newline="") as file:
        assert list(csv.reader(file)) == [
            [field.name for field in dataclasses.fields(LogEntry)]
        ]


# -- every format ------------------------------------------------------------------


def test_export_logs_json(tmp_path: Path, sample_entries: list[LogEntry]) -> None:
    """Test the export_logs helper function with JSON format."""
    output_file = tmp_path / "helper_logs.json"
    export_logs(sample_entries, output_file, format="json")

    assert output_file.exists()
    with output_file.open("r") as f:
        data = json.load(f)
    assert len(data) == 2


def test_export_logs_csv(tmp_path: Path, sample_entries: list[LogEntry]) -> None:
    """Test the export_logs helper function with CSV format."""
    output_file = tmp_path / "helper_logs.csv"
    export_logs(sample_entries, output_file, format="csv")

    assert output_file.exists()
    with output_file.open("r") as f:
        reader = csv.reader(f)
        # Header + 2 rows
        assert len(list(reader)) == 3


def test_export_logs_invalid_format(
    tmp_path: Path, sample_entries: list[LogEntry]
) -> None:
    """Test that export_logs raises ValueError for invalid format."""
    output_file = tmp_path / "invalid.txt"
    with pytest.raises(ValueError, match="Unsupported export format"):
        export_logs(sample_entries, output_file, format="xml")  # type: ignore
    assert not output_file.exists()


@pytest.mark.parametrize(
    "options",
    [
        pytest.param({"format": "xml"}, id="format"),
        pytest.param({"indent": -1}, id="negative"),
        pytest.param({"format": "csv", "indent": 1}, id="csv-indent"),
    ],
)
def test_bad_options_come_before_the_file_system(
    tmp_path: Path, options: dict[str, Any]
) -> None:
    """Refused before any file is looked at or created: the missing
    directory, an OSError otherwise, does not show."""
    with pytest.raises(ValueError, match=r"format|indent"):
        export_logs([], tmp_path / "missing" / "out", **options)


@pytest.mark.parametrize("fmt", FORMATS)
def test_returns_the_entries_written(tmp_path: Path, fmt: ExportFormat) -> None:
    """The count is of entries, and they are written in order."""
    dest = tmp_path / "out"

    written = export_logs([_entry("a"), _entry("b"), _entry("c")], dest, format=fmt)

    assert written == 3
    assert _records(dest, fmt) == ["a", "b", "c"]


@pytest.mark.parametrize("fmt", FORMATS)
def test_no_entries_write_an_empty_export(tmp_path: Path, fmt: ExportFormat) -> None:
    """An empty input replaces the destination like any other: zero entries."""
    dest = tmp_path / "out"
    dest.write_bytes(b"previous")

    assert export_logs([], dest, format=fmt) == 0

    assert _records(dest, fmt) == []


@pytest.mark.parametrize("fmt", FORMATS)
def test_input_is_read_lazily(tmp_path: Path, fmt: ExportFormat) -> None:
    """The input is consumed as it is written: at most one entry is in hand, so
    a long capture does not have to fit in memory."""
    dest = tmp_path / "out"
    alive: list[int] = []

    class Tracked(LogEntry):
        def __del__(self) -> None:
            alive.append(-1)

    def items() -> Iterator[LogEntry]:
        for i in range(50):
            alive.append(1)
            yield Tracked(
                logged_at=datetime(2026, 1, 2, tzinfo=UTC),
                pid=i,
                tid=i,
                level="I",
                tag="T",
                message="m",
                raw="r",
            )
            assert sum(alive) <= 2

    assert export_logs(items(), dest, format=fmt) == 50


@pytest.mark.parametrize(
    "items",
    [
        pytest.param([{"message": "m"}], id="dict"),
        pytest.param("not entries", id="str"),
        pytest.param(_entry(), id="one-entry"),
        pytest.param([None], id="none"),
    ],
)
@pytest.mark.parametrize("fmt", FORMATS)
def test_an_item_of_another_type_raises_type_error(
    tmp_path: Path, fmt: ExportFormat, items: object
) -> None:
    """Only entries are items; the destination stays as it was."""
    dest = tmp_path / "out"
    dest.write_bytes(b"previous")

    with pytest.raises(TypeError, match="LogEntry"):
        export_logs(cast("Any", items), dest, format=fmt)

    assert dest.read_bytes() == b"previous"
    assert [path.name for path in tmp_path.iterdir()] == ["out"]


def test_destination_takes_str_and_path_like(tmp_path: Path) -> None:
    """A str or any ``os.PathLike[str]`` names the destination."""

    class Pathish:
        def __fspath__(self) -> str:
            return str(tmp_path / "like.txt")

    export_logs([_entry()], str(tmp_path / "plain.txt"), format="text")
    export_logs([_entry()], Pathish(), format="text")

    assert (tmp_path / "plain.txt").read_bytes() == b"m\n"
    assert (tmp_path / "like.txt").read_bytes() == b"m\n"


def test_format_and_indent_are_keyword_only(tmp_path: Path) -> None:
    """``export_logs(items, destination, *, format=, indent=)``."""
    with pytest.raises(TypeError, match="positional"):
        export_logs([_entry()], tmp_path / "out", "json")  # type: ignore


# -- atomic writes ------------------------------------------


@pytest.mark.parametrize("fmt", FORMATS)
@pytest.mark.parametrize(
    "error",
    [ValueError("input"), KeyboardInterrupt()],
    ids=["exception", "interrupt"],
)
@pytest.mark.parametrize("before", [0, 2], ids=["at-once", "midway"])
def test_failed_input_leaves_nothing_behind(
    tmp_path: Path, fmt: ExportFormat, error: BaseException, before: int
) -> None:
    """The input raising, an interrupt included, removes the temporary file and
    propagates as it is; a destination that did not exist still does not."""
    dest = tmp_path / "out"

    with pytest.raises(type(error)) as info:
        export_logs(_then_raise([_entry()] * before, error), dest, format=fmt)

    assert info.value is error
    assert list(tmp_path.iterdir()) == []


def test_temporary_file_name(tmp_path: Path) -> None:
    """``.logprobe-<16 hex>.tmp``, whatever the destination is called."""
    seen: list[str] = []

    def items() -> Iterator[LogEntry]:
        seen.extend(path.name for path in tmp_path.iterdir())
        yield _entry()

    export_logs(items(), tmp_path / "out.txt", format="text")

    (name,) = seen
    assert re.fullmatch(r"\.logprobe-[0-9a-f]{16}\.tmp", name)


def test_temporary_file_is_never_another_exports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Opened with "x": a name in use raises, and that file is neither written to
    nor removed, since another export may be writing it."""
    monkeypatch.setattr(os, "urandom", lambda nbytes: b"\0" * nbytes)
    other = tmp_path / ".logprobe-0000000000000000.tmp"
    other.write_bytes(b"another export's")
    dest = tmp_path / "out.txt"
    read: list[LogEntry] = []

    def items() -> Iterator[LogEntry]:
        read.append(_entry())
        yield _entry()

    with pytest.raises(FileExistsError):
        export_logs(items(), dest, format="text")

    assert read == []
    assert other.read_bytes() == b"another export's"
    assert not dest.exists()


def test_interrupt_right_after_the_creation_leaves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file exists and nothing holds it yet: an interrupt here removes it too."""
    dest = tmp_path / "out.txt"
    dest.write_bytes(b"previous")
    real = os.open

    def interrupted(path: str, flags: int, mode: int = 0o777) -> int:
        os.close(real(path, flags, mode))
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "open", interrupted)

    with pytest.raises(KeyboardInterrupt):
        export_logs([_entry()], dest, format="text")

    monkeypatch.undo()
    assert dest.read_bytes() == b"previous"
    assert [path.name for path in tmp_path.iterdir()] == ["out.txt"]


def test_interrupt_right_after_the_replace_keeps_the_new_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one moment an error and a finished export come together: nothing can
    undo the replace, so the new file stays and nothing else does."""
    dest = tmp_path / "out.txt"
    dest.write_bytes(b"previous")
    real = os.replace

    def interrupted(source: str, destination: str) -> None:
        real(source, destination)
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "replace", interrupted)

    with pytest.raises(KeyboardInterrupt):
        export_logs([_entry()], dest, format="text")

    assert dest.read_bytes() == b"m\n"
    assert [path.name for path in tmp_path.iterdir()] == ["out.txt"]


# Real signals at random moments of one-entry exports. In a process of its own: its
# handler raises wherever the timer lands, which pytest and the garbage of other
# tests should not have to take.
_INTERRUPTS = """
import json, os, random, signal, sys, time
from datetime import UTC, datetime
from pathlib import Path

from logprobe import LogEntry, export_logs


class Interrupted(BaseException):
    pass


armed = False


def handler(signum, frame):
    # A signal that is delivered late (the handler runs at a later bytecode
    # boundary than the timer fired) must not escape the guarded region.
    if armed:
        raise Interrupted


directory = Path(sys.argv[1])
dest = directory / "out.txt"
entry = LogEntry(
    logged_at=datetime(2026, 1, 2, tzinfo=UTC),
    pid=1, tid=2, level="I", tag="T", message="new", raw="new",
)
signal.signal(signal.SIGALRM, handler)
rng = random.Random(0)
descriptors = len(os.listdir("/proc/self/fd")) if sys.platform == "linux" else 0
interrupts = 0
torn = 0
end = time.monotonic() + 0.5
while time.monotonic() < end:
    dest.write_bytes(b"old")
    try:
        try:
            armed = True
            signal.setitimer(signal.ITIMER_REAL, rng.uniform(1e-5, 2.5e-4))
            export_logs([entry], dest, format="text")
        finally:
            armed = False
            signal.setitimer(signal.ITIMER_REAL, 0)
    except Interrupted:
        interrupts += 1
    if dest.read_bytes() not in (b"old", b"new\\n"):
        torn += 1
print(json.dumps({
    "interrupts": interrupts,
    "torn": torn,
    "descriptors": (
        len(os.listdir("/proc/self/fd")) - descriptors
        if sys.platform == "linux" else 0
    ),
    "left": sorted(path.name for path in directory.iterdir() if path != dest),
}))
"""


@pytest.mark.skipif(sys.platform == "win32", reason="setitimer is POSIX")
def test_interrupts_at_any_moment_leave_nothing(tmp_path: Path) -> None:
    """Real signals find what a patched call cannot, such as the moment right after
    the ``open`` that creates the file. Wherever they land, no temporary file or
    descriptor stays behind and the destination is whole."""
    root = pathlib.Path(logprobe.__file__).parent.parent
    done = subprocess.run(
        [sys.executable, "-c", _INTERRUPTS, str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        env={**os.environ, "PYTHONPATH": str(root)},
    )

    assert done.returncode == 0, f"child failed ({done.returncode}):\n{done.stderr}"
    report = json.loads(done.stdout)
    assert report["interrupts"] > 0
    assert report["left"] == []
    assert report["descriptors"] == 0
    assert report["torn"] == 0


def test_replace_comes_from_a_closed_file_in_the_destination_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The temporary file sits beside the destination, so ``os.replace`` stays
    on one file system, and it is complete and closed when replaced (Windows
    refuses to replace with an open file)."""
    target = tmp_path / "dir"
    target.mkdir()
    dest = target / "out.txt"
    seen: list[tuple[str, bytes]] = []
    real = os.replace

    def replace(source: str, destination: str) -> None:
        path = target / os.path.basename(source)  # noqa: PTH119
        seen.append((str(path.parent), path.read_bytes()))
        assert os.fspath(destination) == os.fspath(dest.resolve())
        if sys.platform == "linux":
            held = [
                os.readlink(f"/proc/self/fd/{fd}")  # noqa: PTH115
                for fd in os.listdir("/proc/self/fd")  # noqa: PTH208
                if os.path.exists(f"/proc/self/fd/{fd}")  # noqa: PTH110
            ]
            assert str(path) not in held
        real(source, destination)

    monkeypatch.setattr(os, "replace", replace)

    export_logs([_entry("a"), _entry("b")], dest, format="text")

    assert seen == [(str(target), b"a\nb\n")]
    assert [path.name for path in target.iterdir()] == ["out.txt"]


def test_failed_replace_keeps_the_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``os.replace`` refused (on Windows, a destination another process holds
    open): the OSError comes through, the temporary file is removed and the
    destination is untouched."""
    dest = tmp_path / "out.txt"
    dest.write_bytes(b"previous")

    def replace(source: str, destination: str) -> None:
        del source, destination
        raise PermissionError(13, "the destination is held open")

    monkeypatch.setattr(os, "replace", replace)

    with pytest.raises(PermissionError, match="held open"):
        export_logs([_entry()], dest, format="text")

    assert dest.read_bytes() == b"previous"
    assert [path.name for path in tmp_path.iterdir()] == ["out.txt"]


def test_destination_held_open(tmp_path: Path) -> None:
    """A destination someone holds open: Windows refuses the replace with an
    OSError and nothing changes; POSIX replaces it, and the holder
    keeps reading the old file."""
    dest = tmp_path / "out.txt"
    dest.write_bytes(b"previous")

    with dest.open("rb") as held:
        if sys.platform == "win32":
            with pytest.raises(OSError, match=r"\S"):
                export_logs([_entry()], dest, format="text")
        else:
            export_logs([_entry()], dest, format="text")
        assert held.read() == b"previous"

    expected = b"previous" if sys.platform == "win32" else b"m\n"
    assert dest.read_bytes() == expected
    assert [path.name for path in tmp_path.iterdir()] == ["out.txt"]


def test_failed_cleanup_does_not_hide_the_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A scanner holding the temporary file on Windows must not replace the
    export's own error with its PermissionError."""
    dest = tmp_path / "out.txt"
    error = ValueError("input")
    real = os.unlink

    def unlink(path: str, *, dir_fd: int | None = None) -> None:
        del dir_fd
        real(path)
        raise PermissionError(13, "held by a scanner", path)

    monkeypatch.setattr(os, "unlink", unlink)

    with pytest.raises(ValueError, match="input") as info:
        export_logs(_then_raise([_entry()], error), dest, format="text")

    assert info.value is error


def test_refused_cleanup_leaves_the_temporary_file_and_the_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Removal is best effort: when ``unlink`` is refused the temporary file
    stays, the destination is untouched, and the export's error is raised."""
    dest = tmp_path / "out.txt"
    dest.write_bytes(b"previous")
    error = ValueError("input")

    def unlink(path: str, *, dir_fd: int | None = None) -> None:
        del dir_fd
        raise PermissionError(13, "refused", path)

    monkeypatch.setattr(os, "unlink", unlink)

    with pytest.raises(ValueError, match="input") as info:
        export_logs(_then_raise([_entry()], error), dest, format="text")

    assert info.value is error
    assert dest.read_bytes() == b"previous"
    left = [p.name for p in tmp_path.iterdir() if p.name != "out.txt"]
    assert len(left) == 1
    assert left[0].startswith(".logprobe-")
    assert left[0].endswith(".tmp")


def test_directory_destination_raises_before_the_input_is_read(
    tmp_path: Path,
) -> None:
    """A directory cannot be replaced by a file: OSError, the input unread."""
    dest = tmp_path / "out"
    dest.mkdir()
    read: list[LogEntry] = []

    def items() -> Iterator[LogEntry]:
        read.append(_entry())
        yield _entry()

    with pytest.raises(OSError, match="out"):
        export_logs(items(), dest, format="text")

    assert read == []
    assert dest.is_dir()
    assert list(dest.iterdir()) == []


def test_missing_directory_raises_os_error(tmp_path: Path) -> None:
    """The destination's directory is not created; the input stays unread."""
    read: list[LogEntry] = []

    def items() -> Iterator[LogEntry]:
        read.append(_entry())
        yield _entry()

    with pytest.raises(OSError, match="missing"):
        export_logs(items(), tmp_path / "missing" / "out.txt", format="text")

    assert read == []
    assert list(tmp_path.iterdir()) == []


def test_symlink_destination_is_written_through(tmp_path: Path) -> None:
    """A link keeps pointing where it did, and the file it names is replaced
    atomically in that file's own directory."""
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    real = real_dir / "file.txt"
    real.write_bytes(b"previous")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(real)
    except OSError as exc:  # Windows without the symlink privilege
        pytest.skip(f"no symlinks here: {exc}")

    export_logs([_entry()], link, format="text")

    assert link.is_symlink()
    assert real.read_bytes() == b"m\n"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["link.txt", "real"]
    assert [path.name for path in real_dir.iterdir()] == ["file.txt"]


def test_symlink_loop_destination_raises_os_error(tmp_path: Path) -> None:
    """A link that names itself is an OSError on every Python (``Path.resolve()``
    is a RuntimeError on 3.12), before the input is read or anything is created."""
    loop = tmp_path / "loop"
    try:
        loop.symlink_to(loop)
    except OSError as exc:  # Windows without the symlink privilege
        pytest.skip(f"no symlinks here: {exc}")
    read: list[LogEntry] = []

    def items() -> Iterator[LogEntry]:
        read.append(_entry())
        yield _entry()

    with pytest.raises(OSError, match="loop"):
        export_logs(items(), loop, format="text")

    assert read == []
    assert [path.name for path in tmp_path.iterdir()] == ["loop"]


def test_read_only_destination_is_refused(tmp_path: Path) -> None:
    """A read-only file stays one: PermissionError before the input is read, on
    every platform, though POSIX lets a replace pass the file's own mode (Windows would
    refuse the replace)."""
    dest = tmp_path / "out.txt"
    dest.write_bytes(b"previous")
    dest.chmod(stat.S_IREAD)
    if os.access(dest, os.W_OK):
        pytest.skip("this user (root) writes to read-only files")
    read: list[LogEntry] = []

    def items() -> Iterator[LogEntry]:
        read.append(_entry())
        yield _entry()

    try:
        with pytest.raises(PermissionError, match=r"out\.txt"):
            export_logs(items(), dest, format="text")
        assert read == []
        assert dest.read_bytes() == b"previous"
        assert [path.name for path in tmp_path.iterdir()] == ["out.txt"]
    finally:
        dest.chmod(stat.S_IREAD | stat.S_IWRITE)  # Windows cannot remove it otherwise


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_replacing_keeps_the_destination_mode(tmp_path: Path) -> None:
    """A replaced file keeps the mode it had."""
    dest = tmp_path / "out.txt"
    dest.write_bytes(b"previous")
    dest.chmod(0o640)

    export_logs([_entry()], dest, format="text")

    assert stat.S_IMODE(dest.stat().st_mode) == 0o640


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
@pytest.mark.parametrize(
    ("mode", "during"),
    [(0o600, 0o600), (0o640, 0o640), (0o664, 0o644)],
    ids=["private", "group", "wider-than-umask"],
)
def test_temporary_file_is_no_wider_than_the_file_it_replaces(
    tmp_path: Path, mode: int, during: int
) -> None:
    """During the whole write, so a private file's new content stays private. The
    umask narrows what is created; the final mode is still the destination's."""
    dest = tmp_path / "out.log"
    dest.write_bytes(b"previous")
    dest.chmod(mode)
    seen: list[int] = []

    def items() -> Iterator[LogEntry]:
        (temporary,) = (path for path in tmp_path.iterdir() if path != dest)
        seen.append(stat.S_IMODE(temporary.stat().st_mode))
        yield _entry()

    previous = os.umask(0o022)
    try:
        export_logs(items(), dest, format="text")
    finally:
        os.umask(previous)

    assert seen == [during]
    assert dest.read_bytes() == b"m\n"
    assert stat.S_IMODE(dest.stat().st_mode) == mode


def test_file_system_without_chmod_does_not_cost_the_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keeping the mode is best effort: a file system that refuses it (a network
    share, FAT) still gets the new content, and nothing is left behind."""
    dest = tmp_path / "out.txt"
    dest.write_bytes(b"previous")

    def refuse(self: pathlib.Path, mode: int, **options: object) -> None:
        del self, mode, options
        raise PermissionError(1, "no chmod here")

    monkeypatch.setattr(pathlib.Path, "chmod", refuse)

    export_logs([_entry()], dest, format="text")

    assert dest.read_bytes() == b"m\n"
    assert [path.name for path in tmp_path.iterdir()] == ["out.txt"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_new_file_gets_the_umask_mode(tmp_path: Path) -> None:
    """A new file has the mode any ``open()`` would give it, not a private
    temporary file's 0600: a CI artifact stays readable."""
    dest = tmp_path / "out.txt"
    previous = os.umask(0o027)
    try:
        export_logs([_entry()], dest, format="text")
    finally:
        os.umask(previous)

    assert stat.S_IMODE(dest.stat().st_mode) == 0o640


def test_special_file_destination_is_refused(tmp_path: Path) -> None:
    """A FIFO, like a device node, cannot be replaced by a regular file without
    losing what it is: OSError, and it stays."""
    if sys.platform == "win32":
        pytest.skip("POSIX special files")
    dest = tmp_path / "fifo"
    os.mkfifo(dest)

    with pytest.raises(OSError, match="regular file"):
        export_logs([_entry()], dest, format="text")

    assert stat.S_ISFIFO(dest.lstat().st_mode)
    assert [path.name for path in tmp_path.iterdir()] == ["fifo"]


@pytest.mark.skipif(sys.platform == "win32", reason="MAX_PATH, not the name limit")
def test_longest_file_name_still_works(tmp_path: Path) -> None:
    """The temporary file's name does not grow with the destination's, so a
    name at the file system's limit works (a long parametrized test id)."""
    dest = tmp_path / ("x" * 255)

    export_logs([_entry()], dest, format="text")

    assert dest.read_bytes() == b"m\n"
    assert [path.name for path in tmp_path.iterdir()] == [dest.name]
