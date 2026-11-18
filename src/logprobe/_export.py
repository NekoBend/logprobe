"""Write log entries to a file: `export_logs`."""

from __future__ import annotations

import contextlib
import csv
import dataclasses
import errno
import functools
import json
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from ._entry import LogEntry, escape_unsafe

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from os import PathLike
    from typing import TextIO

__all__ = ["export_logs"]

_FORMATS = ("json", "jsonl", "csv", "text")

# The columns of the CSV export: every field of the entry, in declaration order
# (raw included, unlike the JSON forms).
_CSV_COLUMNS = tuple(field.name for field in dataclasses.fields(LogEntry))

# Characters that trigger formula evaluation in Excel/Sheets when they lead a
# cell value. Log content is attacker-controllable, so such values are
# neutralized by prefixing a single quote before writing the CSV row.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@")


def _sanitize_csv_value(value: str) -> str:
    """Neutralize CSV formula injection by prefixing risky leading characters.

    Args:
        value: The string cell value to sanitize.

    Returns:
        The value unchanged, or prefixed with a single quote if its first
        non-whitespace character is one a spreadsheet interprets as a formula.

    """
    # Spreadsheets trim leading whitespace before deciding whether a cell is a
    # formula, so " =cmd" / "\t=cmd" are just as dangerous as "=cmd". Inspect the
    # left-stripped value but prefix the original so the data is preserved.
    if value.lstrip().startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def _checked(items: Iterable[LogEntry]) -> Iterator[LogEntry]:
    """The entries of ``items``, each checked to be a `LogEntry`.

    Raises:
        TypeError: An item is not a `LogEntry`.

    """
    for item in items:
        if not isinstance(item, LogEntry):
            msg = f"export_logs takes LogEntry items, not {type(item).__name__}"
            raise TypeError(msg)
        yield item


def _write_json(entries: Iterable[LogEntry], file: TextIO, indent: int | None) -> int:
    """Write an array, one entry at a time, as ``json.dumps(array, indent=)`` does."""
    # A JSON string holds no raw newline, so every newline of a dumped entry
    # starts a line of its structure, which the array indents one level.
    pad = "\n" + " " * (indent or 0)
    count = 0
    file.write("[")
    for entry in entries:
        if count:
            file.write(",")
        if indent is None:
            file.write(entry.to_json())
        else:
            text = escape_unsafe(
                json.dumps(entry.to_dict(), ensure_ascii=False, indent=indent)
            )
            file.write(pad + text.replace("\n", pad))
        count += 1
    if count and indent is not None:
        file.write("\n")
    file.write("]")
    return count


def _write_jsonl(entries: Iterable[LogEntry], file: TextIO) -> int:
    """Write one compact JSON object per LF-terminated line."""
    count = 0
    for entry in entries:
        file.write(entry.to_json() + "\n")
        count += 1
    return count


def _write_text(entries: Iterable[LogEntry], file: TextIO) -> int:
    """Write each entry's ``raw`` line, LF-terminated: what `read_file` reads."""
    count = 0
    for entry in entries:
        file.write(entry.raw + "\n")
        count += 1
    return count


def _csv_cell(value: object) -> object:
    """One cell: a datetime as ISO 8601, a string protected from formulas."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str):
        return _sanitize_csv_value(value)
    return value


def _write_csv(entries: Iterable[LogEntry], file: TextIO) -> int:
    """Write a header and one row per entry; the columns are the `LogEntry` fields."""
    writer = csv.writer(file)
    writer.writerow(_CSV_COLUMNS)
    count = 0
    for entry in entries:
        writer.writerow([_csv_cell(getattr(entry, name)) for name in _CSV_COLUMNS])
        count += 1
    return count


def _check_options(format: str, indent: object) -> None:  # noqa: A002  (the public name)
    """Refuse a bad ``format`` or ``indent``, before anything is read or created.

    Raises:
        ValueError: ``format`` is unknown, ``indent`` is negative, or ``indent``
            is given for a format other than json.
        TypeError: ``indent`` is neither None nor an int.

    """
    if format not in _FORMATS:
        names = ", ".join(_FORMATS)
        msg = f"Unsupported export format: {format!r}; expected one of {names}"
        raise ValueError(msg)
    if indent is None:
        return
    if format != "json":
        msg = (
            f"indent= applies to format='json' only, not {format!r}: a JSON Lines "
            "record is one line, and csv and text have no structure to indent"
        )
        raise ValueError(msg)
    if isinstance(indent, bool) or not isinstance(indent, int):
        msg = f"indent must be an int or None, not {indent!r}"
        raise TypeError(msg)
    if indent < 0:
        msg = f"indent must be at least 0, got {indent}"
        raise ValueError(msg)


def _mode_to_keep(target: Path) -> int | None:
    """The permission bits of the regular file at ``target``; None if nothing is there.

    Raises:
        OSError: ``target`` is a directory or another special file, which a
            regular file must not replace (a device node, for one, as root).
        PermissionError: ``target`` is read-only. A replace asks the directory,
            not the file, so POSIX would pass it by.

    """
    try:
        status = target.stat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(status.st_mode):
        code = errno.EISDIR if stat.S_ISDIR(status.st_mode) else errno.EINVAL
        raise OSError(code, "export_logs needs a regular file", str(target))
    if not os.access(target, os.W_OK):
        raise PermissionError(errno.EACCES, "the file is read-only", str(target))
    return stat.S_IMODE(status.st_mode)


def _create_temporary(path: Path, mode: int | None) -> TextIO:
    """Create the temporary file: ``mode`` is that of the file it will replace.

    It is no wider than that file from the start: a chmod after the open would
    leave a moment in which a reader can open a private file's new content and keep
    the descriptor. A new file gets the default permissions (mkstemp's are 0600).
    "x": it never opens another file. newline="": nothing is translated, on Windows
    too; only the csv module writes CRLF.

    The opener is a partial of C functions, not a Python function: no bytecode runs
    between the creation and the file object taking the descriptor, so an interrupt
    cannot land there and lose it. After that, losing the file object closes it.
    """
    creation = 0o666 if mode is None else mode & 0o777
    return open(
        path,
        "x",
        encoding="utf-8",
        errors="backslashreplace",
        newline="",
        opener=functools.partial(os.open, mode=creation),
    )


def _remove_temporary(path: Path) -> None:
    """Remove the temporary file; whatever keeps it (a scanner on Windows) must not
    hide the error being raised."""
    with contextlib.suppress(OSError):
        path.unlink(missing_ok=True)


def export_logs(
    entries: Iterable[LogEntry],
    destination: str | PathLike[str],
    *,
    format: Literal["json", "jsonl", "csv", "text"] = "jsonl",  # noqa: A002  (public)
    indent: int | None = None,
) -> int:
    """Write log entries to a file, all of them or, on any error, none.

    The input is read as it is written, so it may be a long iterator. Text is
    UTF-8, with no newline translation on any platform.

    Formats:

    - ``"jsonl"`` (default): JSON Lines, one compact object per LF-terminated
      line.
    - ``"json"``: one array of objects. Compact, or as
      ``json.dumps(array, indent=indent)`` gives it.
    - ``"csv"``: a header and one row per entry, CRLF-terminated. The columns
      are the fields of `LogEntry` in order, ``raw`` included; ``logged_at``
      is written as in ``to_dict()``, booleans as ``True`` and ``False``, and
      a missing value (None) as an empty cell. A string cell that a
      spreadsheet would run as a formula gets a leading ``'``.
    - ``"text"``: each entry's ``raw``, LF-terminated. `read_file` reads it
      back with the format the lines were in (``format="threadtime"`` by
      default).

    The objects of ``"json"`` and ``"jsonl"`` are ``entry.to_dict()``. As in
    `LogEntry.to_json`, the C1 controls (U+0080-U+009F), U+2028, U+2029 and the
    bidirectional controls (U+061C, U+200E, U+200F, U+202A-U+202E,
    U+2066-U+2069) are written as ``\\uXXXX`` escapes, which ``json.loads`` reads
    back as the same characters. So a JSON Lines record is one line also to
    readers that stop at U+0085, U+2028 or U+2029.

    A lone surrogate in a string (it cannot be encoded as UTF-8) is written as
    the escape ``\\ud800`` in ``"json"`` and ``"jsonl"``, which ``json.loads``
    reads back as the lone surrogate, and as the literal text ``\\ud800`` in
    ``"csv"`` and ``"text"``, where it cannot be told from a real backslash.

    The write is atomic: a temporary file named ``.logprobe-<hex>.tmp`` in the
    destination's directory is closed, then ``os.replace``d over the
    destination. On any error, an exception from ``entries`` or an interrupt
    included, the destination is untouched and the removal of the temporary file
    is attempted. The removal is best effort: it can fail (a file held open on
    Windows, a directory that became read-only), and the file, with the part of
    the export written so far, then stays; the error that caused the cleanup is
    still the one raised. A process killed outright leaves the file behind too,
    and only an interrupt right after the replace raises with the new file in
    place. That name takes 30 characters whatever the destination is called, so
    the directory needs room for it under the platform's path limit, as the
    resolved path of the destination does. A
    symlink stays, and the file it names is replaced. A replaced file keeps its
    permission bits, and the temporary file is never wider than they are; a new
    one gets the default ones. The file is not synced to disk, so a power
    failure can lose the write.

    Args:
        entries: The entries to write.
        destination: The file to write.
        format: The file format, as above.
        indent: The indentation of ``"json"``; None for one line. Other formats
            refuse it.

    Returns:
        The number of entries written.

    Raises:
        OSError: The file is read-only, a directory, a special file or a symlink
            loop, its directory does not exist or cannot be written, or Windows
            refuses the replace because another process has the file open.
        ValueError: ``format`` is unknown, or ``indent`` is negative or given
            for a format other than ``"json"``.
        TypeError: ``indent`` is not an int, or an item is not a `LogEntry`.

    """
    _check_options(format, indent)
    # The file a symlink names, in its own directory: replacing the link itself
    # would leave the file it named stale.
    # realpath, not Path.resolve(): on 3.12 that is a RuntimeError for a symlink
    # loop, and here the stat in _mode_to_keep makes it an OSError on any Python.
    target = Path(os.path.realpath(destination))
    mode = _mode_to_keep(target)
    # The name does not grow with the destination's, which may be at the limit.
    temporary = target.with_name(f".logprobe-{os.urandom(8).hex()}.tmp")
    try:
        file = _create_temporary(temporary, mode)
    except FileExistsError:
        raise  # that name is another export's file, not this one's to remove
    except BaseException:  # an interrupt can land right after the creation
        _remove_temporary(temporary)
        raise
    try:
        with file:
            count = _write(_checked(entries), file, format, indent)
        if mode is not None:  # the umask narrowed what was created
            with contextlib.suppress(OSError):  # a file system without chmod
                temporary.chmod(mode)
        temporary.replace(target)
    except BaseException:
        _remove_temporary(temporary)
        raise
    return count


def _write(
    entries: Iterable[LogEntry],
    file: TextIO,
    format: str,  # noqa: A002  (the public name)
    indent: int | None,
) -> int:
    """Write ``entries`` to ``file`` in a checked ``format``; return how many."""
    if format == "json":
        return _write_json(entries, file, indent)
    if format == "jsonl":
        return _write_jsonl(entries, file)
    if format == "csv":
        return _write_csv(entries, file)
    return _write_text(entries, file)
