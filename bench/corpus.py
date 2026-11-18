"""Deterministic log lines for the benchmarks, in logcat's live format.

The live format is what logprobe asks logcat for: ``-v threadtime -v year -v
usec -v zone -v uid``, for example::

    2026-11-04 04:41:08.753289 +0000 shell  3805  3805 I sh      : message

Four kinds of lines, all built from nothing but the recorded device output in
``tests/fixtures/device`` and arithmetic, so two runs (and two machines) build
byte-identical lines:

``live``
    The lines recorded on the API 24 and 36 emulators that are in the live
    format, repeated in recording order until there are enough. The recording holds
    1,194 such lines (856 distinct), 136 bytes on average with the line feed.
``dense``
    Lines of exactly 60 bytes including the line feed: the shortest realistic
    live-format line, many per second.
``multibyte``
    Lines whose message is mostly Japanese text; every fourth line also holds
    an emoji, which makes Python store the whole decoded line at four bytes
    per character.
``broken``
    Short lines that are not in any logcat format (2 to 11 bytes with the line
    feed), which the parser turns into entries of its fallback kind.

A line here is ``bytes`` and ends with ``\\n``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Final

__all__ = [
    "BROKEN_POOL",
    "DENSE_LINE_BYTES",
    "KINDS",
    "build_lines",
    "recorded_live_lines",
    "sized_lines",
]

#: The kinds ``build_lines`` knows.
KINDS: Final = ("live", "dense", "multibyte", "broken")

#: Size of every ``dense`` line, line feed included.
DENSE_LINE_BYTES: Final = 60

FIXTURES: Final = (
    Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "device"
)

# One line in the live format (the recordings also hold other formats).
_LIVE: Final = re.compile(
    r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{6} [+-]\d{4} +\S+ +\d+ +\d+ [VDIWEF] "
)

#: Lines of the ``broken`` kind, repeated in this order.
BROKEN_POOL: Final = (
    "x",
    "??",
    "~~~",
    "abc",
    "12",
    "---",
    "-",
    "broken",
    "trunc 12:3",
    "a:b",
    "\t\t",
    "{]",
)

_JAPANESE: Final = (
    "あいうえお日本語端末ログ出力試験文字列漢字仮名交じり文章接続切断再開確認"
)
_EMOJI: Final = "\U0001f600\U0001f680\U0001f525"


def _collect_stdout(node: object, out: list[str]) -> None:
    """Add every string of every ``stdout`` list under ``node`` to ``out``."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "stdout" and isinstance(value, list):
                out.extend(item for item in value if isinstance(item, str))
            else:
                _collect_stdout(value, out)
    elif isinstance(node, list):
        for item in node:
            _collect_stdout(item, out)


def recorded_live_lines(fixtures: Path = FIXTURES) -> list[str]:
    """Return the live-format lines of the device recordings, in file order.

    Files are read in sorted path order, so the result does not depend on the
    file system.
    """
    found: list[str] = []
    for path in sorted(fixtures.glob("*/*.json")):
        _collect_stdout(json.loads(path.read_text(encoding="utf-8")), found)
    return [line for line in found if _LIVE.match(line)]


def _timestamp(i: int) -> str:
    """A date, time and microseconds that grow with ``i``: 10 us per line."""
    micros = i * 10
    seconds, micro = divmod(micros, 1_000_000)
    minutes, second = divmod(seconds, 60)
    hours, minute = divmod(minutes, 60)
    return f"2026-11-04 {(4 + hours) % 24:02d}:{minute:02d}:{second:02d}.{micro:06d}"


def _dense(i: int) -> str:
    """A live-format line of 59 characters (60 bytes with the line feed)."""
    line = (
        f"{_timestamp(i)} +0000  root {1000 + i % 9000:5d} {1000 + i % 7000:5d}"
        f" I a: {i % 1000:03d}"
    )
    if len(line) != DENSE_LINE_BYTES - 1:  # pragma: no cover - guards the format
        msg = f"dense line has {len(line)} characters"
        raise AssertionError(msg)
    return line


def _japanese_message(i: int) -> str:
    text = "".join(
        _JAPANESE[(i * 7 + j * 3) % len(_JAPANESE)] for j in range(30 + i % 30)
    )
    if i % 4 == 3:
        text += _EMOJI[i % len(_EMOJI)]
    return text


def _multibyte(i: int) -> str:
    return (
        f"{_timestamp(i)} +0900  u0_a123 {2000 + i % 5000:5d} {2000 + i % 3000:5d}"
        f" I ログ{i % 10}: {_japanese_message(i)}"
    )


def build_lines(kind: str, count: int) -> list[bytes]:
    """Return ``count`` lines of ``kind`` (see the module docs), each ending in LF.

    Raises:
        ValueError: If ``kind`` is not in `KINDS` or ``count`` is negative.
    """
    if count < 0:
        msg = f"count must not be negative, got {count}"
        raise ValueError(msg)
    if kind == "live":
        pool = recorded_live_lines()
        if not pool:
            msg = f"no live-format lines found under {FIXTURES}"
            raise FileNotFoundError(msg)
        encoded = [(text + "\n").encode() for text in pool]
        return [encoded[i % len(encoded)] for i in range(count)]
    if kind == "dense":
        return [(_dense(i) + "\n").encode() for i in range(count)]
    if kind == "multibyte":
        return [(_multibyte(i) + "\n").encode() for i in range(count)]
    if kind == "broken":
        encoded = [(text + "\n").encode() for text in BROKEN_POOL]
        return [encoded[i % len(encoded)] for i in range(count)]
    msg = f"unknown kind {kind!r}; choose from {', '.join(KINDS)}"
    raise ValueError(msg)


def sized_lines(count: int, message_bytes: int) -> list[bytes]:
    """Return ``count`` distinct ASCII live-format lines with a fixed message size.

    The message is exactly ``message_bytes`` bytes (the line number, cut or
    padded with ``m``), so that the memory benchmark can tell what an entry
    costs for each byte of input.
    """
    lines = []
    for i in range(count):
        message = f"{i}".ljust(message_bytes, "m")[:message_bytes]
        text = (
            f"{_timestamp(i)} +0000  root {1000 + i % 9000:5d} {1000 + i % 7000:5d}"
            f" I sized: {message}\n"
        )
        lines.append(text.encode("ascii"))
    return lines
