"""The log record."""

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from ._json import extract_json

__all__ = ["LogEntry", "LogLevel"]

#: The severity of a log line, from verbose (``V``) to fatal (``F``).
LogLevel = Literal["V", "D", "I", "W", "E", "F"]

#: The value of the ``schema`` key of :meth:`LogEntry.to_dict`.
ENTRY_SCHEMA = "logprobe.entry/1"

# One encoder for every to_json() call: json.dumps with these options would build
# a new one each time.
_ENCODER = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"))

# Characters that JSON written by this library never holds raw, although JSON
# allows them: the C1 controls (U+0085 among them is a line end to some readers),
# the line and paragraph separators U+2028 and U+2029, and the bidirectional
# controls (U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069), which can
# reorder what a viewer displays. The C0 controls are escaped by ``json`` itself.
_UNSAFE = re.compile(
    "[\x80-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]"
)
_UNSAFE_ESCAPES = {
    code: f"\\u{code:04x}"
    for code in [
        *range(0x80, 0xA0),
        0x061C,
        0x200E,
        0x200F,
        0x2028,
        0x2029,
        *range(0x202A, 0x202F),
        *range(0x2066, 0x206A),
    ]
}


def escape_unsafe(text: str) -> str:
    """Escape the characters of ``_UNSAFE`` in JSON text as ``\\uXXXX``.

    The characters only occur inside JSON strings (every other part of JSON is
    ASCII), and ``\\uXXXX`` reads back as the same character, so the JSON value
    does not change. Text without such a character is returned as it is, after
    one search; pure ASCII text, the usual case, needs only a check that is
    faster than that.
    """
    if text.isascii() or _UNSAFE.search(text) is None:
        return text
    return text.translate(_UNSAFE_ESCAPES)


@dataclass(frozen=True, slots=True)
class LogEntry:
    """One log line, split into its fields.

    Entries are immutable: assigning to a field raises
    ``dataclasses.FrozenInstanceError``. Use ``dataclasses.replace`` to derive
    a changed copy. Entries compare equal field by field and are hashable.

    The constructor does not validate its arguments. The parsers guarantee the
    types below; code that builds entries itself is responsible for passing
    them.

    Attributes:
        logged_at: When the line was logged. Timezone-aware when the line
            carries its UTC offset (``-v zone``) or epoch seconds (``-v epoch``,
            in UTC); naive device-local time otherwise, such as yearless
            ``-v threadtime`` files. Lines without any timestamp (brief,
            process, tag, raw, and unrecognised lines) carry the naive host
            time at parsing. ``-v monotonic`` prints seconds since boot in the
            epoch column, so such a line gets that many seconds after the
            epoch: a 1970 timestamp that is not the moment it was logged.
        pid: Process id; 0 when the format has none.
        tid: Thread id; 0 when the format has none.
        level: Priority: V, D, I, W, E or F.
        tag: The tag, without logcat's padding; empty when the format has none.
        message: The message. Only the separator after the tag is removed;
            leading whitespace (``"\\tat ..."``) and trailing spaces stay.
        raw: The line as read, without its terminator.
        uid: The uid from the ``-v uid`` column, a name mapped to its number;
            None when the column is absent, blank or a name that logprobe does
            not know. An isolated-process name ``u<user>_i<n>`` is read with
            Android 10's ``AID_ISOLATED_START`` (90000); on Android 8 and 9,
            where it is 99000, such a uid is 9000 too low. ``uid_raw`` keeps
            the printed name for that case.
        uid_raw: The ``-v uid`` column as printed (a number or a name); None
            when absent or blank.
        serial: The adb serial of the device the line came from; None for
            lines read from a file or given as text.
        package: The app package the line belongs to, set by package
            attribution; None when not attributed.
        parsed: False for the fallback entry of a line the parser did not
            recognise: its message and raw are the whole line.
        truncated: True when the line was longer than the line cap:
            ``raw`` and ``message`` come from its first ``max_line_bytes`` bytes,
            less the start of a character the cut split (at most 3 bytes).

    """

    logged_at: datetime
    pid: int
    tid: int
    level: LogLevel
    tag: str
    message: str
    raw: str
    uid: int | None = None
    uid_raw: str | None = None
    serial: str | None = None
    package: str | None = None
    parsed: bool = True
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """The entry as a dict that ``json.dumps`` accepts.

        Always present: ``schema`` (``"logprobe.entry/1"``), ``logged_at``,
        ``level``, ``tag``, ``message``, ``pid``, ``tid``, ``parsed`` and
        ``truncated``; the numbers and booleans are written even when they are
        0 or False. Present only when not None: ``serial``, ``uid``,
        ``uid_raw`` and ``package``. ``raw`` is left out: for a line that was
        not parsed, ``message`` already holds the whole line.

        ``logged_at`` is ``datetime.isoformat()`` of the field: with a UTC
        offset when the datetime is timezone-aware, without one when it is
        naive. No offset is ever added.
        """
        data: dict[str, Any] = {
            "schema": ENTRY_SCHEMA,
            "logged_at": self.logged_at.isoformat(),
            "level": self.level,
            "tag": self.tag,
            "message": self.message,
            "pid": self.pid,
            "tid": self.tid,
            "parsed": self.parsed,
            "truncated": self.truncated,
        }
        if self.serial is not None:
            data["serial"] = self.serial
        if self.uid is not None:
            data["uid"] = self.uid
        if self.uid_raw is not None:
            data["uid_raw"] = self.uid_raw
        if self.package is not None:
            data["package"] = self.package
        return data

    def to_json(self) -> str:
        """The entry as one compact JSON string: ``to_dict()`` without spaces
        and with non-ASCII characters as they are, except these, which are
        written as ``\\uXXXX`` escapes (a decoder reads back the same string):
        the C1 controls U+0080-U+009F, U+2028, U+2029, and the bidirectional
        controls U+061C, U+200E, U+200F, U+202A-U+202E and U+2066-U+2069. The C0
        controls are escaped as JSON requires."""
        return escape_unsafe(_ENCODER.encode(self.to_dict()))

    def json_payload(self) -> Any | None:  # noqa: ANN401  (arbitrary parsed JSON)
        """The first JSON object or array found in the message, or None.

        The search is bounded in the work it does, so a hostile message cannot
        make it slow; a value the bounds leave out gives None, never an
        exception. Each call searches the message again; keep the result if you
        need it more than once.
        """
        return extract_json(self.message)
