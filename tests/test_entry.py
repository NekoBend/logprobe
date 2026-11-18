"""Tests for LogEntry."""

import dataclasses
import json
from datetime import UTC, datetime, timedelta, timezone

import pytest

from logprobe import LogEntry

FIELD_ORDER = [
    "logged_at",
    "pid",
    "tid",
    "level",
    "tag",
    "message",
    "raw",
    "uid",
    "uid_raw",
    "serial",
    "package",
    "parsed",
    "truncated",
]


def _entry(**overrides: object) -> LogEntry:
    base = LogEntry(
        logged_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        pid=1,
        tid=2,
        level="I",
        tag="Tag",
        message="m",
        raw="r",
    )
    return dataclasses.replace(base, **overrides)


def test_log_entry_initialization() -> None:
    """The required fields are stored as given."""
    now = datetime.now(UTC).replace(tzinfo=None)
    entry = LogEntry(
        logged_at=now,
        pid=123,
        tid=456,
        level="D",
        tag="TestTag",
        message="Test message",
        raw="raw log line",
    )

    assert entry.logged_at == now
    assert entry.pid == 123
    assert entry.tid == 456
    assert entry.level == "D"
    assert entry.tag == "TestTag"
    assert entry.message == "Test message"
    assert entry.raw == "raw log line"


def test_log_entry_fields_are_in_the_documented_order() -> None:
    """The field order is the positional-argument order."""
    assert [f.name for f in dataclasses.fields(LogEntry)] == FIELD_ORDER


def test_log_entry_can_be_built_positionally() -> None:
    """The seven required fields come first, in order."""
    moment = datetime(2026, 1, 2, 3, 4, 5)  # noqa: DTZ001
    entry = LogEntry(moment, 1, 2, "W", "T", "msg", "raw")

    assert entry == _entry(
        logged_at=moment, level="W", tag="T", message="msg", raw="raw"
    )


def test_log_entry_new_fields_default_to_a_plain_parsed_line() -> None:
    """uid, uid_raw, serial and package are None; parsed is True, truncated False."""
    entry = _entry()

    assert (entry.uid, entry.uid_raw, entry.serial, entry.package) == (
        None,
        None,
        None,
        None,
    )
    assert entry.parsed is True
    assert entry.truncated is False


def test_log_entry_optional_fields_are_stored() -> None:
    """Every optional field takes the value it is given."""
    entry = _entry(
        uid=10065,
        uid_raw="u0_a65",
        serial="emulator-5554",
        package="com.example.app",
        parsed=False,
        truncated=True,
    )

    assert entry.uid == 10065
    assert entry.uid_raw == "u0_a65"
    assert entry.serial == "emulator-5554"
    assert entry.package == "com.example.app"
    assert entry.parsed is False
    assert entry.truncated is True


def test_log_entry_is_frozen() -> None:
    """Assigning to a field raises FrozenInstanceError; the entry is unchanged."""
    entry = _entry()
    name = "message"  # a variable name: the type checker would refuse the statement

    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(entry, name, "changed")
    with pytest.raises(dataclasses.FrozenInstanceError):
        delattr(entry, name)
    assert entry.message == "m"


def test_log_entry_uses_slots() -> None:
    """Entries have no instance dict, and no attribute can be added."""
    entry = _entry()

    assert LogEntry.__slots__ == tuple(FIELD_ORDER)
    assert not hasattr(entry, "__dict__")
    # A frozen dataclass with slots raises AttributeError here on some Python
    # versions and TypeError on others (its __setattr__ calls a super() built
    # for the pre-slots class); either way the assignment fails.
    with pytest.raises((AttributeError, TypeError)):
        setattr(entry, "extra_" + "field", 1)


def test_log_entry_equality_is_by_field() -> None:
    """Entries with equal fields are equal; any differing field breaks equality."""
    assert _entry() == _entry()
    assert _entry() != _entry(message="other")
    assert _entry() != _entry(serial="emulator-5554")
    assert _entry() != _entry(truncated=True)
    assert _entry() != "not an entry"


def test_log_entry_is_hashable() -> None:
    """Equal entries hash alike, so entries work in sets and as dict keys."""
    entry = _entry()

    assert hash(entry) == hash(_entry())
    assert len({entry, _entry(), _entry(message="other")}) == 2
    assert {entry: 1}[_entry()] == 1


def test_replace_derives_a_changed_copy() -> None:
    """dataclasses.replace builds a new entry; the original is untouched."""
    entry = _entry()

    attributed = dataclasses.replace(entry, package="com.example", uid=10065)

    assert (attributed.package, attributed.uid) == ("com.example", 10065)
    assert (entry.package, entry.uid) == (None, None)
    assert attributed.message == entry.message
    assert attributed is not entry


def test_log_entry_does_not_validate_its_arguments() -> None:
    """The constructor stores what it is given: the parsers guarantee the types."""
    entry = _entry(pid="1")

    assert entry.pid == "1"


def test_log_entry_has_no_meta() -> None:
    """The record has no free-form field."""
    assert not hasattr(_entry(), "meta")


# -- serialization ---------------------------------------------------------------------


def test_to_dict_of_an_aware_entry_has_the_offset() -> None:
    entry = _entry(logged_at=datetime(2026, 1, 2, 3, 4, 5, 6, tzinfo=UTC))

    assert entry.to_dict() == {
        "schema": "logprobe.entry/1",
        "logged_at": "2026-01-02T03:04:05.000006+00:00",
        "level": "I",
        "tag": "Tag",
        "message": "m",
        "pid": 1,
        "tid": 2,
        "parsed": True,
        "truncated": False,
    }


def test_to_dict_keeps_the_offset_of_the_zone() -> None:
    zone = timezone(timedelta(hours=9))

    data = _entry(logged_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=zone)).to_dict()

    assert data["logged_at"] == "2026-01-02T03:04:05+09:00"


def test_to_dict_of_a_naive_entry_invents_no_offset() -> None:
    entry = _entry(logged_at=datetime(2026, 1, 2, 3, 4, 5))  # noqa: DTZ001

    assert entry.to_dict()["logged_at"] == "2026-01-02T03:04:05"


def test_to_dict_writes_zero_and_false() -> None:
    """Numbers and booleans are always present, whatever their value."""
    entry = _entry(pid=0, tid=0, parsed=False, truncated=False)

    data = entry.to_dict()

    assert (data["pid"], data["tid"], data["parsed"], data["truncated"]) == (
        0,
        0,
        False,
        False,
    )


def test_to_dict_omits_optional_fields_that_are_none() -> None:
    data = _entry().to_dict()

    assert not {"serial", "uid", "uid_raw", "package", "raw"} & data.keys()


def test_to_dict_writes_optional_fields_that_are_set() -> None:
    entry = _entry(uid=0, uid_raw="root", serial="emulator-5554", package="com.x")

    data = entry.to_dict()

    assert (data["uid"], data["uid_raw"], data["serial"], data["package"]) == (
        0,
        "root",
        "emulator-5554",
        "com.x",
    )
    assert "raw" not in data


def test_to_dict_never_contains_raw() -> None:
    entry = _entry(raw="the whole line", parsed=False, message="the whole line")

    assert "raw" not in entry.to_dict()
    assert entry.to_dict()["message"] == "the whole line"


def test_to_dict_is_json_ready() -> None:
    entry = _entry(uid=10065, uid_raw="u0_a65", message="é\n日本")

    data = entry.to_dict()

    assert json.loads(json.dumps(data)) == data


def test_to_json_is_compact_and_not_ascii_escaped() -> None:
    entry = _entry(message="日本é", tag="T")

    text = entry.to_json()

    assert text == (
        '{"schema":"logprobe.entry/1","logged_at":"2026-01-02T03:04:05+00:00",'
        '"level":"I","tag":"T","message":"日本é","pid":1,"tid":2,'
        '"parsed":true,"truncated":false}'
    )
    assert json.loads(text) == entry.to_dict()


def test_json_payload_finds_the_first_object_or_array() -> None:
    assert _entry(message='got {"a": [1, 2]} and [3]').json_payload() == {"a": [1, 2]}
    assert _entry(message="x [1, {}] y").json_payload() == [1, {}]
    assert _entry(message="no json here").json_payload() is None
    assert _entry(message="").json_payload() is None
    assert _entry(message="{broken").json_payload() is None


_ESCAPED = (
    *range(0x80, 0xA0),
    0x061C,
    0x200E,
    0x200F,
    0x2028,
    0x2029,
    *range(0x202A, 0x202F),
    *range(0x2066, 0x206A),
)


@pytest.mark.parametrize("code", _ESCAPED, ids=[f"U+{c:04X}" for c in _ESCAPED])
def test_to_json_escapes_each_unsafe_character(code: int) -> None:
    """The character is written as ``\\uXXXX``, never raw, and reads back."""
    char = chr(code)
    text = f"a{char}b"
    entry = _entry(message=text, tag=text)

    out = entry.to_json()

    assert char not in out
    assert f"a\\u{code:04x}b" in out
    assert json.loads(out)["message"] == text
    assert json.loads(out)["tag"] == text
    assert json.loads(out) == entry.to_dict()


def test_to_json_leaves_ordinary_text_byte_for_byte() -> None:
    """ASCII, accented, CJK, emoji and neighbours of the escaped ranges."""
    text = (
        'plain "q" \\ \t caf\u00e9 \u65e5\u672c\U0001f600 '
        "\u00a0\u00ff\u2027\u202f\u2065\u206a"
    )
    entry = _entry(message=text)

    expected = json.dumps(entry.to_dict(), ensure_ascii=False, separators=(",", ":"))

    assert entry.to_json() == expected
    assert entry.to_json().encode() == expected.encode()
