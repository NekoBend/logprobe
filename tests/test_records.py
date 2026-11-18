import copy
import dataclasses
import json
import pickle
import typing
from datetime import UTC, datetime

import pytest

import logprobe
from logprobe import DeviceSummary, Gap, LogprobeError, StreamSummary
from logprobe._errors import EXIT_STATUS

T0 = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)
T1 = datetime(2026, 1, 2, 3, 4, 9, tzinfo=UTC)


def summary(**overrides: object) -> DeviceSummary:
    fields: dict[str, object] = {
        "serial": "emulator-5554",
        "started_at": T0,
        "ended_at": T1,
        "lines": 10,
        "entries": 10,
        "unparsed": 0,
        "truncated": 0,
        "gaps": 0,
        "lost": 0,
        "reconnects": 0,
        "unattributed": 0,
        "flush": "not_requested",
        "error": None,
    }
    fields.update(overrides)
    return DeviceSummary(**fields)  # type: ignore[arg-type]


def test_clean_summary_is_complete() -> None:
    assert summary().complete


@pytest.mark.parametrize(
    "override",
    [
        {"gaps": 1},
        {"unattributed": 1},
        {"unparsed": 1},
        {"truncated": 1},
        {"flush": "timed_out"},
        {"flush": "failed"},
        {"flush": "cancelled"},
        {"error": LogprobeError("device_lost", "gone")},
    ],
)
def test_each_condition_makes_summary_incomplete(override: dict[str, object]) -> None:
    assert not summary(**override).complete


@pytest.mark.parametrize("flush", ["not_requested", "done"])
def test_good_flush_states_stay_complete(flush: str) -> None:
    assert summary(flush=flush).complete


def test_lost_reconnects_and_running_do_not_affect_complete() -> None:
    assert summary(lost=5, reconnects=3, ended_at=None).complete


def test_stream_summary_complete() -> None:
    good, bad = summary(), summary(gaps=1)
    assert StreamSummary((good, good)).complete
    assert not StreamSummary((good, bad)).complete
    assert StreamSummary(()).complete


def test_gap_to_dict_required_only() -> None:
    gap = Gap("s1", "ring_rotated", "released", T0, None)
    assert gap.to_dict() == {
        "schema": "logprobe.gap/1",
        "serial": "s1",
        "reason": "ring_rotated",
        "cause": "released",
        "detected_at": "2026-01-02T03:04:05.123456+00:00",
    }


def test_gap_to_dict_optional_fields() -> None:
    gap = Gap("s1", "device_reported", "notice", T0, T1, lost=0)
    data = gap.to_dict()
    assert data["start_at"] == "2026-01-02T03:04:09+00:00"
    assert data["lost"] == 0
    assert json.loads(json.dumps(data)) == data


def test_gap_start_at_only() -> None:
    data = Gap("s1", "continuity_unknown", "stalled", T0, T1).to_dict()
    assert "start_at" in data
    assert "lost" not in data


def test_summary_to_dict_writes_zero_counts() -> None:
    data = summary(lines=0, entries=0).to_dict()
    assert data == {
        "schema": "logprobe.summary/1",
        "serial": "emulator-5554",
        "started_at": "2026-01-02T03:04:05.123456+00:00",
        "ended_at": "2026-01-02T03:04:09+00:00",
        "lines": 0,
        "entries": 0,
        "unparsed": 0,
        "truncated": 0,
        "gaps": 0,
        "lost": 0,
        "reconnects": 0,
        "unattributed": 0,
        "flush": "not_requested",
        "complete": True,
    }
    assert "error" not in data


def test_summary_to_dict_error_and_running() -> None:
    error = LogprobeError("logcat_failed", "boom", {"exit": 1})
    data = summary(error=error, ended_at=None).to_dict()
    assert data["error"] == {"code": "logcat_failed", "message": "boom"}
    assert "ended_at" not in data
    assert data["complete"] is False
    assert json.loads(json.dumps(data)) == data


def test_stream_summary_to_dict() -> None:
    stream = StreamSummary((summary(), summary(serial="b")))
    data = stream.to_dict()
    assert [d["serial"] for d in data] == ["emulator-5554", "b"]
    assert all(d["schema"] == "logprobe.summary/1" for d in data)


@pytest.mark.parametrize(
    ("code", "status"),
    [
        ("adb_error", 20),
        ("device_lost", 21),
        ("logcat_failed", 22),
        ("device_command_failed", 23),
    ],
)
def test_exit_status(code: str, status: int) -> None:
    assert EXIT_STATUS[code] == status


def test_records_are_frozen_and_slotted() -> None:
    gap = Gap("s1", "ring_rotated", "released", T0, None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        gap.serial = "x"  # ty: ignore[invalid-assignment]
    s = summary()
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.lines = 1  # ty: ignore[invalid-assignment]
    with pytest.raises(dataclasses.FrozenInstanceError):
        StreamSummary((s,)).devices = ()  # ty: ignore[invalid-assignment]
    assert not hasattr(gap, "__dict__")
    assert not hasattr(s, "__dict__")


def _check_clone(result: StreamSummary) -> None:
    got = result.devices[0].error
    assert isinstance(got, LogprobeError)
    assert (got.code, got.message, got.details) == (
        "device_lost",
        "gone",
        {"serial": "s1"},
    )
    assert result.devices[0].serial == "emulator-5554"
    assert result.devices[0].started_at == T0


def _with_error() -> StreamSummary:
    error = LogprobeError("device_lost", "gone", {"serial": "s1"})
    return StreamSummary((summary(error=error),))


def test_summary_with_error_survives_pickle() -> None:
    _check_clone(pickle.loads(pickle.dumps(_with_error())))  # noqa: S301


def test_summary_with_error_survives_copy() -> None:
    original = _with_error()
    assert copy.copy(original).devices[0].error is original.devices[0].error
    _check_clone(copy.deepcopy(_with_error()))


def test_gap_pickles() -> None:
    gap = Gap("s1", "device_reported", "notice", T0, T1, 7)
    assert pickle.loads(pickle.dumps(gap)) == gap  # noqa: S301


def test_exports() -> None:
    for name in ("Gap", "DeviceSummary", "StreamSummary"):
        assert name in logprobe.__all__


def test_record_type_hints_resolve_at_runtime() -> None:
    for cls in (Gap, DeviceSummary, StreamSummary):
        assert typing.get_type_hints(cls)
