"""Device selection and the public API."""

from __future__ import annotations

import copy
import pickle

import pytest

import logprobe
from logprobe import Device, DeviceInfo, LogprobeError, devices
from logprobe._errors import EXIT_STATUS
from tests.fake_adb_server import FakeAdbServer, ShellScript


def construct(fake: FakeAdbServer, serial: str | None = None) -> Device:
    return Device(serial, adb_server=fake.address, start_server=False)


def failure(fake: FakeAdbServer, serial: str | None = None) -> LogprobeError:
    with pytest.raises(LogprobeError) as info:
        construct(fake, serial)
    return info.value


def test_device_names_are_public() -> None:
    assert {"Device", "DeviceInfo", "LogprobeError", "devices"} <= set(logprobe.__all__)


# --- errors ------------------------------------------------------------------


def test_error_attributes_and_str() -> None:
    error = LogprobeError("device_offline", "gone", {"serial": "x"})
    assert (error.code, error.message, error.details, str(error)) == (
        "device_offline",
        "gone",
        {"serial": "x"},
        "gone",
    )
    assert LogprobeError("adb_error", "m").details == {}


def test_error_pickle_and_copy_round_trip() -> None:
    error = LogprobeError("device_offline", "gone", {"serial": "x", "n": [1]})
    for clone in (
        pickle.loads(pickle.dumps(error)),  # noqa: S301
        copy.copy(error),
        copy.deepcopy(error),
    ):
        assert type(clone) is LogprobeError
        assert (clone.code, clone.message, clone.details) == (
            "device_offline",
            "gone",
            {"serial": "x", "n": [1]},
        )
        assert str(clone) == "gone"


def test_error_repr_shows_the_code() -> None:
    assert (
        repr(LogprobeError("device_not_found", "no device"))
        == "LogprobeError('device_not_found', 'no device')"
    )
    assert repr(LogprobeError("adb_error", "m", {"a": 1})) == (
        "LogprobeError('adb_error', 'm', {'a': 1})"
    )


def test_exit_statuses() -> None:
    assert EXIT_STATUS == {
        "internal_error": 1,
        "usage_error": 2,
        "adb_server_unavailable": 3,
        "device_not_found": 4,
        "multiple_devices": 4,
        "device_offline": 5,
        "device_unauthorized": 5,
        "adb_error": 20,
        "device_lost": 21,
        "logcat_failed": 22,
        "device_command_failed": 23,
        "interrupted": 130,
    }


# --- devices() ---------------------------------------------------------------


def test_devices_lists_every_state(fake: FakeAdbServer) -> None:
    fake.add_device("a", "device")
    fake.add_device("b", "offline")
    fake.add_device("c", "unauthorized")
    result = devices(adb_server=fake.address, start_server=False)
    assert [(d.serial, d.state) for d in result] == [
        ("a", "device"),
        ("b", "offline"),
        ("c", "unauthorized"),
    ]
    assert all(isinstance(d, DeviceInfo) for d in result)


# --- selection: explicit serial ------------------------------------------------


def test_serial_argument_selects_that_device(fake: FakeAdbServer) -> None:
    fake.add_device("a")
    fake.add_device("b")
    device = construct(fake, "b")
    assert device.serial == "b"
    assert device.server == ("127.0.0.1", fake.port)


def test_serial_not_attached(fake: FakeAdbServer) -> None:
    fake.add_device("a")
    error = failure(fake, "zzz")
    assert error.code == "device_not_found"
    assert error.details == {"serial": "zzz", "attached": ["a"]}


def test_serial_unauthorized(fake: FakeAdbServer) -> None:
    fake.add_device("a", "unauthorized")
    error = failure(fake, "a")
    assert error.code == "device_unauthorized"
    assert error.details == {"serial": "a", "state": "unauthorized"}


@pytest.mark.parametrize("state", ["offline", "bootloader", "recovery"])
def test_serial_in_other_state_is_offline(fake: FakeAdbServer, state: str) -> None:
    fake.add_device("a", state)
    error = failure(fake, "a")
    assert error.code == "device_offline"
    assert error.details == {"serial": "a", "state": state}


def test_environment_serial_is_used_when_no_argument(
    fake: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake.add_device("a")
    fake.add_device("b")
    monkeypatch.setenv("ANDROID_SERIAL", "b")
    assert construct(fake).serial == "b"


def test_argument_beats_environment_serial(
    fake: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake.add_device("a")
    fake.add_device("b")
    monkeypatch.setenv("ANDROID_SERIAL", "b")
    assert construct(fake, "a").serial == "a"


def test_environment_serial_not_attached(
    fake: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake.add_device("a")
    monkeypatch.setenv("ANDROID_SERIAL", "gone")
    error = failure(fake)
    assert error.code == "device_not_found"
    assert error.details == {"serial": "gone", "attached": ["a"]}


@pytest.mark.parametrize(
    ("state", "code"),
    [("unauthorized", "device_unauthorized"), ("offline", "device_offline")],
)
def test_environment_serial_in_a_bad_state(
    fake: FakeAdbServer, monkeypatch: pytest.MonkeyPatch, state: str, code: str
) -> None:
    fake.add_device("a", state)
    fake.add_device("b")
    monkeypatch.setenv("ANDROID_SERIAL", "a")
    error = failure(fake)
    assert error.code == code
    assert error.details == {"serial": "a", "state": state}


def test_empty_environment_serial_counts_as_unset(
    fake: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake.add_device("only")
    monkeypatch.setenv("ANDROID_SERIAL", "")
    assert construct(fake).serial == "only"


# --- selection: no serial ---------------------------------------------------------


def test_single_ready_device_is_chosen_even_with_others(fake: FakeAdbServer) -> None:
    fake.add_device("off", "offline")
    fake.add_device("ok")
    assert construct(fake).serial == "ok"


def test_two_ready_devices_are_ambiguous(fake: FakeAdbServer) -> None:
    fake.add_device("a")
    fake.add_device("b")
    fake.add_device("c", "offline")
    error = failure(fake)
    assert error.code == "multiple_devices"
    assert error.details == {"serials": ["a", "b"]}


def test_only_unauthorized_and_offline_reports_unauthorized(
    fake: FakeAdbServer,
) -> None:
    fake.add_device("a", "offline")
    fake.add_device("b", "unauthorized")
    error = failure(fake)
    assert error.code == "device_unauthorized"
    assert error.details == {"devices": {"a": "offline", "b": "unauthorized"}}


def test_only_offline_reports_offline(fake: FakeAdbServer) -> None:
    fake.add_device("a", "offline")
    error = failure(fake)
    assert error.code == "device_offline"
    assert error.details == {"devices": {"a": "offline"}}


def test_no_devices_is_not_found(fake: FakeAdbServer) -> None:
    error = failure(fake)
    assert error.code == "device_not_found"
    assert error.details == {}


# --- construction and methods ---------------------------------------------------------


def test_selection_happens_at_construction(fake: FakeAdbServer) -> None:
    failure(fake)
    assert fake.requests == ["host:devices-l"]


@pytest.mark.parametrize("bad", ["a\0", "a\nb", ""])
def test_bad_serial_is_value_error(fake: FakeAdbServer, bad: str) -> None:
    with pytest.raises(ValueError, match="serial"):
        construct(fake, bad)
    assert fake.requests == []


def test_features_and_shell(fake: FakeAdbServer) -> None:
    fake.add_device("a")
    fake.features["a"] = ["shell_v2", "cmd"]
    fake.shell['export ANDROID_LOG_TAGS=""; exec getprop ro.x'] = ShellScript(
        steps=[("stdout", b"1\n"), ("stderr", b"w")], exit_status=0
    )
    device = construct(fake)
    assert device.features() == frozenset({"shell_v2", "cmd"})
    result = device.shell(["getprop", "ro.x"], timeout=5)
    assert (result.exit_status, result.stdout, result.stderr) == (0, b"1\n", b"w")


def test_unreachable_server_fails_at_construction() -> None:
    from tests.fake_adb_server import free_port

    with pytest.raises(LogprobeError) as info:
        Device(adb_server=f"tcp:127.0.0.1:{free_port()}")
    assert info.value.code == "adb_server_unavailable"


def test_error_pickle_and_copy_keep_notes() -> None:
    error = LogprobeError("adb_error", "m", {"k": 1})
    error.add_note("while reading logcat")
    for clone in (
        pickle.loads(pickle.dumps(error)),  # noqa: S301
        copy.copy(error),
        copy.deepcopy(error),
    ):
        assert clone.__notes__ == ["while reading logcat"]
        assert (clone.code, clone.message, clone.details) == (
            "adb_error",
            "m",
            {"k": 1},
        )
