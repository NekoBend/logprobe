"""Tests for the scripted fake adb server itself."""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

import pytest

from logprobe import _adb
from tests.fake_adb_server import (
    ConnectionRecord,
    Cut,
    FakeAdbServer,
    Omit,
    ShellScript,
    Wait,
    _Handler,
    t_value_of,
)

if TYPE_CHECKING:
    import queue
    from collections.abc import Sequence

SERIAL = "emulator-5554"
PREFIX = 'export ANDROID_LOG_TAGS=""; exec '


@pytest.fixture
def device(fake: FakeAdbServer) -> FakeAdbServer:
    fake.add_device(SERIAL)
    return fake


def open_stream(fake: FakeAdbServer, args: Sequence[str]) -> _adb.ShellStream:
    address = _adb.resolve_server_address(fake.address)
    return _adb.open_shell(address, SERIAL, args, timeout=5)


def read_all(stream: _adb.ShellStream) -> bytes:
    stream.set_timeout(5)
    out = bytearray()
    with stream:
        while (event := stream.read()) is not None:
            if event[0] == "stdout":
                out.extend(event[1])
    return bytes(out)


def run(fake: FakeAdbServer, args: Sequence[str]) -> bytes:
    return read_all(open_stream(fake, args))


def test_nth_connection_gets_nth_script(device: FakeAdbServer) -> None:
    device.add_sequence(
        "logcat",
        ShellScript(steps=[("stdout", b"first\n")]),
        ShellScript(steps=[("stdout", b"second\n")]),
    )
    assert run(device, ["logcat"]) == b"first\n"
    assert run(device, ["logcat", "-T", "5"]) == b"second\n"
    # Past the last script the default applies.
    assert run(device, ["logcat"]) == b""
    assert [r.index for r in device.records] == [0, 1, 2]


def test_sequences_count_per_prefix(device: FakeAdbServer) -> None:
    device.add_sequence("logcat", ShellScript(steps=[("stdout", b"L\n")]))
    device.add_sequence("getprop", ShellScript(steps=[("stdout", b"P\n")]))
    assert run(device, ["getprop", "x"]) == b"P\n"
    assert run(device, ["logcat"]) == b"L\n"


def test_exact_shell_entry_wins_over_sequence(device: FakeAdbServer) -> None:
    device.add_sequence("logcat", ShellScript(steps=[("stdout", b"seq\n")]))
    device.shell[PREFIX + "logcat"] = ShellScript(steps=[("stdout", b"exact\n")])
    assert run(device, ["logcat"]) == b"exact\n"


def test_wait_point_holds_until_release(device: FakeAdbServer) -> None:
    device.add_sequence(
        "logcat",
        ShellScript(
            steps=[("stdout", b"a\n"), Wait("gate"), ("stdout", b"b\n")],
        ),
    )
    stream = open_stream(device, ["logcat"])
    stream.set_timeout(5)
    assert stream.read() == ("stdout", b"a\n")
    assert device.wait_reached("gate")
    stream.set_timeout(0.2)
    with pytest.raises(TimeoutError):
        stream.read()
    device.release("gate")
    stream.set_timeout(5)
    assert stream.read() == ("stdout", b"b\n")
    assert stream.read() is None
    assert stream.exit_status == 0
    stream.close()
    assert device.wait_done(0)
    assert device.violations == []


def test_release_before_arrival_is_remembered(device: FakeAdbServer) -> None:
    device.release("gate")
    device.add_sequence("logcat", ShellScript(steps=[Wait("gate"), ("stdout", b"x\n")]))
    assert run(device, ["logcat"]) == b"x\n"


def test_unreleased_wait_is_reported_and_drops(device: FakeAdbServer) -> None:
    device.guard = 0.1
    device.add_sequence("logcat", ShellScript(steps=[Wait("never")]))
    stream = open_stream(device, ["logcat"])
    assert read_all(stream) == b""
    assert stream.exit_status is None
    assert device.wait_done(0)
    assert device.records[0].dropped
    assert any("never" in v for v in device.violations)
    device.violations.clear()


def test_client_closing_frees_a_wait_point(device: FakeAdbServer) -> None:
    device.add_sequence("logcat", ShellScript(steps=[Wait("gate")]))
    stream = open_stream(device, ["logcat"])
    assert device.wait_reached("gate")
    stream.close()
    assert device.wait_done(0)
    assert device.violations == []
    assert device.records[0].dropped


def test_t_value_is_recorded_and_checked(device: FakeAdbServer) -> None:
    device.add_sequence(
        "logcat",
        ShellScript(expect_t="100.000"),
        ShellScript(expect_t="99.000"),
        ShellScript(expect_t="7.000"),
    )
    run(device, ["logcat", "-T", "100.000"])
    run(device, ["logcat", "-T", "100.000"])
    run(device, ["logcat"])
    assert [r.t_value for r in device.records] == ["100.000", "100.000", None]
    assert len(device.violations) == 2
    assert "connection 1" in device.violations[0]
    assert "got None" in device.violations[1]
    device.violations.clear()


def test_t_value_of_parses_quoted_command() -> None:
    assert t_value_of(PREFIX + "logcat -v threadtime -T 12.500") == "12.500"
    assert t_value_of(PREFIX + "logcat -b all") is None
    assert t_value_of(PREFIX + "logcat -T") is None
    assert t_value_of("logcat -T 'unclosed") is None


def test_one_off_answers(device: FakeAdbServer) -> None:
    device.answer("date +%s", b"1700000000\n")
    device.answer("getprop ro.build.version.sdk", b"36\n")
    device.answer("getprop", b"other\n")
    device.answer("logcat -g", b"main: ring buffer is 256 KiB\n")
    device.answer("dumpsys package", b"Package [x]\n", exit_status=3)
    assert run(device, ["date", "+%s"]) == b"1700000000\n"
    # The longest matching prefix wins.
    assert run(device, ["getprop", "ro.build.version.sdk"]) == b"36\n"
    assert run(device, ["getprop", "ro.other"]) == b"other\n"
    assert run(device, ["logcat", "-g"]).startswith(b"main:")
    result = _adb.run_shell(
        _adb.resolve_server_address(device.address),
        SERIAL,
        ["dumpsys", "package", "x"],
        timeout=5,
    )
    assert (result.exit_status, result.stdout) == (3, b"Package [x]\n")


def test_log_command_is_recorded_and_injected_into_live_stream(
    device: FakeAdbServer,
) -> None:
    device.echo_logged = lambda tag, message: f"I/{tag}: {message}\n".encode()
    device.add_sequence(
        "logcat",
        ShellScript(steps=[("stdout", b"before\n"), Wait("live", live=True)]),
    )
    stream = open_stream(device, ["logcat"])
    stream.set_timeout(5)
    assert stream.read() == ("stdout", b"before\n")
    assert device.wait_reached("live")
    assert run(device, ["log", "-t", "mark", "hello world"]) == b""
    assert stream.read() == ("stdout", b"I/mark: hello world\n")
    assert device.logged == [("mark", "hello world")]
    device.release("live")
    assert stream.read() is None
    stream.close()
    assert device.records[0].delivered_lines() == [
        b"before\n",
        b"I/mark: hello world\n",
    ]


def test_log_command_without_echo_adds_nothing(device: FakeAdbServer) -> None:
    device.add_sequence("logcat", ShellScript(steps=[Wait("live", live=True)]))
    stream = open_stream(device, ["logcat"])
    assert device.wait_reached("live")
    run(device, ["log", "-t", "t", "m"])
    device.release("live")
    stream.set_timeout(5)
    assert stream.read() is None
    stream.close()
    assert device.logged == [("t", "m")]
    assert device.records[0].stdout == b""


def test_inject_without_live_stream_reaches_nobody(device: FakeAdbServer) -> None:
    assert device.inject(b"x\n") == 0


def test_drop_mid_packet_payload(device: FakeAdbServer) -> None:
    device.add_sequence(
        "logcat",
        ShellScript(
            steps=[("stdout", b"whole\n"), Cut("stdout", b"abcdef\n", keep=5 + 3)],
        ),
    )
    stream = open_stream(device, ["logcat"])
    stream.set_timeout(5)
    assert stream.read() == ("stdout", b"whole\n")
    # The client sees the end of the stream without an exit status.
    assert stream.read() is None
    assert stream.exit_status is None
    stream.close()
    assert device.wait_done(0)
    record = device.records[0]
    assert record.dropped
    assert record.delivered_lines() == [b"whole\n"]
    assert record.partial_line() == b"abc"
    assert bytes(record.lost) == b"def\n"


def test_drop_inside_packet_header(device: FakeAdbServer) -> None:
    device.add_sequence("logcat", ShellScript(steps=[Cut("stdout", b"line\n", keep=3)]))
    stream = open_stream(device, ["logcat"])
    stream.set_timeout(5)
    assert stream.read() is None
    assert stream.exit_status is None
    stream.close()
    assert device.wait_done(0)
    assert bytes(device.records[0].lost) == b"line\n"
    assert device.records[0].stdout == b""


def test_drop_mid_line_between_packets(device: FakeAdbServer) -> None:
    # A line split over two packets, the connection ends after the first part.
    device.add_sequence(
        "logcat",
        ShellScript(steps=[("stdout", b"ok\n"), ("stdout", b"half")], exit_status=None),
    )
    assert run(device, ["logcat"]) == b"ok\nhalf"
    record = device.records[0]
    assert record.dropped
    assert record.delivered_lines() == [b"ok\n"]
    assert record.partial_line() == b"half"


def test_omitted_lines_are_recorded_not_sent(device: FakeAdbServer) -> None:
    device.add_sequence(
        "logcat",
        ShellScript(
            steps=[
                ("stdout", b"1\n"),
                Omit(b"2\n3\n"),
                ("stdout", b"4\n"),
            ],
        ),
    )
    device.add_sequence(
        "logcat", ShellScript(steps=[Omit(b"9\n"), ("stdout", b"10\n")])
    )
    assert run(device, ["logcat"]) == b"1\n4\n"
    assert run(device, ["logcat"]) == b"10\n"
    first, second = device.records
    assert first.omitted_lines() == [b"2\n", b"3\n"]
    assert not first.dropped
    assert device.expected_loss() == b"2\n3\n9\n"
    sent = first.delivered_lines() + second.delivered_lines()
    assert sent == [b"1\n", b"4\n", b"10\n"]


def test_modes_still_work_with_control_steps(device: FakeAdbServer) -> None:
    for mode in ("fragment", "coalesce"):
        device.add_sequence(
            "logcat",
            ShellScript(
                steps=[("stdout", b"a\n"), Wait(mode), ("stdout", b"b\n")],
                fragment=mode == "fragment",
                coalesce=mode == "coalesce",
            ),
        )
        device.release(mode)
        assert run(device, ["logcat"]) == b"a\nb\n"


def test_concurrent_connections_are_independent(device: FakeAdbServer) -> None:
    device.add_sequence(
        "logcat",
        ShellScript(steps=[Wait("one"), ("stdout", b"1\n")]),
        ShellScript(steps=[("stdout", b"2\n")]),
    )
    results: list[bytes] = []
    thread = threading.Thread(target=lambda: results.append(run(device, ["logcat"])))
    thread.start()
    assert device.wait_reached("one")
    assert run(device, ["logcat"]) == b"2\n"
    device.release("one")
    thread.join(timeout=5)
    assert results == [b"1\n"]
    assert [r.index for r in device.records] == [0, 1]


def test_one_off_does_not_use_up_a_shorter_sequence(device: FakeAdbServer) -> None:
    device.add_sequence(
        "logcat",
        ShellScript(steps=[("stdout", b"STREAM-1\n")]),
        ShellScript(steps=[("stdout", b"STREAM-2\n")]),
    )
    device.answer("logcat -g", b"ring 256K\n")
    assert run(device, ["logcat", "-g"]) == b"ring 256K\n"
    assert run(device, ["logcat", "-v", "threadtime"]) == b"STREAM-1\n"
    assert run(device, ["logcat", "-g"]) == b"ring 256K\n"
    assert run(device, ["logcat", "-v", "threadtime"]) == b"STREAM-2\n"
    # Nothing left in the sequence: the default applies, not the one-off.
    assert run(device, ["logcat", "-d"]) == b""


def test_exhausted_longer_sequence_does_not_fall_to_shorter(
    device: FakeAdbServer,
) -> None:
    device.add_sequence("logcat -g", ShellScript(steps=[("stdout", b"G\n")]))
    device.add_sequence("logcat", ShellScript(steps=[("stdout", b"STREAM\n")]))
    assert run(device, ["logcat", "-g"]) == b"G\n"
    assert run(device, ["logcat", "-g"]) == b""
    assert run(device, ["logcat"]) == b"STREAM\n"


def test_sequence_wins_a_prefix_tie_with_one_off(device: FakeAdbServer) -> None:
    device.answer("getprop", b"one-off\n")
    device.add_sequence("getprop", ShellScript(steps=[("stdout", b"seq\n")]))
    assert run(device, ["getprop"]) == b"seq\n"
    assert run(device, ["getprop"]) == b""


def test_records_carry_the_device_serial(fake: FakeAdbServer) -> None:
    fake.add_device("emulator-5554")
    fake.add_device("emulator-5556")
    fake.add_sequence("logcat", ShellScript(steps=[("stdout", b"any\n")]))
    fake.add_sequence(
        "logcat", ShellScript(steps=[("stdout", b"only-56\n")]), serial="emulator-5556"
    )
    address = _adb.resolve_server_address(fake.address)
    for serial in ("emulator-5556", "emulator-5554"):
        stream = _adb.open_shell(address, serial, ["logcat"], timeout=5)
        read_all(stream)
    assert [r.serial for r in fake.records] == ["emulator-5556", "emulator-5554"]
    assert [bytes(r.stdout) for r in fake.records] == [b"only-56\n", b"any\n"]


def test_log_marker_reaches_only_the_streams_of_its_device(
    fake: FakeAdbServer,
) -> None:
    fake.add_device("emulator-5554")
    fake.add_device("emulator-5556")
    fake.echo_logged = lambda tag, message: f"I/{tag}: {message}\n".encode()
    fake.add_sequence(
        "logcat",
        ShellScript(steps=[Wait("a", live=True)]),
        ShellScript(steps=[Wait("b", live=True)]),
    )
    address = _adb.resolve_server_address(fake.address)
    stream_a = _adb.open_shell(address, "emulator-5554", ["logcat"], timeout=5)
    stream_b = _adb.open_shell(address, "emulator-5556", ["logcat"], timeout=5)
    assert fake.wait_reached("a")
    assert fake.wait_reached("b")
    _adb.run_shell(address, "emulator-5554", ["log", "-t", "t", "m"], timeout=5)
    assert fake.inject(b"x\n", serial="emulator-5556") == 1
    fake.release("a")
    fake.release("b")
    assert read_all(stream_a) == b"I/t: m\n"
    assert read_all(stream_b) == b"x\n"


def test_failing_log_command_adds_nothing(device: FakeAdbServer) -> None:
    device.echo_logged = lambda tag, message: f"I/{tag}: {message}\n".encode()
    device.answer("log -t", exit_status=1)
    device.add_sequence("logcat", ShellScript(steps=[Wait("live", live=True)]))
    stream = open_stream(device, ["logcat"])
    assert device.wait_reached("live")
    result = _adb.run_shell(
        _adb.resolve_server_address(device.address),
        SERIAL,
        ["log", "-t", "t", "m"],
        timeout=5,
    )
    assert result.exit_status == 1
    device.release("live")
    assert read_all(stream) == b""
    assert device.logged == []


def test_lone_carriage_return_does_not_split_lines(device: FakeAdbServer) -> None:
    device.add_sequence(
        "logcat",
        ShellScript(steps=[("stdout", b"a\rb\nc\n"), Omit(b"x\ry\n"), Omit(b"tail")]),
    )
    run(device, ["logcat"])
    record = device.records[0]
    assert record.delivered_lines() == [b"a\rb\n", b"c\n"]
    assert record.omitted_lines() == [b"x\ry\n", b"tail"]


def test_cut_rejects_values_that_are_not_a_cut() -> None:
    with pytest.raises(ValueError, match="keep"):
        Cut("stdout", b"abc\n", keep=-1)
    with pytest.raises(ValueError, match="keep"):
        Cut("stdout", b"abc\n", keep=5 + 4)
    assert Cut("stdout", b"abc\n", keep=0).keep == 0


def test_client_gone_at_a_wait_drops_the_connection(
    device: FakeAdbServer,
) -> None:
    big = b"x" * 1_000_000 + b"\n"
    device.add_sequence(
        "logcat",
        ShellScript(
            steps=[("stdout", b"first\n"), Wait("gate")] + [("stdout", big)] * 40
        ),
    )
    stream = open_stream(device, ["logcat"])
    stream.set_timeout(5)
    assert stream.read() == ("stdout", b"first\n")
    assert device.wait_reached("gate")
    stream.close()
    # The client is gone; the fake notices at the wait point.
    assert device.wait_done(0)
    assert device.records[0].dropped
    assert device.records[0].stdout == b"first\n"


def test_failed_write_does_not_count_as_delivered(device: FakeAdbServer) -> None:
    big = b"x" * 1_000_000 + b"\n"
    device.add_sequence(
        "logcat",
        ShellScript(steps=[("stdout", big)] * 60),
    )
    stream = open_stream(device, ["logcat"])
    stream.set_timeout(5)
    assert stream.read() is not None
    stream.close()
    assert device.wait_done(0)
    record = device.records[0]
    assert record.dropped
    assert len(record.stdout) < 60 * len(big)
    # Every payload is either written or recorded as lost.
    assert len(record.stdout) + len(record.lost) == 60 * len(big)


def test_injected_line_is_never_stranded_after_release(
    device: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The handler pauses just before it unregisters its queue; an inject that
    # lands in that window is still counted and must still be delivered.
    device.add_sequence("logcat", ShellScript(steps=[Wait("live", live=True)]))
    paused = threading.Event()
    proceed = threading.Event()
    original = device._remove_live

    def slow_remove(lines: object) -> None:
        paused.set()
        assert proceed.wait(5)
        original(lines)  # ty: ignore[invalid-argument-type]

    monkeypatch.setattr(device, "_remove_live", slow_remove)
    stream = open_stream(device, ["logcat"])
    assert device.wait_reached("live")
    device.release("live")
    assert paused.wait(5)
    assert device.inject(b"tail\n") == 1
    proceed.set()
    assert read_all(stream) == b"tail\n"
    assert device.wait_done(0)
    record = device.records[0]
    assert (bytes(record.stdout), bytes(record.lost)) == (b"tail\n", b"")
    # After the queue is unregistered nobody counts it any more.
    assert device.inject(b"late\n") == 0


def test_inject_accounting_holds_under_concurrent_release(
    device: FakeAdbServer,
) -> None:
    for round_number in range(30):
        name = f"live-{round_number}"
        device.add_sequence("logcat", ShellScript(steps=[Wait(name, live=True)]))
        stream = open_stream(device, ["logcat"])
        assert device.wait_reached(name)
        counted = [0]
        stop = threading.Event()

        def pump(stop: threading.Event = stop, counted: list[int] = counted) -> None:
            while not stop.is_set():
                counted[0] += device.inject(b"l\n")
                time.sleep(0.0005)

        thread = threading.Thread(target=pump, daemon=True)
        thread.start()
        try:
            device.release(name)
            read_all(stream)
        finally:
            stop.set()
            thread.join(timeout=5)
        assert not thread.is_alive()
        assert device.wait_done(round_number)
        record = device.records[round_number]
        # Every counted line was written or recorded as lost, none vanished.
        assert counted[0] * 2 == len(record.stdout) + len(record.lost)


def test_failed_live_send_accounts_every_counted_line(
    device: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The client is gone and the lines are injected after the wait was
    # released but before the handler unregisters its queue, so the final
    # drain has to send them to a closed connection. Every counted line must
    # end up either written or recorded as lost.
    drained: list[tuple[int, bool]] = []
    original_drain = _Handler._drain

    def spy_drain(
        self: _Handler,
        lines: queue.Queue[bytes],
        script: ShellScript,
        record: ConnectionRecord,
        *,
        send: bool,
    ) -> OSError | None:
        drained.append((lines.qsize(), send))
        return original_drain(self, lines, script, record, send=send)

    monkeypatch.setattr(_Handler, "_drain", spy_drain)
    device.add_sequence("logcat", ShellScript(steps=[Wait("gone", live=True)]))
    paused = threading.Event()
    proceed = threading.Event()
    original_remove = device._remove_live

    def slow_remove(lines: object) -> None:
        paused.set()
        assert proceed.wait(5)
        original_remove(lines)  # ty: ignore[invalid-argument-type]

    monkeypatch.setattr(device, "_remove_live", slow_remove)
    stream = open_stream(device, ["logcat"])
    assert device.wait_reached("gone")
    device.release("gone")
    assert paused.wait(5)
    stream.close()
    counted = 0
    for _ in range(50):
        counted += device.inject(b"l\n")
    assert counted == 50
    proceed.set()
    assert device.wait_done(0)
    record = device.records[0]
    # The drain really ran after the release (so it tried to send), and found
    # every injected line still queued.
    assert drained == [(counted, True)]
    assert counted * 2 == len(record.stdout) + len(record.lost)


def test_wait_name_is_single_use(device: FakeAdbServer) -> None:
    device.answer("dumpsys package", b"pkg\n")
    device.oneoff["dumpsys package"] = ShellScript(
        steps=[Wait("slow"), ("stdout", b"pkg\n")]
    )
    device.release("slow")
    assert run(device, ["dumpsys", "package"]) == b"pkg\n"
    assert device.violations == []
    assert run(device, ["dumpsys", "package"]) == b"pkg\n"
    assert any("slow" in v and "more than once" in v for v in device.violations)
    device.violations.clear()


def test_stop_ends_connections_parked_at_a_wait(fake: FakeAdbServer) -> None:
    fake.add_device(SERIAL)
    fake.add_sequence("logcat", ShellScript(steps=[Wait("gate")]))
    known = set(threading.enumerate())
    stream = open_stream(fake, ["logcat"])
    assert fake.wait_reached("gate")
    handlers = [t for t in threading.enumerate() if t not in known]
    assert handlers  # the parked handler thread is running
    fake.stop()
    assert not any(t.is_alive() for t in handlers)
    assert any("still waiting" in v for v in fake.violations)
    fake.violations.clear()
    assert fake.wait_idle(0)
    stream.set_timeout(5)
    assert stream.read() is None
    stream.close()


def test_wait_idle_follows_connection_close(device: FakeAdbServer) -> None:
    device.add_sequence("logcat", ShellScript(steps=[Wait("gate")]))
    stream = open_stream(device, ["logcat"])
    assert device.wait_reached("gate")
    assert not device.wait_idle(0.05)
    stream.close()
    assert device.wait_idle(5)


def test_coalesced_failed_write_keeps_completed_packets(device: FakeAdbServer) -> None:
    big = b"x" * 1_000_000 + b"\n"
    device.add_sequence(
        "logcat",
        ShellScript(steps=[("stdout", b"a\n")] + [("stdout", big)] * 40, coalesce=True),
    )
    stream = open_stream(device, ["logcat"])
    stream.set_timeout(5)
    assert stream.read() is not None
    stream.close()
    assert device.wait_done(0)
    record = device.records[0]
    assert bytes(record.stdout).startswith(b"a\n")
    assert len(record.stdout) + len(record.lost) == 2 + 40 * len(big)


def test_steps_after_a_failed_write_are_lost(device: FakeAdbServer) -> None:
    big = b"x" * 1_000_000 + b"\n"
    device.add_sequence(
        "logcat",
        ShellScript(
            steps=[("stdout", big)] * 60 + [Wait("gate"), ("stdout", b"tail\n")]
        ),
    )
    stream = open_stream(device, ["logcat"])
    stream.set_timeout(5)
    assert stream.read() is not None
    stream.close()
    assert device.wait_done(0)
    record = device.records[0]
    assert len(record.stdout) + len(record.lost) == 60 * len(big) + len(b"tail\n")


def test_steps_after_an_abandoned_wait_are_lost(device: FakeAdbServer) -> None:
    device.add_sequence(
        "logcat",
        ShellScript(steps=[Wait("gate"), ("stdout", b"after\n"), Omit(b"skip\n")]),
    )
    stream = open_stream(device, ["logcat"])
    assert device.wait_reached("gate")
    stream.close()
    assert device.wait_done(0)
    record = device.records[0]
    assert (bytes(record.stdout), bytes(record.lost)) == (b"", b"after\n")
    assert bytes(record.omitted) == b"skip\n"


def test_wait_done_zero_timeout_polls(device: FakeAdbServer) -> None:
    device.add_sequence("logcat", ShellScript(steps=[("stdout", b"x\n")]))
    stream = open_stream(device, ["logcat"])
    read_all(stream)
    assert device.wait_done(0)
    assert device.records[0].done.is_set()
    assert device.wait_done(0, timeout=0)
    assert not device.wait_done(5, timeout=0)


def test_client_closed_at_a_wait_is_no_violation_when_stopping(
    fake: FakeAdbServer,
) -> None:
    fake.add_device(SERIAL)
    fake.add_sequence("logcat", ShellScript(steps=[Wait("gate")]))
    stream = open_stream(fake, ["logcat"])
    assert fake.wait_reached("gate")
    stream.close()
    fake.stop()
    assert fake.violations == []
    assert fake.wait_idle(0)
