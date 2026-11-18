"""Markers of the blocking and the asyncio stream: ``since="now"``, ``stop(flush=)``.

A test that requests the ``mode`` fixture runs against both versions from one
body; the one that does not is about ``on_entry``.

The fake adb server plays the device. A marker is a line the library writes
with ``log -t``; the fake records the command, and a test puts the marker line
into a connection that is waiting (``inject``) at the place the device would
have logged it. Real waits are shortened through private seams (the receive
tick, the backoff, the time the start marker may take), never with long sleeps;
the order of events is decided with rendezvous, not with sleeps.
"""

from __future__ import annotations

import contextlib
import itertools
import logging
import math
import shlex
import threading
import time
from typing import TYPE_CHECKING, Any

import pytest

from logprobe import Gap, LogEntry, LogprobeError, _astream, _marks, _resume, _stream
from tests.fake_adb_server import FakeAdbServer, Omit, ShellScript, Wait, program_of
from tests.test_stream import (
    GUARD,
    PROMPT,
    attach,
    hold,
    kill_if_hung,
    lines,
    logline,
    names,
    stream_threads,
    wait_until,
)
from tests.test_stream_resume import BASE, at, expect_t, lost, staying

if TYPE_CHECKING:
    from collections.abc import Iterator

    from tests.stream_modes import Mode, StreamLike


pytestmark = pytest.mark.filterwarnings("error::ResourceWarning")

CLOCK = int(BASE.timestamp())  # what the device's `date +%s` answers
TICK = 0.02  # the receive tick of these tests
EOF_TEXT = b"logcat: Unexpected EOF!\n"


@pytest.fixture(autouse=True)
def no_threads_left() -> Iterator[None]:
    before = stream_threads()
    yield
    wait_until(lambda: stream_threads() == before, GUARD)


@pytest.fixture(autouse=True)
def fast_tick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_stream, "TICK", TICK)
    monkeypatch.setattr(_astream, "TICK", TICK)


@pytest.fixture
def fast_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_resume, "backoff", lambda _failures: 0.01)


def marker_line(token: str, n: int = 500) -> bytes:
    """The log line a device writes for ``log -t logprobe <token>``."""
    return logline(n, tag="logprobe", message=token)


def echo_markers(server: FakeAdbServer, *, after: bytes = b"") -> None:
    """Make each successful ``log -t`` add its line (and ``after``) to the logcat."""
    counter = itertools.count(500)

    def echo(tag: str, message: str) -> bytes:
        return logline(next(counter), tag=tag, message=message) + after

    server.echo_logged = echo


def log_commands(server: FakeAdbServer) -> list[list[str]]:
    """The words of every ``log -t`` command the fake saw, in order."""
    return [
        shlex.split(program_of(record.command))
        for record in list(server.records)
        if program_of(record.command).startswith("log -t")
    ]


def begin(
    server: FakeAdbServer,
    mode: Mode,
    *serials: str,
    since: str | None = None,
    reconnect: float = 0.0,
    buffer_lines: int = 10_000,
) -> StreamLike:
    """A stream over ``serials`` (default one device), not started."""
    return mode.stream(
        attach(server, *(serials or ("a",))),
        since=since,
        reconnect=reconnect,
        buffer_lines=buffer_lines,
    )


def guard(s: StreamLike) -> threading.Timer:
    """Kill ``s`` if a test hangs (a guard only; cancelled by the caller)."""
    timer = threading.Timer(GUARD, s.kill)
    timer.daemon = True
    timer.start()
    return timer


def drain(s: StreamLike) -> list[str]:
    """Iterate to the end; the stream must end by itself."""
    timer = guard(s)
    try:
        return [entry.message for entry in s]
    finally:
        timer.cancel()


def take(s: StreamLike, count: int) -> list[str]:
    """Take ``count`` entries, stop the stream and take the rest."""
    timer = guard(s)
    got: list[str] = []
    try:
        for entry in s:
            got.append(entry.message)
            if len(got) == count:
                s.stop()
    finally:
        timer.cancel()
    return got


def only(s: StreamLike) -> Any:  # noqa: ANN401
    """The summary of the stream's only device."""
    (summary,) = s.summary.devices
    return summary


# --- arguments ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "error"),
    [
        ("later", ValueError),
        ("NOW", ValueError),
        ("", ValueError),
        (1, TypeError),
        (True, TypeError),
        (b"now", TypeError),
    ],
)
def test_since_accepts_only_now_or_none(
    server: FakeAdbServer, mode: Mode, value: object, error: type[Exception]
) -> None:
    (device,) = attach(server, "a")
    with pytest.raises(error):
        mode.stream([device], since=value)
    with pytest.raises(error):
        mode.device_stream(device, since=value)
    assert server.records == []  # refused before any command ran


@pytest.mark.parametrize(
    ("value", "error"),
    [
        (True, TypeError),
        (False, TypeError),
        ("1", TypeError),
        ([1], TypeError),
        (math.nan, ValueError),
        (math.inf, ValueError),
        (-math.inf, ValueError),
        (0, ValueError),
        (0.0, ValueError),
        (-1, ValueError),
        (10**400, ValueError),
    ],
)
def test_flush_must_be_a_finite_number_above_zero(
    server: FakeAdbServer, mode: Mode, value: object, error: type[Exception]
) -> None:
    s = begin(server, mode)
    with pytest.raises(error):
        s.stop(flush=value)  # ty: ignore[invalid-argument-type]
    assert not s._core.outbox.stopping  # a refused request stops nothing


# --- since="now" --------------------------------------------------------------------


def staying_open(server: FakeAdbServer, first: bytes = b"", name: str = "go") -> None:
    """The device's logcat sends ``first`` and then waits for lines to be injected."""
    server.answer("date +%s", f"{CLOCK}\n".encode())
    steps: list[Any] = [("stdout", first)] if first else []
    server.add_sequence("logcat", staying(*steps, name=name))


def test_since_now_delivers_only_what_follows_its_own_start_marker(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    early = marker_line("start-" + "a" * 32, 1)  # an earlier run's marker
    staying_open(server, logline(0, message="earlier crash") + early)
    s = begin(server, mode, since="now").start()
    assert server.wait_reached("go")
    token = server.logged[0][1]
    assert token.startswith("start-")
    server.inject(
        logline(2, message="just before")
        + marker_line(token)
        + logline(3, message="m3")
        + marker_line("flush-" + "b" * 32)  # a marker nobody waits for
        + logline(4, message="m4")
    )
    assert take(s, 2) == ["m3", "m4"]
    assert only(s).entries == 2  # what was skipped is not counted as delivered
    assert only(s).error is None


def test_since_now_reads_the_clock_writes_the_marker_and_connects_before_the_clock(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    staying_open(server)
    s = begin(server, mode, since="now").start()
    assert server.wait_reached("go")
    commands = [program_of(record.command) for record in server.records]
    assert commands[0] == "date +%s"
    assert commands[1] == f"log -t logprobe {server.logged[0][1]}"
    assert commands[2].startswith("logcat ")
    assert server.records[2].t_value == f"{CLOCK - 1}.000000"
    s.stop()
    s.join(GUARD)


def test_since_now_prepares_all_devices_first_and_each_skips_to_its_own_marker(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    server.answer("date +%s", f"{CLOCK}\n".encode())
    for serial in ("a", "b"):
        server.add_sequence("logcat", staying(name=f"go-{serial}"), serial=serial)
    s = begin(server, mode, "a", "b", since="now").start()
    assert server.wait_reached("go-a")
    assert server.wait_reached("go-b")
    commands = [
        (record.serial, program_of(record.command).split()[0:2])
        for record in server.records
    ]
    # Each device is prepared in turn (clock, then its own marker) ...
    assert commands[:4] == [
        ("a", ["date", "+%s"]),
        ("a", ["log", "-t"]),
        ("b", ["date", "+%s"]),
        ("b", ["log", "-t"]),
    ]
    # ... and only then are the two logcat connections opened.
    assert sorted((serial, words[0]) for serial, words in commands[4:]) == [
        ("a", "logcat"),
        ("b", "logcat"),
    ]
    tokens = {
        record.serial: shlex.split(program_of(record.command))[3]
        for record in server.records
        if program_of(record.command).startswith("log -t")
    }
    assert len(set(tokens.values())) == 2
    for serial in ("a", "b"):
        server.inject(
            logline(1, tag=serial, message=f"before-{serial}")
            + marker_line(tokens[serial])
            + logline(2, tag=serial, message=f"after-{serial}"),
            serial,
        )
    got: list[tuple[str | None, str]] = []
    with kill_if_hung(s):
        for entry in s:
            got.append((entry.serial, entry.message))
            if len(got) == 2:
                s.stop()
    assert sorted(got) == [("a", "after-a"), ("b", "after-b")]
    assert [d.entries for d in s.summary.devices] == [1, 1]
    assert [d.error for d in s.summary.devices] == [None, None]


@pytest.mark.usefixtures("fast_backoff")
def test_a_reconnect_before_any_line_was_read_starts_at_the_since_time_again(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    since = f"{CLOCK - 1}.000000"
    server.answer("date +%s", f"{CLOCK}\n".encode())
    server.add_sequence(
        "logcat",
        ShellScript(exit_status=None, expect_t=since),
        staying(name="c1", t=since),
    )
    s = begin(server, mode, since="now", reconnect=60.0).start()
    assert server.wait_reached("c1")  # the second connection carried the same -T
    token = server.logged[0][1]
    server.inject(marker_line(token) + logline(1, message="m1"))
    assert take(s, 1) == ["m1"]
    assert only(s).reconnects == 1


@pytest.mark.parametrize(
    ("failing", "exit_status", "message"),
    [
        ("clock", 1, "exit status 1"),
        ("clock_text", 0, "it printed 'soon'"),
        ("clock_hangs", None, "did not finish within 0.3 seconds"),
        ("marker", 3, "exit status 3"),
    ],
)
def test_since_now_fails_the_start_when_a_device_command_fails(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    failing: str,
    exit_status: int | None,
    message: str,
) -> None:
    monkeypatch.setattr(_marks, "COMMAND_LIMIT", 0.3)
    clock = ("stdout", f"{CLOCK}\n".encode())
    odd = ("stderr", b"date: odd\n")
    if failing == "clock":
        script = ShellScript(steps=[odd], exit_status=1)
    elif failing == "clock_text":
        script = ShellScript(steps=[("stdout", b"soon\n"), odd])
    elif failing == "clock_hangs":
        script = ShellScript(steps=[Wait("never")])
    else:  # the first device's marker is written, the second one's fails
        script = ShellScript(steps=[clock])
        server.add_sequence(
            "log -t", ShellScript(), ShellScript(steps=[odd], exit_status=3)
        )
    server.add_sequence("date +%s", script, ShellScript(steps=[clock]))
    s = begin(server, mode, "a", "b", since="now")
    with pytest.raises(LogprobeError) as info:
        s.start()
    error = info.value
    assert error.code == "device_command_failed"
    assert error.details["serial"] == ("b" if failing == "marker" else "a")
    assert error.details["exit_status"] == exit_status
    assert message in str(error)
    command = error.details["command"]
    assert isinstance(command, list)
    assert command[:2] == (["log", "-t"] if failing == "marker" else ["date", "+%s"])
    # what the command wrote to stderr is kept (it is empty for a hang)
    assert error.details["stderr"] == (
        [] if failing == "clock_hangs" else ["date: odd"]
    )
    assert all("logcat" not in program_of(r.command) for r in server.records)
    assert stream_threads() == []
    assert s.summary.devices[1 if failing == "marker" else 0].error is error


def test_since_now_fails_the_stream_when_the_start_marker_does_not_come_back(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_marks, "START_WAIT", 0.1)
    staying_open(server, logline(0, message="old"))
    s = begin(server, mode, since="now").start()
    got: list[str] = []
    with pytest.raises(LogprobeError) as info:
        got.extend(entry.message for entry in s)
    assert got == []
    assert info.value.code == "device_command_failed"
    assert info.value.details["serial"] == "a"
    assert info.value.details["command"] == log_commands(server)[0]
    assert only(s).error is info.value


@pytest.mark.parametrize("how", ["slow backoff", "refused", "silent handshake"])
def test_the_start_marker_wait_also_runs_through_the_reconnects(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    monkeypatch.setattr(_marks, "START_WAIT", 0.3)
    delay = 5.0 if how == "slow backoff" else 0.05
    monkeypatch.setattr(_resume, "backoff", lambda _failures: delay)
    server.answer("date +%s", f"{CLOCK}\n".encode())
    server.add_sequence("logcat", lost(Wait("cut")))
    s = begin(server, mode, since="now", reconnect=60.0).start()
    assert server.wait_reached("cut")
    if how == "refused":
        server.fail["host:transport:a"] = "protocol fault"
    elif how == "silent handshake":
        server.silent_prefix = "shell,v2"  # the adb server hangs on the reconnect
    began = time.monotonic()
    server.release("cut")
    with pytest.raises(LogprobeError) as info:
        drain(s)
    # the error is device_command_failed within the wait, not device_lost later
    assert info.value.code == "device_command_failed"
    assert time.monotonic() - began < 0.3 + PROMPT
    assert only(s).reconnects == 0


# --- stop(flush=) -------------------------------------------------------------------


def flushing(server: FakeAdbServer, mode: Mode, first: bytes = b"") -> StreamLike:
    """A started stream whose logcat sends ``first`` and then stays open."""
    server.add_sequence("logcat", hold("a", first))
    s = begin(server, mode).start()
    assert server.wait_reached("hold-a")  # the connection can take injected lines
    return s


def test_a_flush_on_a_silent_stream_is_done_at_once(
    server: FakeAdbServer, mode: Mode
) -> None:
    echo_markers(server)
    s = flushing(server, mode)
    began = time.monotonic()
    s.stop(flush=5)
    assert drain(s) == []
    assert time.monotonic() - began < PROMPT
    assert only(s).flush == "done"
    assert only(s).complete
    ((tag, token),) = server.logged
    assert (tag, token.startswith("flush-")) == ("logprobe", True)


def test_a_flush_delivers_every_line_before_its_marker_and_none_after_it(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    echo_markers(server, after=logline(900, message="after"))
    s = flushing(server, mode, lines(0, 3))
    s.stop(flush=5)
    assert drain(s) == names(0, 3)
    assert only(s).flush == "done"
    assert only(s).entries == 3  # the line after the marker was read but not delivered


def test_a_flush_whose_marker_never_arrives_times_out_without_an_error(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    s = flushing(server, mode, lines(0, 2))
    wait_until(lambda: only(s).entries == 2)
    began = time.monotonic()
    s.stop(flush=0.15)
    assert drain(s) == names(0, 2)
    elapsed = time.monotonic() - began
    assert 0.12 < elapsed < 0.15 + PROMPT  # a Windows clock tick is 15.6 ms
    assert only(s).flush == "timed_out"
    assert only(s).error is None
    assert not s.summary.complete
    s.join(GUARD)  # and nothing is raised


def test_a_flush_times_out_in_time_while_unrelated_lines_keep_flowing(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    s = flushing(server, mode)
    stop_feeding = threading.Event()

    def feed() -> None:
        for number in itertools.count():
            if stop_feeding.is_set():
                return
            server.inject(logline(number % 900, message=f"n{number}"))
            stop_feeding.wait(0.002)

    feeder = threading.Thread(target=feed)
    feeder.start()
    try:
        wait_until(lambda: only(s).entries > 0)
        began = time.monotonic()
        s.stop(flush=0.15)
        got = drain(s)
    finally:
        stop_feeding.set()
        feeder.join()
    assert got  # lines flowed all the time, so the wait was not a silent one
    assert time.monotonic() - began < 0.15 + PROMPT
    assert only(s).flush == "timed_out"


def test_a_flush_requested_while_a_reader_waits_on_a_full_queue_gets_every_line(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    echo_markers(server, after=logline(30, message="late"))  # follows the marker
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[
                ("stdout", lines(0, 10)),
                Wait("second"),
                ("stdout", lines(10, 10)),
                Wait("end", live=True),
            ]
        ),
    )
    s = begin(server, mode, buffer_lines=1).start()
    outbox = s._core.outbox
    wait_until(lambda: outbox.pending_lines == 10)
    server.release("second")
    wait_until(lambda: outbox.waiting == 1)  # the reader waits for room
    assert server.wait_reached("end")  # every line is on its way before the marker
    began = time.monotonic()
    s.stop(flush=0.2)
    # The blocked reader notices the request: its marker is written although
    # the consumer takes nothing, so what is logged later is not in the flush.
    wait_until(lambda: server.logged)
    assert time.monotonic() - began < PROMPT  # the marker came at once
    time.sleep(0.4)  # a consumer that takes nothing for twice the budget
    got = drain(s)
    assert time.monotonic() - began > 0.3  # the wall time passed the budget
    assert got == names(0, 20)
    assert only(s).flush == "done"
    assert outbox.backpressure()["a"] > 0.3  # the wait for room is not the budget's


def test_a_flush_under_back_pressure_from_a_slow_consumer_gets_every_line(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    budget = 0.1
    count = 60
    mode.patch_read_size(monkeypatch, 80)  # about one line a chunk
    staying_open(server)
    s = begin(server, mode, since="now", buffer_lines=4).start()
    assert server.wait_reached("go")
    echo_markers(server)  # the flush marker follows the lines below
    start_marker = server.logged[0][1]
    server.inject(marker_line(start_marker))
    for n in range(count):
        server.inject(logline(n, message=f"m{n}"))
    got: list[str] = []
    began = time.monotonic()
    timer = guard(s)
    for number, entry in enumerate(s):
        got.append(entry.message)
        if number == 0:
            s.stop(flush=budget)
        time.sleep(0.004)  # the consumer is slower than the reader
    timer.cancel()
    assert got == [f"m{n}" for n in range(count)]
    assert only(s).flush == "done"
    assert time.monotonic() - began > budget
    # the waits for room add up to more than the budget, which they do not use
    assert s._core.outbox.backpressure()["a"] > budget


@pytest.mark.parametrize("how", ["stop", "kill"])
def test_a_stop_or_a_kill_cancels_a_flush_that_is_waiting(
    server: FakeAdbServer, mode: Mode, how: str
) -> None:
    s = flushing(server, mode)
    s.stop(flush=60)
    wait_until(lambda: server.logged)  # the marker is written and never comes back
    began = time.monotonic()
    getattr(s, how)()
    s.join(GUARD)
    assert time.monotonic() - began < PROMPT
    assert only(s).flush == "cancelled"
    assert only(s).error is None
    assert not s.summary.complete


def test_a_flush_after_a_stop_does_nothing(server: FakeAdbServer, mode: Mode) -> None:
    s = flushing(server, mode)
    s.stop()
    s.stop(flush=60)
    s.join(GUARD)
    assert only(s).flush == "not_requested"
    assert server.logged == []  # no marker was written


def test_a_second_flush_does_not_change_the_first(
    server: FakeAdbServer, mode: Mode
) -> None:
    s = flushing(server, mode)
    s.stop(flush=0.1)
    s.stop(flush=60)
    began = time.monotonic()
    s.join(GUARD)
    assert time.monotonic() - began < 0.1 + PROMPT
    assert only(s).flush == "timed_out"


@pytest.mark.usefixtures("fast_backoff")
def test_a_reconnect_that_hangs_ends_with_the_flush_budget(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    server.add_sequence(
        "logcat",
        lost(("stdout", at(0, "m0")), Wait("cut", live=True)),
    )
    s = begin(server, mode, reconnect=60.0).start()
    wait_until(lambda: only(s).entries == 1)
    began = time.monotonic()
    s.stop(flush=0.3)
    wait_until(lambda: server.logged)  # the marker is written, and never comes back
    server.silent_prefix = "shell,v2"  # the adb server hangs on the next connection
    server.release("cut")
    assert drain(s) == ["m0"]
    assert time.monotonic() - began < 0.3 + PROMPT  # not the 10 s of the adb layer
    assert only(s).flush == "timed_out"
    assert only(s).error is None


@pytest.mark.usefixtures("fast_backoff")
def test_a_flush_requested_during_a_silent_handshake_ends_with_its_budget(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    server.add_sequence(
        "logcat",
        lost(("stdout", at(0, "m0")), Wait("cut", live=True)),
    )
    s = begin(server, mode, reconnect=60.0).start()
    wait_until(lambda: only(s).entries == 1)
    server.silent_prefix = "shell,v2"  # the adb server hangs on the next connection
    server.release("cut")
    assert server.silent_started.wait(GUARD)  # the handshake is under way
    began = time.monotonic()
    s.stop(flush=0.3)
    assert drain(s) == ["m0"]
    assert time.monotonic() - began < 0.3 + PROMPT  # not the 10 s of the adb layer
    assert only(s).flush == "timed_out"
    assert only(s).error is None


def test_a_marker_command_that_exits_with_an_error_fails_the_flush(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    server.answer("log -t", exit_status=1)
    s = flushing(server, mode, lines(0, 1))
    wait_until(lambda: only(s).entries == 1)  # the line is read before the request
    s.stop(flush=60)
    assert drain(s) == ["m0"]
    assert only(s).flush == "failed"
    assert only(s).error is None
    assert not s.summary.complete


def test_a_device_that_ended_before_the_request_keeps_its_end(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    server.add_sequence("logcat", ShellScript(steps=[("stdout", lines(0, 1))]))
    s = begin(server, mode).start()
    with pytest.raises(LogprobeError) as info:
        s.join(GUARD)
    assert info.value.code == "device_lost"
    s.stop(flush=1)
    assert only(s).flush == "not_requested"
    assert only(s).error is info.value


def test_a_flush_requested_before_the_start_marker_waits_for_it(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    echo_markers(server)
    staying_open(server)
    s = begin(server, mode, since="now").start()
    assert server.wait_reached("go")
    s.stop(flush=60)
    token = server.logged[0][1]
    server.inject(logline(1, message="old") + marker_line(token, 2) + lines(3, 2))
    assert drain(s) == names(3, 2)
    assert only(s).flush == "done"
    assert [words[-1][:6] for words in log_commands(server)] == ["start-", "flush-"]


# --- a flush across a lost connection -----------------------------------------------


@pytest.mark.usefixtures("fast_backoff")
def test_a_marker_that_comes_back_in_the_replay_ends_the_flush(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    server.add_sequence(
        "logcat",
        lost(("stdout", at(0, "m0") + at(1, "m1")), Wait("cut", live=True)),
        staying(("stdout", at(0, "m0") + at(1, "m1")), name="c1", t=expect_t(1)),
    )
    s = begin(server, mode, reconnect=60.0).start()
    wait_until(lambda: only(s).entries == 2)
    s.stop(flush=60)
    wait_until(lambda: server.logged)  # written on the first connection, never seen
    token = server.logged[0][1]
    server.release("cut")
    assert server.wait_reached("c1")
    server.inject(at(2, token, tag="logprobe"))  # the device replays it
    assert drain(s) == ["m0", "m1"]
    assert only(s).flush == "done"
    assert only(s).reconnects == 1
    assert len(server.logged) == 1  # it was not written again


@pytest.mark.usefixtures("fast_backoff")
def test_a_marker_that_could_not_be_written_is_written_again_after_the_resume(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    server.add_sequence("log -t", ShellScript(exit_status=None), ShellScript())
    server.add_sequence(
        "logcat",
        lost(("stdout", at(0, "m0")), Wait("cut", live=True)),
        staying(("stdout", at(0, "m0")), name="c1", t=expect_t(0)),
    )
    counter = itertools.count(1)

    def echo(tag: str, message: str) -> bytes:
        server.wait_reached("c1")  # the new connection can take the line
        return at(next(counter), message, tag=tag)

    server.echo_logged = echo
    s = begin(server, mode, reconnect=60.0).start()
    wait_until(lambda: only(s).entries == 1)
    s.stop(flush=60)
    wait_until(lambda: len(log_commands(server)) == 1)  # the first write was dropped
    server.release("cut")
    assert drain(s) == ["m0"]
    assert only(s).flush == "done"
    first, second = log_commands(server)
    assert first == second  # the same marker
    assert len(server.logged) == 1  # and only the second write went through


def test_the_wait_before_a_reconnect_uses_up_the_flush_budget(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(_resume, "backoff", lambda _failures: 30.0)
    server.add_sequence("logcat", lost(("stdout", lines(0, 1))))
    with caplog.at_level(logging.WARNING, logger="logprobe"):
        s = begin(server, mode, reconnect=60.0).start()
        wait_until(
            lambda: any("reconnecting in" in r.getMessage() for r in caplog.records)
        )
    began = time.monotonic()
    s.stop(flush=0.15)  # the reader sleeps for 30 s, so only the budget can end it
    s.join(GUARD)
    assert time.monotonic() - began < 0.15 + PROMPT
    assert only(s).flush == "timed_out"
    assert only(s).error is None


def test_a_reconnect_handshake_is_limited_by_the_flush_budget_alone(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The adb client's limit per step must not cut a handshake that has a deadline."""
    monkeypatch.setattr(_resume, "backoff", lambda _failures: 0.01)
    mode.limit_adb_steps(monkeypatch, 0.2)
    server.add_sequence("logcat", lost(("stdout", lines(0, 1)), Wait("cut", live=True)))
    s = begin(server, mode, reconnect=0.3).start()
    wait_until(lambda: only(s).entries == 1)
    s.stop(flush=1.0)
    wait_until(lambda: server.logged)  # the marker went to the first connection
    server.silent_prefix = "shell,v2"  # the new connection never answers
    server.release("cut")
    assert drain(s) == names(0, 1)
    assert only(s).error is None
    assert only(s).flush == "timed_out"


@pytest.mark.parametrize("ending", ["stop", "kill"])
def test_a_flush_that_a_later_stop_or_kill_follows_on_the_same_thread_is_cancelled(
    server: FakeAdbServer, mode: Mode, ending: str
) -> None:
    server.add_sequence("logcat", hold("a", lines(0, 2)))
    s = begin(server, mode).start()
    wait_until(lambda: only(s).entries == 2)
    s.stop(flush=60)
    getattr(s, ending)()
    s.join(GUARD)
    assert only(s).flush == "cancelled"


@pytest.mark.usefixtures("fast_backoff")
def test_a_cut_off_during_a_slow_flush_resumes_with_one_gap_and_no_lost_line(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    first = b"".join(at(n, f"m{n}") for n in range(6))
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[("stdout", first), Wait("cut"), ("stderr", EOF_TEXT)],
            exit_status=1,
        ),
        # The replay starts at m4 and lacks it: a line that was read is gone.
        staying(Omit(at(4, "m4")), ("stdout", at(5, "m5")), name="c1", t=expect_t(5)),
    )
    s = begin(server, mode, reconnect=60.0, buffer_lines=2).start()
    got: list[Gap | LogEntry | str] = []
    timer = guard(s)
    for number, item in enumerate(s.items()):
        got.append(item if isinstance(item, Gap) else item.message)
        if number == 0:
            s.stop(flush=60)
            wait_until(lambda: server.logged)  # the marker went to the first connection
            token = server.logged[0][1]
            server.release("cut")
            assert server.wait_reached("c1")
            server.inject(
                at(6, "m6") + at(7, "m7") + at(8, token, tag="logprobe") + at(9, "x")
            )
        time.sleep(0.005)
    timer.cancel()
    gap = got[6]
    assert isinstance(gap, Gap)
    assert (gap.reason, gap.cause) == ("ring_rotated", "released")
    assert [x for x in got if x is not gap] == [f"m{n}" for n in range(8)]
    assert only(s).flush == "done"
    assert (only(s).gaps, only(s).reconnects) == (1, 1)


# --- the with block and several devices ----------------------------------------------


@pytest.mark.parametrize("body_fails", [False, True])
def test_the_with_exit_in_the_on_entry_form_waits_for_a_flush_and_cancels_it_on_error(
    server: FakeAdbServer, *, body_fails: bool
) -> None:
    server.add_sequence("logcat", hold("a", lines(0, 3)))
    (device,) = attach(server, "a")
    got: list[str] = []

    def deliver_the_marker() -> None:
        wait_until(lambda: server.logged)
        server.inject(marker_line(server.logged[0][1]) + logline(9, message="after"))

    deliverer = threading.Thread(target=deliver_the_marker)
    if not body_fails:
        deliverer.start()
    s = device.stream(on_entry=lambda e: got.append(e.message), reconnect=0.0)
    try:
        with contextlib.suppress(ValueError), s:
            assert server.wait_reached("hold-a")
            s.stop(flush=60)
            if body_fails:
                msg = "body"
                raise ValueError(msg)
    finally:
        if not body_fails:
            deliverer.join()
    if body_fails:
        assert only(s).flush == "cancelled"
    else:
        assert only(s).flush == "done"
        assert got == names(0, 3)  # and nothing after the marker


def test_two_devices_flush_with_their_own_markers(
    server: FakeAdbServer, mode: Mode
) -> None:
    echo_markers(server, after=logline(900, message="after"))
    devices = attach(server, "a", "b")
    for serial in ("a", "b"):
        server.add_sequence(
            "logcat",
            hold(serial, b"".join(logline(n, tag=serial) for n in range(3))),
            serial=serial,
        )
    s = mode.stream(devices, reconnect=0.0).start()
    assert server.wait_reached("hold-a")
    assert server.wait_reached("hold-b")
    s.stop(flush=5)
    timer = guard(s)
    got = [(entry.serial, entry.message) for entry in s]
    timer.cancel()
    for serial in ("a", "b"):
        assert [m for who, m in got if who == serial] == names(0, 3)
    assert [d.flush for d in s.summary.devices] == ["done", "done"]
    tokens = [token for _, token in server.logged]
    assert len(set(tokens)) == 2
    assert all(token.startswith("flush-") for token in tokens)


def test_the_with_exit_of_an_iteration_cancels_a_flush_nobody_will_wait_for(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    server.add_sequence("logcat", hold("a"))
    began = time.monotonic()
    with begin(server, mode) as s:
        assert server.wait_reached("hold-a")
        s.stop(flush=60)  # the marker never comes back and nobody iterates
    assert time.monotonic() - began < PROMPT
    assert only(s).flush == "cancelled"
