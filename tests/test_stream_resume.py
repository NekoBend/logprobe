"""Reconnection of the blocking and the asyncio stream, against the fake adb server.

A test that requests the ``mode`` fixture runs against both versions from one
body; the two that do not drive the blocking reader through scripted sockets and
a scripted clock, and say so.

Every connection of a scenario has its own script. Times of the log lines are
seconds after ``BASE``; the ``-T`` value each reconnect sends is checked with
``t_value_of`` through the fake's connection records. Real waits are shortened
through private seams (the backoff, the receive tick, the idle time of the
resume check), never with long sleeps.
"""

from __future__ import annotations

import logging
import subprocess
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from logprobe import Gap, LogEntry, LogprobeError, _adb, _astream, _resume, _stream
from logprobe import _feed as feed_module
from logprobe._resume import t_arg
from tests.fake_adb_server import Cut, FakeAdbServer, Omit, ShellScript, Wait, packet
from tests.test_stream import (
    GUARD,
    PROMPT,
    attach,
    hold,
    stream_threads,
    wait_threads_gone,
    wait_until,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from tests.fake_adb_server import Step
    from tests.stream_modes import Mode, StreamLike


pytestmark = pytest.mark.filterwarnings("error::ResourceWarning")

BASE = datetime(2026, 11, 16, 3, 0, 0, tzinfo=UTC)
EOF_TEXT = b"logcat: Unexpected EOF!\n"
FAST = 0.01  # the backoff the reader uses in the tests that wait for it


def at(seconds: float, message: str = "x", tag: str = "T") -> bytes:
    """One log line ``seconds`` after ``BASE``, in the live wire format."""
    moment = BASE + timedelta(seconds=seconds)
    clock = f"{moment:%Y-%m-%d %H:%M:%S}.{moment.microsecond:06d} +0000"
    return f"{clock}  1000   100   100 I {tag}: {message}\n".encode()


def expect_t(cursor: float) -> str:
    """The ``-T`` value a reconnect sends when the newest line read is at ``cursor``."""
    return t_arg(BASE + timedelta(seconds=cursor) - feed_module.OVERLAP)


def released(*steps: Step) -> ShellScript:
    """A logcat that sends ``steps`` and is then cut off by logd."""
    return ShellScript(steps=[*steps, ("stderr", EOF_TEXT)], exit_status=1)


def lost(*steps: Step) -> ShellScript:
    """A connection that sends ``steps`` and then closes without an exit packet."""
    return ShellScript(steps=list(steps), exit_status=None)


def staying(*steps: Step, name: str = "end", t: str | None = None) -> ShellScript:
    """A logcat that sends ``steps`` and then stays open until the client closes."""
    return ShellScript(steps=[*steps, Wait(name, live=True)], expect_t=t)


@pytest.fixture(autouse=True)
def no_threads_left() -> Iterator[None]:
    before = stream_threads()
    yield
    wait_until(lambda: stream_threads() == before, GUARD)


@pytest.fixture
def fast_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_resume, "backoff", lambda _failures: FAST)


@pytest.fixture(autouse=True)
def fast_tick(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the readers' receive tick short, so a stop is noticed quickly."""
    monkeypatch.setattr(_stream, "TICK", 0.02)
    monkeypatch.setattr(_astream, "TICK", 0.02)


@pytest.fixture
def fast_idle(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the idle time of the resume check short."""
    monkeypatch.setattr(_resume, "RESUME_IDLE", 0.05)


def watched(s: StreamLike) -> threading.Timer:
    """Kill ``s`` if a test hangs (a guard only; the timer is cancelled)."""
    timer = threading.Timer(GUARD, s.kill)
    timer.daemon = True
    timer.start()
    return timer


def run(s: StreamLike, count: int) -> tuple[list[LogEntry | Gap], LogprobeError | None]:
    """Take items until ``count`` arrived, then stop the stream and take the rest.

    The scripts end in a connection that stays open, so everything the stream
    could still deliver comes in the same chunk as the last expected item; an
    extra item shows up in the result. With ``count`` 0 nothing stops the
    stream: it must end by itself.
    """
    timer = watched(s)
    items: list[LogEntry | Gap] = []
    error: LogprobeError | None = None
    try:
        for item in s.items():
            items.append(item)
            if len(items) == count:
                s.stop()
        s.join()
    except LogprobeError as raised:
        error = raised
    finally:
        timer.cancel()
    return items, error


def shape(items: list[LogEntry | Gap]) -> list[str]:
    """Messages of entries and ``reason/cause`` of gaps, in order."""
    return [
        f"{item.reason}/{item.cause}" if isinstance(item, Gap) else item.message
        for item in items
    ]


def start(
    server: FakeAdbServer, mode: Mode, *, reconnect: float = 60.0, serial: str = "a"
) -> StreamLike:
    (device,) = attach(server, serial)
    return mode.device_stream(device, reconnect=reconnect).start()


# --- connections that logd cut off ----------------------------------------------------


@pytest.mark.parametrize("reconnect", [60.0, 0.0])
def test_a_cut_off_whose_lines_all_come_back_reports_nothing(
    server: FakeAdbServer,
    mode: Mode,
    reconnect: float,
    caplog: pytest.LogCaptureFixture,
) -> None:
    server.add_sequence(
        "logcat",
        released(("stdout", at(0, "m0") + at(1, "m1") + at(2, "m2"))),
        staying(("stdout", at(1, "m1") + at(2, "m2") + at(3, "m3"))),
    )
    with caplog.at_level(logging.WARNING, logger="logprobe"):
        s = start(server, mode, reconnect=reconnect, serial="dev-7")
        items, error = run(s, 4)
    assert error is None
    assert shape(items) == ["m0", "m1", "m2", "m3"]
    assert server.records[1].t_value == expect_t(2)
    summary = s.summary.devices[0]
    assert (summary.reconnects, summary.gaps, summary.lost, summary.lines) == (
        1,
        0,
        0,
        4,
    )
    assert any(
        "dev-7" in r.getMessage() and "released" in r.getMessage()
        for r in caplog.records
    )


def test_lines_that_do_not_come_back_make_a_ring_rotated_gap_before_the_next_line(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    server.add_sequence(
        "logcat",
        released(("stdout", at(0, "m0") + at(0.5, "m1") + at(1, "m2") + at(2, "m3"))),
        staying(
            Omit(at(1, "m2")), ("stdout", at(2, "m3") + at(3, "m4")), t=expect_t(2)
        ),
    )
    s = start(server, mode)
    items, error = run(s, 6)
    assert error is None
    assert shape(items) == ["m0", "m1", "m2", "m3", "ring_rotated/released", "m4"]
    gap = items[4]
    assert isinstance(gap, Gap)
    assert (gap.serial, gap.lost, gap.start_at) == (
        "a",
        None,
        BASE + timedelta(seconds=1),
    )
    assert gap.detected_at.tzinfo is not None
    summary = s.summary.devices[0]
    assert (summary.gaps, summary.lost, summary.reconnects) == (1, 0, 1)
    assert server.expected_loss() == at(1, "m2")


def test_a_logcat_that_ended_by_itself_is_resumed_at_once(
    server: FakeAdbServer, mode: Mode, caplog: pytest.LogCaptureFixture
) -> None:
    server.add_sequence(
        "logcat",
        ShellScript(steps=[("stdout", at(0, "m0"))], exit_status=0),
        staying(("stdout", at(0, "m0") + at(1, "m1"))),
    )
    with caplog.at_level(logging.WARNING, logger="logprobe"):
        s = start(server, mode)
        items, error = run(s, 2)
    assert error is None
    assert shape(items) == ["m0", "m1"]
    assert s.summary.devices[0].reconnects == 1
    assert any("reconnecting in 0 s" in r.getMessage() for r in caplog.records)


def test_a_failing_first_connection_is_not_resumed_even_with_a_budget(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    server.add_sequence(
        "logcat", ShellScript(steps=[("stderr", b"usage\n")], exit_status=2)
    )
    s = start(server, mode, reconnect=60.0)
    items, error = run(s, 1)
    assert items == []
    assert error is not None
    assert error.code == "logcat_failed"
    assert len(server.records) == 1


# --- lost connections ----------------------------------------------------------------


@pytest.mark.usefixtures("fast_backoff")
def test_a_late_line_older_than_the_cursor_is_delivered_once_without_a_gap(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    server.add_sequence(
        "logcat",
        lost(("stdout", at(10, "A"))),
        staying(("stdout", at(10, "A") + at(9.914, "B") + at(11, "C")), t=expect_t(10)),
    )
    s = start(server, mode)
    items, error = run(s, 3)
    assert error is None
    assert shape(items) == ["A", "B", "C"]
    assert server.records[1].t_value == t_arg(BASE + timedelta(seconds=9))


@pytest.mark.usefixtures("fast_backoff")
def test_a_device_that_is_away_for_a_while_is_resumed_when_it_returns(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    server.add_sequence(
        "logcat",
        lost(("stdout", at(0, "m0"))),
        staying(("stdout", at(0, "m0") + at(1, "m1"))),
    )
    (device,) = attach(server, "a")
    present = list(server.devices)
    waits: list[int] = []

    def away_then_back(failures: int) -> float:
        waits.append(failures)
        if len(waits) == 1:
            server.devices = []  # gone when the first attempt comes
        else:
            server.devices = present  # back before the second
        return FAST

    monkeypatch.setattr(_resume, "backoff", away_then_back)
    s = mode.device_stream(device).start()
    items, error = run(s, 2)
    assert error is None
    assert shape(items) == ["m0", "m1"]
    assert waits == [0, 1]
    assert server.requests.count("host:transport:a") == 3


@pytest.mark.usefixtures("fast_backoff")
def test_a_device_that_does_not_come_back_in_time_ends_the_stream_with_device_lost(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    server.add_sequence("logcat", lost(("stdout", at(0, "m0"))))
    (device,) = attach(server, "a")
    original = _resume.backoff

    def vanish(failures: int) -> float:
        server.devices = []
        return original(failures)

    monkeypatch.setattr(_resume, "backoff", vanish)
    s = mode.device_stream(device, reconnect=0.15).start()
    items, error = run(s, 0)
    assert shape(items) == ["m0"]
    assert error is not None
    assert error.code == "device_lost"
    assert error.details["serial"] == "a"
    assert isinstance(error.__cause__, LogprobeError)
    assert error.__cause__.code == "device_not_found"
    assert s.summary.devices[0].error is error


def test_an_unreachable_server_is_adb_server_unavailable_and_is_never_started(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    server.add_sequence("logcat", lost(("stdout", at(0, "m0"))))
    (device,) = attach(server, "a")
    stopped = threading.Event()

    def after_server_stop(_failures: int) -> float:
        assert stopped.wait(GUARD)
        return FAST

    def must_not_run(*_args: object, **_kwargs: object) -> None:
        pytest.fail("a reconnect tried to start an adb server")

    monkeypatch.setattr(_resume, "backoff", after_server_stop)
    monkeypatch.setattr(_adb, "ensure_server", must_not_run)
    monkeypatch.setattr(subprocess, "Popen", must_not_run)
    s = mode.device_stream(device, reconnect=0.15).start()
    assert server.wait_done(0)
    server.stop()
    stopped.set()
    items, error = run(s, 0)
    assert shape(items) == ["m0"]
    assert error is not None
    assert error.code == "adb_server_unavailable"
    assert error.details["serial"] == "a"


def test_a_server_that_answers_with_a_failure_ends_the_stream_with_adb_error(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    server.add_sequence("logcat", lost(("stdout", at(0, "m0"))))
    (device,) = attach(server, "a")

    def break_the_server(_failures: int) -> float:
        server.fail["host:transport:a"] = "protocol fault"
        return FAST

    monkeypatch.setattr(_resume, "backoff", break_the_server)
    s = mode.device_stream(device, reconnect=0.15).start()
    items, error = run(s, 0)
    assert shape(items) == ["m0"]
    assert error is not None
    assert error.code == "adb_error"
    assert "protocol fault" in error.message


@pytest.mark.usefixtures("fast_backoff")
def test_lines_of_the_same_microsecond_are_dropped_by_occurrence(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    same = at(5, "same")
    server.add_sequence(
        "logcat",
        lost(("stdout", at(0, "old") + at(4.6, "m1") + same * 3)),
        staying(("stdout", at(0, "old") + at(4.6, "m1") + same * 4), t=expect_t(5)),
    )
    s = start(server, mode)
    items, error = run(s, 6)
    assert error is None
    # the older line the first connection read is dropped as well; the
    # fourth identical line is new
    assert shape(items) == ["old", "m1", "same", "same", "same", "same"]
    assert s.summary.devices[0].gaps == 0


@pytest.mark.usefixtures("fast_backoff")
def test_one_replayed_line_missing_from_three_identical_ones_is_a_gap(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    same = at(5, "same")
    server.add_sequence(
        "logcat",
        released(("stdout", same * 3)),
        staying(("stdout", same * 2 + at(6, "n")), t=expect_t(5)),
    )
    s = start(server, mode)
    items, error = run(s, 5)
    assert error is None
    assert shape(items) == ["same", "same", "same", "ring_rotated/released", "n"]


@pytest.mark.usefixtures("fast_backoff", "fast_idle")
def test_a_short_history_is_reported_after_the_replay_stayed_silent(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(feed_module, "HISTORY_LINES", 3)
    first = ("a", 10.0), ("b", 10.2), ("c", 10.4), ("d", 10.5)
    steps: list[Any] = []
    for number, (name, moment) in enumerate(first):
        steps.append(("stdout", at(moment, name)))
        if number < len(first) - 1:
            steps.append(Wait(f"read-{number}"))
    server.add_sequence(
        "logcat",
        lost(*steps),
        # only what the history still holds comes back, then nothing
        staying(
            ("stdout", at(10.2, "b") + at(10.4, "c") + at(10.5, "d")),
            name="quiet",
            t=expect_t(10.5),
        ),
    )
    s = start(server, mode)
    timer = watched(s)
    items = s.items()
    got: list[LogEntry | Gap] = []
    for number in range(4):
        got.append(next(items))
        if number < 3:
            server.release(f"read-{number}")
    got.append(next(items))  # only the silence can end the check
    assert server.wait_reached("quiet", GUARD)
    assert server.inject(at(11, "n"), "a") == 1
    got.append(next(items))
    s.stop()
    s.join()
    timer.cancel()
    assert shape(got) == ["a", "b", "c", "d", "continuity_unknown/disconnected", "n"]


@pytest.mark.usefixtures("fast_backoff")
def test_a_clock_that_stepped_back_is_a_continuity_gap_before_the_old_line(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    server.add_sequence(
        "logcat",
        lost(("stdout", at(10, "A"))),
        staying(("stdout", at(10, "A") + at(3, "B")), t=expect_t(10)),
    )
    s = start(server, mode)
    items, error = run(s, 3)
    assert error is None
    assert shape(items) == ["A", "continuity_unknown/disconnected", "B"]


@pytest.mark.usefixtures("fast_backoff")
def test_a_connection_lost_during_the_check_starts_over_and_reports_one_gap(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    server.add_sequence(
        "logcat",
        lost(("stdout", at(10, "A") + at(10.5, "B"))),
        # an unread line older than the replay start; the check is not done
        # (A and B have not come back) when this connection is lost
        lost(("stdout", at(3, "D"))),
        staying(("stdout", at(10, "A") + at(10.5, "B") + at(11, "n"))),
    )
    s = start(server, mode)
    items, error = run(s, 5)
    assert error is None
    assert shape(items) == ["A", "B", "D", "continuity_unknown/disconnected", "n"]
    # the cursor did not move, so both reconnects start from the same time
    assert server.records[1].t_value == server.records[2].t_value == expect_t(10.5)
    summary = s.summary.devices[0]
    assert (summary.gaps, summary.reconnects) == (1, 2)


# --- the borders between connections --------------------------------------------------

_CAFE = at(1, "café ünï")


@pytest.mark.usefixtures("fast_backoff")
@pytest.mark.parametrize(
    "keep",
    [
        5 + _CAFE.index("é".encode()) + 1,  # inside a UTF-8 character
        5 + 30,  # inside the time stamp of a log line
        3,  # inside the header of the packet
    ],
    ids=["in a character", "in a line", "in a packet header"],
)
def test_bytes_of_a_cut_connection_are_never_joined_to_the_next(
    server: FakeAdbServer, mode: Mode, keep: int
) -> None:
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[("stdout", at(0, "m0")), Cut("stdout", _CAFE, keep)],
            exit_status=None,
        ),
        staying(("stdout", at(0, "m0") + _CAFE), t=expect_t(0)),
    )
    s = start(server, mode)
    items, error = run(s, 2)
    assert error is None
    assert shape(items) == ["m0", "café ünï"]
    assert s.summary.devices[0].unparsed == 0


def test_the_part_of_a_packet_that_arrived_is_delivered_when_the_device_is_lost(
    server: FakeAdbServer, mode: Mode
) -> None:
    both = at(1, "x") + at(2, "y")
    keep = 5 + len(at(1, "x")) + 3  # the packet header, all of x and a bit of y
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[("stdout", at(0, "m0")), Cut("stdout", both, keep)],
            exit_status=None,
        ),
    )
    s = start(server, mode, reconnect=0.0)
    items, error = run(s, 0)
    assert error is not None
    assert error.code == "device_lost"
    assert shape(items) == ["m0", "x"]
    assert s.summary.devices[0].lines == 2


# --- many connections, quick succession, the budget -----------------------------


def _open_descriptors() -> int | None:
    path = Path("/proc/self/fd")
    return len(list(path.iterdir())) if path.is_dir() else None


def test_twenty_reconnects_leave_no_thread_and_no_descriptor_behind(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_resume, "QUICK_END", -1.0)  # no cut-off counts as quick
    # lines two seconds apart: each reconnect replays only the newest one
    scripts = [released(("stdout", at(0, "m0")))]
    scripts += [
        released(("stdout", at(2 * k - 2, f"m{k - 1}") + at(2 * k, f"m{k}")))
        for k in range(1, 20)
    ]
    scripts.append(staying(("stdout", at(38, "m19") + at(40, "m20"))))
    server.add_sequence("logcat", *scripts)
    (device,) = attach(server, "a")
    assert server.wait_idle(GUARD)  # the server let go of the attach request
    before = _open_descriptors()
    s = mode.device_stream(device).start()
    items, error = run(s, 21)
    assert error is None
    assert shape(items) == [f"m{k}" for k in range(21)]
    summary = s.summary.devices[0]
    assert (summary.reconnects, summary.gaps) == (20, 0)
    assert len(server.records) == 21
    wait_threads_gone()
    assert server.wait_idle(GUARD)
    if before is not None:
        wait_until(lambda: _open_descriptors() == before)


def _api36_connection() -> ShellScript:
    """A connection logd cuts off at once, after the lines it writes about it."""
    logdr = "logdr: UID=2000 GID=2000 PID=9000 n tail=0 logMask=ff pid=0"
    return released(
        ("stdout", at(0, logdr, "logd") + at(0.1, "write error", "SocketClient"))
    )


def test_three_quick_cut_offs_end_with_logcat_failed_at_reconnect_zero(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    server.default_shell = _api36_connection()
    s = start(server, mode, reconnect=0.0)
    _, error = run(s, 0)
    assert error is not None
    assert error.code == "logcat_failed"
    assert error.details["stderr"] == ["logcat: Unexpected EOF!"]
    assert len(server.records) == 3
    # the lines logd wrote about each connection did not make it count as long
    assert s.summary.devices[0].reconnects == 2


@pytest.mark.usefixtures("fast_backoff")
def test_quick_cut_offs_use_up_the_budget_and_end_with_logcat_failed(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    server.default_shell = _api36_connection()
    s = start(server, mode, reconnect=0.15)
    _, error = run(s, 0)
    assert error is not None
    assert error.code == "logcat_failed"
    assert len(server.records) > 3


# --- the resume check counts only silence --------------------------------------


class _Clock:
    """A clock the scripted socket moves forward: ``time.monotonic`` for the test."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _SilentSocket:
    """Returns the given chunks; ``None`` is a receive timeout of 0.6 seconds."""

    def __init__(self, clock: _Clock, *chunks: bytes | None) -> None:
        self._clock = clock
        self._chunks = list(chunks)

    def settimeout(self, _timeout: float | None) -> None:
        pass

    def recv(self, _size: int) -> bytes:
        chunk = self._chunks.pop(0) if self._chunks else b""
        if chunk is None:
            self._clock.now += 0.6
            raise TimeoutError
        return chunk


class _Pipe:
    def __init__(self, sock: _SilentSocket) -> None:
        self.sock = sock

    def close(self) -> None:
        pass


def test_data_that_completes_no_line_still_counts_as_data_for_the_check(
    server: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    (device,) = attach(server, "a")
    unit = _stream._Unit(device, None, 0.0)
    unit.feeder.feed(at(10, "A"))
    plan = _resume.plan_resume(unit.feeder, "disconnected", BASE)
    unit.feeder.begin_connection(plan.check)
    clock = _Clock()
    monkeypatch.setattr(_stream, "monotonic", clock)
    line = at(10, "A")
    # a replayed line arrives in three pieces, each after 0.6 s of silence:
    # 1.2 s in all, but never 1 s (RESUME_IDLE) without data
    pieces = [packet(1, line[:20]), packet(1, line[20:40]), packet(1, line[40:])]
    sock = _SilentSocket(clock, pieces[0], None, pieces[1], None, pieces[2])
    run = _stream._Run(_Pipe(sock), "a", plan.check)  # ty: ignore[invalid-argument-type]
    core = _stream._Core([unit], _stream.Outbox(10, 1 << 20))
    _stream._read(core, unit, run)
    assert core.outbox.take(0) is None  # no gap, no line: A was a replay
    assert unit.feeder.duplicates == 1
    assert run.pending() is not None  # the check still waits for a new line


@pytest.mark.parametrize("request_name", ["request_stop", "request_kill"])
def test_a_check_that_ends_on_a_full_queue_does_not_receive_again_after_a_stop(
    server: FakeAdbServer, monkeypatch: pytest.MonkeyPatch, request_name: str
) -> None:
    monkeypatch.setattr(feed_module, "HISTORY_LINES", 3)
    (device,) = attach(server, "a")
    unit = _stream._Unit(device, None, 0.0)
    outbox = _stream.Outbox(1, 1 << 20)
    lines = [at(10 + k / 10, name) for k, name in enumerate("abcd")]
    core = _stream._Core([unit], outbox)
    chunks = unit.feeder.feed(b"".join(lines))
    _stream._enqueue(core, unit, chunks, time.perf_counter())  # queue full
    plan = _resume.plan_resume(unit.feeder, "disconnected", BASE)
    unit.feeder.begin_connection(plan.check)
    clock = _Clock()
    monkeypatch.setattr(_stream, "monotonic", clock)

    class Counting(_SilentSocket):
        extra = 0

        def recv(self, _size: int) -> bytes:
            if not self._chunks:
                Counting.extra += 1
            return super().recv(_size)

    # nothing comes back: the silence ends the check with a gap
    sock = Counting(clock, None, None)
    run = _stream._Run(_Pipe(sock), "a", plan.check)  # ty: ignore[invalid-argument-type]
    reader = threading.Thread(target=_stream._read, args=(core, unit, run))
    reader.start()
    wait_until(lambda: outbox.waiting == 1)
    getattr(outbox, request_name)()
    reader.join(GUARD)
    assert not reader.is_alive()
    assert Counting.extra == 0  # it looked at the flags before receiving again


# --- stop and kill while the reader is not reading ---------------------------------


class _Seen(logging.Handler):
    """Sets an event when the reader logs that it will reconnect."""

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.reconnecting = threading.Event()

    def emit(self, record: logging.LogRecord) -> None:
        if "reconnecting in" in record.getMessage():
            self.reconnecting.set()


@pytest.mark.parametrize("request_name", ["stop", "kill"])
@pytest.mark.parametrize("phase", ["backoff wait", "resume check", "half-empty wait"])
def test_stop_and_kill_end_the_reader_promptly_while_it_waits_or_checks(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    request_name: str,
    phase: str,
) -> None:
    mode.patch_ticks(monkeypatch, _adb.TICK)  # the real slice
    seen = _Seen()
    logger = logging.getLogger("logprobe")
    logger.addHandler(seen)
    try:
        if phase == "backoff wait":
            # the first backoff is a full second; the stream must not sit it out
            server.add_sequence("logcat", lost(("stdout", at(0, "m0"))))
        elif phase == "resume check":
            # the replay never brings the line back: the check stays pending
            server.add_sequence(
                "logcat",
                released(("stdout", at(0, "m0"))),
                staying(name="check"),
            )
        else:
            # an older logd: the reader closes the connection on the full queue
            # and then waits for it to be half empty
            monkeypatch.setattr(_resume, "STALL_AFTER", 0.1)
            server.answer("getprop ro.build.version.sdk", b"24\n")
            steps: list[Step] = [("stdout", at(0, "m0")), Wait("w0")]
            steps += [("stdout", at(1, "m1")), Wait("w1"), ("stdout", at(2, "m2"))]
            server.add_sequence("logcat", staying(*steps, name="held"))
        if phase == "half-empty wait":
            (device,) = attach(server, "a")
            s = mode.device_stream(device, detect_skips=True, buffer_lines=2).start()
            outbox = s._core.outbox
            wait_until(lambda: outbox.pending_lines == 1)
            server.release("w0")
            wait_until(lambda: outbox.pending_lines == 2)
            server.release("w1")
            assert server.wait_done(1, GUARD)  # the reader closed it, m2 is held
            assert next(iter(s)).message == "m0"  # m2 goes in: still above half
            wait_until(lambda: outbox._draining == 1)
        else:
            s = start(server, mode)
        if phase == "backoff wait":
            assert seen.reconnecting.wait(GUARD)
        elif phase == "resume check":
            assert server.wait_reached("check", GUARD)
        began = time.monotonic()
        getattr(s, request_name)()
        s.join(PROMPT)
        assert time.monotonic() - began < PROMPT
    finally:
        logger.removeHandler(seen)
    assert s.summary.devices[0].error is None
    # one logcat connection, or two; the half-empty wait follows the getprop
    assert len(server.records) == (1 if phase == "backoff wait" else 2)


@pytest.mark.usefixtures("fast_backoff")
@pytest.mark.parametrize("request_name", ["stop", "kill"])
def test_a_stop_during_a_failing_attempt_is_not_reported_as_an_error(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    request_name: str,
) -> None:
    server.add_sequence("logcat", released(("stdout", at(0, "m0"))))
    (device,) = attach(server, "a")
    holder: list[StreamLike] = []
    plan_resume = _stream.plan_resume
    failure = _adb.failure

    def vanish(*args, **kwargs):
        server.devices = []  # the attempt that follows is answered with FAIL
        return plan_resume(*args, **kwargs)

    def stopping(*args, **kwargs):
        getattr(holder[0], request_name)()  # after the last cancelled() check
        return failure(*args, **kwargs)

    monkeypatch.setattr(_stream, "plan_resume", vanish)
    mode.hook_failure(monkeypatch, stopping)
    s = mode.device_stream(device, reconnect=0)
    holder.append(s)
    s.start()
    timer = watched(s)
    items, error = run(s, 0)
    timer.cancel()
    if request_name == "stop":  # a kill may drop what is still queued
        assert shape(items) == ["m0"]
    assert error is None
    assert s.summary.devices[0].error is None


# --- several devices ------------------------------------------------------------------


def test_a_device_that_flows_is_not_held_up_by_another_one_reconnecting(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    in_backoff = threading.Event()
    let_go = threading.Event()
    mode.gate_backoff(monkeypatch, in_backoff, let_go)
    server.add_sequence(
        "logcat",
        lost(("stdout", at(0, "a0"))),
        staying(("stdout", at(0, "a0") + at(1, "a1"))),
        serial="a",
    )
    server.add_sequence("logcat", hold("b", at(0, "b0")), serial="b")
    devices = attach(server, "a", "b")
    s = mode.stream(devices, reconnect=60.0).start()
    timer = watched(s)
    items = s.items()
    first = [next(items), next(items)]
    assert {i.message for i in first if isinstance(i, LogEntry)} == {"a0", "b0"}
    assert in_backoff.wait(GUARD)  # a sits in the wait before its reconnect
    assert server.wait_reached("hold-b", GUARD)
    injected = time.monotonic()
    assert server.inject(at(1, "b1"), "b") == 1
    arrived = next(items)
    assert isinstance(arrived, LogEntry)
    assert (arrived.serial, arrived.message) == ("b", "b1")
    # A task that sat out a's wait without yielding would deliver b1 only after it.
    assert time.monotonic() - injected < PROMPT
    let_go.set()
    arrived = next(items)
    assert isinstance(arrived, LogEntry)
    assert (arrived.serial, arrived.message) == ("a", "a1")
    s.stop()
    s.join()
    timer.cancel()
    by_serial = {d.serial: d for d in s.summary.devices}
    assert by_serial["a"].reconnects == 1
    assert by_serial["b"].reconnects == 0
    assert by_serial["a"].error is None
    assert by_serial["b"].error is None


# --- the chatty notice through a stream -----------------------------------------------


def _notices() -> list[bytes]:
    from tests.device_facts import level_dir, load

    facts = load(level_dir(24), "C06")["facts"]["notice_details"]
    return [f"{each['line']}\n".encode() for each in facts[:3]]


def test_a_replayed_chatty_notice_makes_no_second_gap_and_the_summary_counts_once(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    notices = _notices()
    server.add_sequence(
        "logcat",
        released(("stdout", b"".join(notices))),
        staying(("stdout", b"".join(notices[1:]) + at(0, "n"))),
    )
    s = start(server, mode)
    items, error = run(s, 7)
    assert error is None
    kinds = ["Gap" if isinstance(item, Gap) else "entry" for item in items]
    assert kinds == ["Gap", "entry", "Gap", "entry", "Gap", "entry", "entry"]
    gaps = [item for item in items if isinstance(item, Gap)]
    assert [(g.reason, g.cause, g.lost) for g in gaps] == [
        ("device_reported", "notice", 4),
        ("device_reported", "notice", 26),
        ("device_reported", "notice", 2),
    ]
    summary = s.summary.devices[0]
    assert (summary.gaps, summary.lost, summary.reconnects) == (3, 32, 1)
    assert summary.entries == 4
