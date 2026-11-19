"""The log streams: arguments, lifecycle, limits and errors.

A test that requests the ``mode`` fixture runs twice, against ``LogStream`` and
against ``AsyncLogStream`` (through the adapter of ``tests.stream_modes``), from
one body. The tests that do not request it are about what only the blocking
stream has: ``on_entry``, reader threads, a ``KeyboardInterrupt`` that reaches a
blocking wait, and the private seams of the blocking client; tests that start
no stream are not parametrized either. What only the asyncio stream has is in
``test_astream``.
"""

from __future__ import annotations

import _thread
import contextlib
import gc
import logging
import math
import signal
import struct
import threading
import time
from typing import TYPE_CHECKING, Any

import pytest

import logprobe
from logprobe import (
    And,
    Anr,
    Crash,
    Device,
    Gap,
    LogEntry,
    LogprobeError,
    Not,
    Package,
    Tag,
    _astream,
    _stream,
    stream,
)
from logprobe._adb import TICK
from tests.fake_adb_server import FakeAdbServer, ShellScript, Wait, program_of

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterator, Sequence

    from logprobe._adb import ShellStream
    from tests.stream_modes import Mode, StreamLike


pytestmark = pytest.mark.filterwarnings("error::ResourceWarning")

# A reader or a start must react to a request within a tick; the bound allows
# for a slow machine.
LATE = TICK + 1.5
# The bound for a reaction to stop() or kill(): one tick plus two ticks of the
# Windows clock (15.6 ms each) and a fixed margin for a busy machine.
PROMPT = TICK + 2 * 0.016 + 0.2
# A Ctrl-C leaves a with block within a second.
CTRL_C = 1.0
GUARD = 10.0


# --- helpers -----------------------------------------------------------------


def logline(
    n: int, *, tag: str = "T", level: str = "I", message: str | None = None
) -> bytes:
    text = f"m{n}" if message is None else message
    return (
        f"2026-11-16 12:00:00.{n:06d} +0900  1000  100  101 {level} {tag}: {text}\n"
    ).encode()


def lines(first: int, count: int, *, tag: str = "T", level: str = "I") -> bytes:
    return b"".join(
        logline(n, tag=tag, level=level) for n in range(first, first + count)
    )


def names(first: int, count: int) -> list[str]:
    return [f"m{n}" for n in range(first, first + count)]


def wait_until(condition: Callable[[], object], timeout: float = GUARD) -> None:
    """Poll ``condition`` until it holds; a guard against hanging tests only."""
    deadline = time.monotonic() + timeout
    pause = threading.Event()
    while not condition():
        assert time.monotonic() < deadline, "condition not reached in time"
        pause.wait(0.005)


def stream_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name.startswith("logprobe-")]


def wait_threads_gone(timeout: float = LATE) -> None:
    wait_until(lambda: not stream_threads(), timeout)


def attach(fake: FakeAdbServer, *serials: str) -> list[Device]:
    devices = []
    for serial in serials:
        fake.add_device(serial)
        fake.features[serial] = ["shell_v2"]
        devices.append(Device(serial, adb_server=fake.address, start_server=False))
    return devices


def hold(serial: str, first: bytes = b"", name: str | None = None) -> ShellScript:
    """A logcat that sends ``first`` and then stays open until released."""
    steps: list[Any] = [("stdout", first)] if first else []
    steps.append(Wait(name or f"hold-{serial}", live=True))
    return ShellScript(steps=steps, exit_status=0)


def collect(s: StreamLike) -> tuple[list[str], BaseException | None]:
    got: list[str] = []
    try:
        got.extend(entry.message for entry in s)
    except LogprobeError as error:
        return got, error
    return got, None


@contextlib.contextmanager
def kill_if_hung(s: StreamLike, seconds: float = GUARD) -> Generator[None]:
    """Kill ``s`` when the body takes longer than ``seconds``; that fails the test."""
    fired = threading.Event()

    def kill() -> None:
        fired.set()
        s.kill()

    timer = threading.Timer(seconds, kill)
    timer.daemon = True
    timer.start()
    try:
        yield
    finally:
        timer.cancel()
    assert not fired.is_set(), "the guard had to kill the stream"


@pytest.fixture(autouse=True)
def no_threads_left() -> Iterator[None]:
    before = stream_threads()
    yield
    wait_until(lambda: stream_threads() == before, GUARD)


@pytest.fixture(autouse=True)
def single_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run the tests of this module without reconnecting.

    They are about one connection: a script that ends must end the stream. The
    tests of reconnection live in ``test_stream_resume`` and pass the value they
    mean.
    """
    for entry_point in (Device.stream, stream, Device.astream, logprobe.astream):
        monkeypatch.setitem(entry_point.__kwdefaults__, "reconnect", 0.0)  # ty: ignore[invalid-argument-type]


@contextlib.contextmanager
def real_sigint() -> Generator[None]:
    """Make ``_thread.interrupt_main`` raise KeyboardInterrupt in this thread."""
    if threading.current_thread() is not threading.main_thread():
        pytest.skip("needs the main thread")
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


@contextlib.contextmanager
def interrupt_main_when(ready: Callable[[], bool]) -> Generator[None]:
    """Send Ctrl-C to the main thread from another thread once ``ready()`` is true.

    ``ready`` must turn true only after the main thread has left this call's
    ``Thread.start()`` and reached the wait under test. ``Thread.start()``
    waits in a ``threading.Condition``, and an interrupt that lands after that
    wait let go of its lock but before the ``finally`` that takes it back is
    running makes the ``with`` block raise ``RuntimeError: release unlocked
    lock`` instead of KeyboardInterrupt. Without the GIL the sending thread
    runs at the same time as the main thread, so the interrupt can land there.
    A short pause after ``ready()`` gives the main thread time to block (best
    effort). On leaving, a sender that has not sent yet is cancelled, and the
    sender is joined while the caller's SIGINT handler is still in place.
    """
    cancel = threading.Event()
    sending = threading.Lock()  # cancel and send never overlap

    def send() -> None:
        deadline = time.monotonic() + GUARD
        while not ready():
            if cancel.wait(0.001) or time.monotonic() > deadline:
                return
        time.sleep(0.01)
        with sending:
            if not cancel.is_set():
                _thread.interrupt_main()

    sender = threading.Thread(target=send, daemon=True)
    sender.start()
    try:
        yield
    finally:
        # A Ctrl-C sent just before the cancel can still arrive here, once; it
        # must neither replace the test's own outcome nor skip the join.
        for _ in range(2):
            try:
                with sending:
                    cancel.set()
                sender.join(GUARD)
                break
            except KeyboardInterrupt:
                pass
        assert not sender.is_alive(), "the Ctrl-C sender did not end"


# --- arguments ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"buffer_lines": 0}, ValueError),
        ({"buffer_lines": -5}, ValueError),
        ({"buffer_lines": True}, TypeError),
        ({"buffer_lines": 10.0}, TypeError),
        ({"buffer_lines": "10"}, TypeError),
        ({"buffer_bytes": 65535}, ValueError),
        ({"buffer_bytes": False}, TypeError),
        ({"buffer_bytes": 1e6}, TypeError),
        ({"reconnect": True}, TypeError),
        ({"reconnect": None}, TypeError),
        ({"reconnect": "60"}, TypeError),
        ({"reconnect": float("nan")}, ValueError),
        ({"reconnect": -1}, ValueError),
        ({"reconnect": -0.001}, ValueError),
        ({"reconnect": float("-inf")}, ValueError),
        ({"reconnect": -(10**400)}, ValueError),
        ({"level": "X"}, ValueError),
        ({"tag": []}, ValueError),
        ({"detect_skips": 1}, TypeError),
        ({"detect_skips": "yes"}, TypeError),
        ({"detect_skips": None}, TypeError),
    ],
)
def test_arguments_are_checked_at_call_time(
    server: FakeAdbServer, mode: Mode, kwargs: dict[str, Any], error: type[Exception]
) -> None:
    (device,) = attach(server, "a")
    before = list(server.requests)
    with pytest.raises(error):
        mode.device_stream(device, **kwargs)
    with pytest.raises(error):
        mode.stream([device], **kwargs)
    assert server.requests == before


def test_on_entry_must_be_callable(server: FakeAdbServer) -> None:
    """Blocking only: the asyncio stream has no ``on_entry``."""
    (device,) = attach(server, "a")
    before = list(server.requests)
    with pytest.raises(TypeError):
        device.stream(on_entry="not callable")  # ty: ignore[invalid-argument-type]
    with pytest.raises(TypeError):
        stream([device], on_entry="not callable")  # ty: ignore[invalid-argument-type]
    assert server.requests == before


@pytest.mark.parametrize("reconnect", [0, 0.0, 1, 59.5, math.inf, 10**400])
def test_reconnect_accepts_zero_numbers_and_infinity(
    server: FakeAdbServer, mode: Mode, reconnect: float
) -> None:
    (device,) = attach(server, "a")
    mode.device_stream(device, reconnect=reconnect)
    mode.stream([device], reconnect=reconnect)


def test_buffer_limits_at_their_minimum_are_accepted(
    server: FakeAdbServer, mode: Mode
) -> None:
    (device,) = attach(server, "a")
    mode.device_stream(device, buffer_lines=1, buffer_bytes=65536)


def test_devices_must_be_a_non_empty_iterable_of_devices_or_strings(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    (device,) = attach(server, "a")
    with pytest.raises(ValueError, match="empty"):
        mode.stream([])
    with pytest.raises(ValueError, match="serial"):
        mode.stream([device, device])
    with pytest.raises(ValueError, match="serial"):
        mode.stream([device, "a"])
    with pytest.raises(TypeError):
        mode.stream("a")
    with pytest.raises(TypeError):
        mode.stream(5)  # ty: ignore[invalid-argument-type]
    with pytest.raises(TypeError):
        mode.stream([device, 5])  # ty: ignore[invalid-argument-type]
    with pytest.raises(TypeError):
        mode.stream([None])  # ty: ignore[invalid-argument-type]


def test_serial_strings_become_devices(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    attach(server, "a", "b")
    monkeypatch.setenv("ADB_SERVER_SOCKET", server.address)
    s = mode.stream(["a", "b"])
    assert s.serials == ("a", "b")
    with pytest.raises(ValueError, match="serial"):
        mode.stream(["a", "a"])
    with pytest.raises(LogprobeError) as info:
        mode.stream(["a", "nope"])
    assert info.value.code == "device_not_found"


def test_the_stream_is_not_started_and_connects_to_nothing(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    (device,) = attach(server, "a")
    before = list(server.requests)
    s = mode.device_stream(device, level="W", tag="x", message="m", pid=1)
    assert isinstance(mode.unwrap(s), mode.cls)
    assert s.serials == ("a",)
    assert server.requests == before
    assert server.records == []
    assert stream_threads() == []
    assert s.summary.devices[0].ended_at is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"package": "com.example"},
        {"package": ["com.a", "com.b"]},
        {"where": Package("com.example")},
        {"where": And(Tag("x"), Package("com.example"))},
        {"where": Not(Package("com.example"))},
        {"where": Tag("x"), "package": "com.example"},
    ],
)
def test_package_conditions_are_accepted_and_connect_to_nothing_before_start(
    server: FakeAdbServer, mode: Mode, kwargs: dict[str, Any]
) -> None:
    (device,) = attach(server, "a")
    before = list(server.requests)
    for s in (mode.device_stream(device, **kwargs), mode.stream([device], **kwargs)):
        assert s._core.units[0].attributor is not None
    assert server.requests == before
    assert server.records == []


def test_public_names() -> None:
    assert {"LogStream", "stream"} <= set(logprobe.__all__)
    assert logprobe.stream is _stream.stream


# --- reading -----------------------------------------------------------------


def test_the_logcat_command_reads_the_backlog_in_the_live_format(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", ShellScript(steps=[("stdout", lines(0, 2))]))
    s = mode.device_stream(device).start()
    got, error = collect(s)
    assert got == names(0, 2)
    assert error is not None
    command = program_of(server.records[0].command)
    assert command == "logcat -v threadtime -v year -v usec -v zone -v uid"


def test_entries_carry_the_serial_and_items_yields_them(
    server: FakeAdbServer, mode: Mode
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", ShellScript(steps=[("stdout", lines(0, 3))]))
    s = mode.device_stream(device).start()
    got = []
    with pytest.raises(LogprobeError):
        got.extend(s.items())
    assert [type(item) for item in got] == [LogEntry] * 3
    assert {item.serial for item in got if isinstance(item, LogEntry)} == {"a"}
    assert not any(isinstance(item, Gap) for item in got)


def test_the_condition_filters_and_the_counts_follow_the_feeder(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    (device,) = attach(server, "a")
    data = (
        b"--------- beginning of main\n"
        + lines(0, 3, level="I")
        + lines(3, 2, level="W")
        + logline(5, level="I", message="x" * 70_000)
    )
    server.add_sequence("logcat", ShellScript(steps=[("stdout", data)]))
    s = mode.device_stream(device, level="W").start()
    got, _ = collect(s)
    assert got == ["m3", "m4"]
    summary = s.summary.devices[0]
    # Lines the condition removed (and the divider) still count as lines; a
    # removed line that was cut still counts as truncated.
    assert (summary.lines, summary.entries, summary.truncated) == (7, 2, 1)
    assert summary.unparsed == 0
    assert summary.flush == "not_requested"
    assert summary.gaps == summary.lost == summary.reconnects == 0
    assert summary.unattributed == 0


def test_unparsed_lines_are_counted_and_delivered(
    server: FakeAdbServer, mode: Mode
) -> None:
    (device,) = attach(server, "a")
    data = lines(0, 1) + b"this is not a log line\n" + lines(1, 1)
    server.add_sequence("logcat", ShellScript(steps=[("stdout", data)]))
    s = mode.device_stream(device).start()
    got = []
    with contextlib.suppress(LogprobeError):
        got.extend(entry for entry in s)
    assert [entry.parsed for entry in got] == [True, False, True]
    summary = s.summary.devices[0]
    assert (summary.lines, summary.entries, summary.unparsed) == (3, 3, 1)
    assert not summary.complete


def test_a_condition_with_where_and_shortcuts(
    server: FakeAdbServer, mode: Mode
) -> None:
    (device,) = attach(server, "a")
    data = lines(0, 2, tag="keep") + lines(2, 2, tag="drop")
    server.add_sequence("logcat", ShellScript(steps=[("stdout", data)]))
    s = mode.device_stream(device, Tag("keep"), message="m1").start()
    got, _ = collect(s)
    assert got == ["m1"]


def test_multiple_devices_keep_each_devices_order_and_serials(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    # Both connections stay open: a device that ended would stop the stream,
    # and a stop leaves what the other reader has not read yet unread.
    devices = attach(server, "a", "b")
    for serial in ("a", "b"):
        data = b"".join(logline(n, tag=serial) for n in range(300))
        server.add_sequence("logcat", hold(serial, data), serial=serial)
    s = mode.stream(devices).start()
    entries: list[LogEntry] = []
    with kill_if_hung(s):
        for entry in s:
            entries.append(entry)
            if len(entries) == 600:
                s.stop()
        s.join(GUARD)
    for serial in ("a", "b"):
        mine = [e for e in entries if e.serial == serial]
        assert [e.message for e in mine] == names(0, 300)
        assert {e.tag for e in mine} == {serial}
    assert s.serials == ("a", "b")
    assert [d.serial for d in s.summary.devices] == ["a", "b"]
    assert [d.lines for d in s.summary.devices] == [300, 300]


def test_both_devices_connections_open_after_all_preparation(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    devices = attach(server, "a", "b")
    for serial in ("a", "b"):
        server.add_sequence("logcat", hold(serial), serial=serial)
    s = mode.stream(devices).start()
    s.stop()
    s.join()
    steps = [
        r
        for r in server.requests
        if r.startswith(("host-serial:", "host:transport:", "shell"))
    ]
    kinds = [r.split(":")[0].split(",")[0] for r in steps]
    assert kinds[:2] == ["host-serial", "host-serial"]
    assert set(kinds[2:]) <= {"host", "shell"}
    assert [r for r in steps if r.startswith("host-serial:")] == [
        "host-serial:a:features",
        "host-serial:b:features",
    ]


# --- limits and backpressure --------------------------------------------------


def test_backpressure_makes_the_reader_wait_and_loses_nothing(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    (device,) = attach(server, "a")
    batches = [lines(i * 20, 20) for i in range(5)]
    steps: list[Any] = []
    for number, batch in enumerate(batches):
        steps += [("stdout", batch), Wait(f"b{number}")]
    server.add_sequence("logcat", ShellScript(steps=steps, exit_status=0))
    s = mode.device_stream(device, buffer_lines=20).start()
    outbox = s._core.outbox
    wait_until(lambda: outbox.pending_lines == 20)
    server.release("b0")
    # The second batch finds the queue at its cap and waits (nobody consumes).
    wait_until(lambda: outbox.waiting == 1)
    assert outbox.pending_lines == 20
    for number in range(1, 5):
        server.release(f"b{number}")
    got, error = collect(s)
    assert got == names(0, 100)
    assert error is not None
    assert outbox.backpressure()["a"] > 0


def test_the_byte_limit_applies_to_the_charged_input_bytes(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    (device,) = attach(server, "a")
    # Two batches stay under the cap one by one (each below 64 KiB) and reach it
    # together; the charge of a batch is its input bytes.
    big = b"".join(logline(n, message="y" * 1200) for n in range(30))
    size = len(big)
    assert size < 65536 <= 2 * size
    steps: list[Any] = []
    for number in range(4):
        steps += [("stdout", big), Wait(f"c{number}")]
    server.add_sequence("logcat", ShellScript(steps=steps, exit_status=0))
    s = mode.device_stream(device, buffer_bytes=65536).start()
    outbox = s._core.outbox
    wait_until(lambda: outbox.pending_bytes == size)
    server.release("c0")
    wait_until(lambda: outbox.pending_bytes == 2 * size)
    server.release("c1")
    wait_until(lambda: outbox.waiting == 1)  # the third batch waits for room
    assert outbox.pending_bytes == 2 * size
    server.release("c2")
    server.release("c3")
    got, _ = collect(s)
    assert len(got) == 4 * 30


def test_the_limits_are_shared_by_all_devices(
    server: FakeAdbServer, mode: Mode
) -> None:
    devices = attach(server, "a", "b")
    for serial in ("a", "b"):
        server.add_sequence(
            "logcat",
            ShellScript(
                steps=[("stdout", lines(0, 10)), Wait(f"more-{serial}")],
                exit_status=0,
            ),
            serial=serial,
        )
    s = mode.stream(devices, buffer_lines=1).start()
    outbox = s._core.outbox
    # The first chunk is admitted whatever its size; the other device waits.
    wait_until(lambda: outbox.waiting == 1 and outbox.pending_lines == 10)
    server.release("more-a")
    server.release("more-b")
    got, _ = collect(s)
    assert sorted(got) == sorted(names(0, 10) * 2)


def test_a_large_chunk_is_not_starved_by_small_ones(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A chunk above the cap still gets in while a later small chunk waits.

    The arrival order itself is pinned in test_outbox.
    """
    devices = attach(server, "a", "b")
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[Wait("a-go"), ("stdout", lines(0, 100)), Wait("a-end", live=True)]
        ),
        serial="a",
    )
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[
                ("stdout", lines(0, 5)),
                Wait("b-late"),
                ("stdout", logline(5, message="late")),
                Wait("b-end", live=True),
            ]
        ),
        serial="b",
    )
    s = mode.stream(devices, buffer_lines=5).start()
    outbox = s._core.outbox
    wait_until(lambda: outbox.pending_lines == 5)  # b fills the queue to its cap
    admitted: list[int] = []  # the lines of each chunk let in from now on
    admit = outbox._admit

    def recording_admit(segments: Sequence[object], lines: int, charge: int) -> None:
        admitted.append(lines)
        admit(segments, lines, charge)

    monkeypatch.setattr(outbox, "_admit", recording_admit)
    server.release("a-go")
    wait_until(lambda: outbox.waiting == 1)  # a's chunk is above the cap and waits
    server.release("b-late")
    wait_until(lambda: outbox.waiting == 2)  # b's small chunk lines up behind it
    got: list[tuple[str | None, str]] = []
    with kill_if_hung(s):
        for entry in s:
            got.append((entry.serial, entry.message))
            if len(got) == 106:
                s.stop()
    assert len(got) == 106
    # The case only holds if a's lines reached the queue as a chunk above the cap.
    assert max(admitted) > 5
    assert got[:5] == [("b", message) for message in names(0, 5)]
    assert got.index(("b", "late")) > min(
        position for position, (who, _) in enumerate(got) if who == "a"
    )
    assert [message for who, message in got if who == "a"] == names(0, 100)


# --- lifecycle ---------------------------------------------------------------


def test_lifecycle_a_stream_starts_once(server: FakeAdbServer, mode: Mode) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a"))
    s = mode.device_stream(device)
    assert s.start() is s
    with pytest.raises(RuntimeError):
        s.start()
    s.stop()
    s.join()
    with pytest.raises(RuntimeError):
        s.start()
    with pytest.raises(RuntimeError), s:
        pass


def test_lifecycle_iteration_and_join_need_a_started_stream(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    (device,) = attach(server, "a")
    s = mode.device_stream(device)
    with pytest.raises(RuntimeError):
        iter(s)
    with pytest.raises(RuntimeError):
        s.items()
    with pytest.raises(RuntimeError):
        s.join()
    assert s.summary.devices[0].error is None


@pytest.mark.parametrize("request_name", ["stop", "kill"])
def test_lifecycle_stop_or_kill_before_start_connects_to_nothing(
    server: FakeAdbServer, mode: Mode, request_name: str
) -> None:
    (device,) = attach(server, "a")
    before = list(server.requests)
    s = mode.device_stream(device)
    getattr(s, request_name)()
    getattr(s, request_name)()
    assert s.start() is s
    assert server.requests == before
    assert server.records == []
    assert list(s) == []
    summary = s.join()
    assert summary.devices[0].error is None
    assert summary.devices[0].ended_at is not None
    assert summary.complete
    assert s.join() == summary
    with pytest.raises(RuntimeError):
        s.start()


def test_lifecycle_with_after_stop_does_nothing(
    server: FakeAdbServer, mode: Mode
) -> None:
    (device,) = attach(server, "a")
    s = mode.device_stream(device)
    s.stop()
    with s:
        assert list(s) == []


def test_lifecycle_stop_and_kill_can_be_repeated(
    server: FakeAdbServer, mode: Mode
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 3)))
    s = mode.device_stream(device).start()
    wait_until(lambda: s.summary.devices[0].entries == 3)
    for _ in range(3):
        s.stop()
    got, error = collect(s)
    assert got == names(0, 3)
    assert error is None
    for _ in range(3):
        s.stop()
        s.kill()
    assert s.join().devices[0].error is None


def test_lifecycle_one_iteration_at_a_time(server: FakeAdbServer, mode: Mode) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 3)))
    s = mode.device_stream(device).start()
    first = iter(s)
    with pytest.raises(RuntimeError):
        iter(s)
    with pytest.raises(RuntimeError):
        s.items()
    assert next(first).message == "m0"
    first.close()  # ty: ignore[missing-attribute]
    second = s.items()
    with pytest.raises(RuntimeError):
        iter(s)
    del second  # an iteration that is dropped gives its place back
    gc.collect()
    third = iter(s)
    s.kill()
    assert list(third) == []


def test_lifecycle_an_iteration_that_ended_gives_its_place_back(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 2)))
    s = mode.device_stream(device).start()
    wait_until(lambda: s.summary.devices[0].entries == 2)
    s.stop()
    assert [e.message for e in s] == ["m0", "m1"]
    assert list(s) == []
    assert list(s.items()) == []


def test_lifecycle_on_entry_forbids_iteration(server: FakeAdbServer) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a"))
    s = device.stream(on_entry=lambda _entry: None).start()
    with pytest.raises(RuntimeError):
        iter(s)
    with pytest.raises(RuntimeError):
        s.items()
    s.stop()
    s.join()


def test_lifecycle_failure_is_raised_after_the_queued_items_and_is_the_same_object(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[("stdout", lines(0, 50)), ("stderr", b"boom\n")], exit_status=2
        ),
    )
    s = mode.device_stream(device).start()
    got, error = collect(s)
    assert got == names(0, 50)
    assert isinstance(error, LogprobeError)
    assert error.code == "logcat_failed"
    assert error.details == {"serial": "a", "exit_status": 2, "stderr": ["boom"]}
    with pytest.raises(LogprobeError) as joined:
        s.join()
    assert joined.value is error
    assert s.summary.devices[0].error is error
    assert not s.summary.complete
    with pytest.raises(LogprobeError) as again:
        list(s)  # a new iteration of a failed stream raises the same error
    assert again.value is error


def test_lifecycle_the_with_exit_raises_the_same_error(
    server: FakeAdbServer, mode: Mode
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", ShellScript(steps=[("stdout", lines(0, 5))]))
    with pytest.raises(LogprobeError) as info, mode.device_stream(device) as s:
        wait_until(lambda: s.summary.devices[0].ended_at is not None)
        # Leaving early (nothing was taken): the stream is killed, then joined.
    assert info.value is s.summary.devices[0].error
    assert info.value.code == "device_lost"
    assert s.summary.devices[0].entries == 5


def test_lifecycle_the_body_exception_wins_and_the_stream_error_is_logged(
    server: FakeAdbServer, mode: Mode, caplog: pytest.LogCaptureFixture
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[("stdout", lines(0, 1)), Wait("fail")],
            exit_status=3,
        ),
    )
    with caplog.at_level(logging.ERROR, logger="logprobe"):  # noqa: SIM117
        with pytest.raises(ValueError, match="body"):  # noqa: PT012
            with mode.device_stream(device) as s:
                assert next(iter(s)).message == "m0"
                server.release("fail")
                wait_until(lambda: s.summary.devices[0].ended_at is not None)
                msg = "body"
                raise ValueError(msg)
    error = s.summary.devices[0].error
    assert error is not None
    assert error.code == "logcat_failed"
    records = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(records) == 1
    assert records[0].exc_info
    assert records[0].exc_info[1] is error


def test_lifecycle_the_body_exception_wins_and_the_stream_error_is_logged_with_on_entry(
    server: FakeAdbServer, caplog: pytest.LogCaptureFixture
) -> None:
    """Blocking only: ``on_entry`` makes the with exit a different path."""
    (device,) = attach(server, "a")
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[("stdout", lines(0, 1)), Wait("fail")],
            exit_status=3,
        ),
    )
    seen = threading.Event()

    def on_entry(_entry: LogEntry) -> None:
        seen.set()

    with caplog.at_level(logging.ERROR, logger="logprobe"):  # noqa: SIM117
        with pytest.raises(ValueError, match="body"):  # noqa: PT012
            with device.stream(on_entry=on_entry) as s:
                assert seen.wait(GUARD)
                server.release("fail")
                wait_until(lambda: s.summary.devices[0].ended_at is not None)
                msg = "body"
                raise ValueError(msg)
    error = s.summary.devices[0].error
    assert error is not None
    assert error.code == "logcat_failed"
    records = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(records) == 1
    assert records[0].exc_info
    assert records[0].exc_info[1] is error


def test_lifecycle_a_body_error_that_is_the_stream_error_is_not_logged(
    server: FakeAdbServer, mode: Mode, caplog: pytest.LogCaptureFixture
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", ShellScript(steps=[("stdout", lines(0, 2))]))
    with caplog.at_level(logging.ERROR, logger="logprobe"):  # noqa: SIM117
        with pytest.raises(LogprobeError):  # noqa: PT012
            with mode.device_stream(device) as s:
                for _ in s:
                    pass
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


def test_lifecycle_join_timeout_raises_and_the_stream_keeps_running(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 2)))
    s = mode.device_stream(device).start()
    began = time.monotonic()
    with pytest.raises(TimeoutError):
        s.join(0.3)
    assert 0.25 <= time.monotonic() - began < LATE + 0.5
    with pytest.raises(TimeoutError):
        s.join(0)
    assert mode.readers_running(s, "a") == 1
    # The stream still works: a line that arrives now is delivered.
    wait_until(lambda: server.inject(lines(2, 1), "a") == 1)
    wait_until(lambda: s.summary.devices[0].entries == 3)
    s.stop()
    assert [e.message for e in s] == names(0, 3)
    assert s.join(GUARD).devices[0].error is None


def test_lifecycle_join_with_no_time_after_the_end_returns_the_summary(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 2)))
    s = mode.device_stream(device).start()
    wait_until(lambda: s.summary.devices[0].entries == 2)
    s.stop()
    s.join(GUARD)
    mode.wait_readers_ended(s, GUARD)
    assert s.join(0).devices[0].entries == 2


def test_lifecycle_join_from_inside_on_entry_is_a_runtime_error(
    server: FakeAdbServer,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 1)))
    outcome: list[BaseException] = []
    done = threading.Event()

    def on_entry(_entry: LogEntry) -> None:
        try:
            s.join()
        except RuntimeError as error:
            outcome.append(error)
        done.set()

    s = device.stream(on_entry=on_entry)
    s.start()
    assert done.wait(GUARD)
    s.stop()
    s.join()
    assert len(outcome) == 1


@pytest.mark.parametrize(
    "make", [lambda: ValueError("bad"), lambda: SystemExit(3), KeyboardInterrupt]
)
def test_lifecycle_on_entry_exceptions_stop_the_stream_and_are_raised_as_is(
    server: FakeAdbServer, make: Callable[[], BaseException]
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 100)))
    raised = make()
    calls: list[str] = []

    def on_entry(entry: LogEntry) -> None:
        calls.append(entry.message)
        raise raised

    s = device.stream(on_entry=on_entry).start()
    wait_threads_gone(GUARD)
    assert calls == ["m0"]  # the queue was dropped
    with pytest.raises(type(raised)) as first:
        s.join()
    assert first.value is raised
    with pytest.raises(type(raised)) as second:
        s.join()
    assert second.value is raised
    with pytest.raises(type(raised)) as third:
        s.__exit__(None, None, None)
    assert third.value is raised


def test_lifecycle_on_entry_exception_is_raised_by_the_with_exit(
    server: FakeAdbServer,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 5)))
    raised = ValueError("callback failed")
    reached = threading.Event()

    def on_entry(_entry: LogEntry) -> None:
        reached.set()
        raise raised

    with pytest.raises(ValueError, match="callback failed") as info:  # noqa: SIM117
        with device.stream(on_entry=on_entry):
            assert reached.wait(GUARD)
    assert info.value is raised


def test_lifecycle_on_entry_gets_every_entry_in_order_on_one_thread(
    server: FakeAdbServer,
) -> None:
    devices = attach(server, "a", "b")
    for serial in ("a", "b"):
        server.add_sequence(
            "logcat",
            hold(serial, b"".join(logline(n, tag=serial) for n in range(200))),
            serial=serial,
        )
    got: list[tuple[str, str]] = []
    thread_names = set()

    def on_entry(entry: LogEntry) -> None:
        thread_names.add(threading.current_thread().name)
        got.append((entry.serial or "", entry.message))

    with stream(devices, on_entry=on_entry) as s:
        wait_until(lambda: len(got) == 400)
    assert thread_names == {"logprobe-consumer"}
    for serial in ("a", "b"):
        assert [m for who, m in got if who == serial] == names(0, 200)
    assert all(d.error is None for d in s.summary.devices)


@pytest.mark.parametrize("body_fails", [False, True])
def test_lifecycle_the_with_exit_in_the_on_entry_form_stops_and_delivers(
    server: FakeAdbServer, *, body_fails: bool
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 10)))
    got: list[str] = []
    first = threading.Event()
    release = threading.Event()

    def on_entry(entry: LogEntry) -> None:
        got.append(entry.message)
        first.set()
        if entry.message == "m0":
            assert release.wait(GUARD)

    s = device.stream(on_entry=on_entry)

    def release_at_exit() -> None:
        wait_until(lambda: s._core.outbox.stopping)  # the with exit asks to stop
        release.set()

    releaser = threading.Thread(target=release_at_exit)
    releaser.start()
    try:
        with contextlib.suppress(ValueError), s:
            assert first.wait(GUARD)
            wait_until(lambda: s.summary.devices[0].entries == 10)
            if body_fails:
                msg = "body"
                raise ValueError(msg)
    finally:
        release.set()
        releaser.join()
    assert got == names(0, 10)
    assert s.summary.devices[0].error is None
    assert s.summary.devices[0].ended_at is not None


def test_lifecycle_iterator_with_exit_kills_when_the_iteration_is_unfinished(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 100)))
    with mode.device_stream(device) as s:
        first = next(iter(s))
    assert first.message == "m0"
    assert s._core.outbox.killed
    assert s.summary.devices[0].error is None


def test_lifecycle_start_then_kill_twenty_times_leaves_nothing(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence(
        "logcat",
        *[hold("a", lines(0, 2), name=f"round-{n}") for n in range(20)],
    )
    for _ in range(20):
        s = mode.device_stream(device).start()
        s.kill()
        s.join()
        wait_threads_gone()
    assert server.wait_idle(GUARD)
    assert len(server.records) == 20


def test_lifecycle_kill_inside_on_entry_delivers_no_further_entry(
    server: FakeAdbServer,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 50)))
    got: list[str] = []

    def on_entry(entry: LogEntry) -> None:
        got.append(entry.message)
        s.kill()

    s = device.stream(on_entry=on_entry)
    s.start()
    s.join()
    assert got == ["m0"]


def test_lifecycle_kill_from_another_thread_lets_the_entry_in_flight_through(
    server: FakeAdbServer,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 50)))
    inside = threading.Event()
    go = threading.Event()
    got: list[str] = []

    def on_entry(entry: LogEntry) -> None:
        got.append(entry.message)
        inside.set()
        assert go.wait(GUARD)

    s = device.stream(on_entry=on_entry).start()
    assert inside.wait(GUARD)
    s.kill()
    go.set()
    s.join()
    assert got == ["m0"]


def test_lifecycle_kill_in_the_iteration_body_stops_at_the_next_entry(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 50)))
    s = mode.device_stream(device).start()
    got = []
    for entry in s:
        got.append(entry.message)
        s.kill()
    assert got == ["m0"]
    assert s.join().devices[0].error is None


def _full_queue_stream(server: FakeAdbServer, mode: Mode) -> StreamLike:
    """A stream whose reader waits on a full queue; nobody consumes."""
    (device,) = attach(server, "a")
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[("stdout", lines(0, 10)), Wait("second"), ("stdout", lines(10, 10))],
            exit_status=None,
        ),
    )
    s = mode.device_stream(device, buffer_lines=1).start()
    wait_until(lambda: s._core.outbox.pending_lines == 10)
    server.release("second")
    wait_until(lambda: s._core.outbox.waiting == 1)
    return s


def test_lifecycle_kill_while_a_reader_waits_on_a_full_queue(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    s = _full_queue_stream(server, mode)
    began = time.monotonic()
    s.kill()
    s.join(GUARD)
    assert time.monotonic() - began < PROMPT
    assert s._core.outbox.pending_lines == 0
    assert s.summary.devices[0].error is None


def test_lifecycle_stop_while_a_reader_waits_on_a_full_queue(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    s = _full_queue_stream(server, mode)
    s.stop()
    got, error = collect(s)
    # The reader let its chunk in without waiting, so nothing is lost.
    assert got == names(0, 20)
    assert error is None


def test_lifecycle_stop_during_the_features_check(
    server: FakeAdbServer, mode: Mode
) -> None:
    (device,) = attach(server, "a")
    server.silent_prefix = "host-serial:"
    s = mode.device_stream(device)
    stopped_at: list[float] = []

    def stopper() -> None:
        assert server.silent_started.wait(GUARD)
        stopped_at.append(time.monotonic())
        s.stop()

    thread = threading.Thread(target=stopper)
    thread.start()
    assert s.start() is s
    returned = time.monotonic()
    thread.join()
    assert returned - stopped_at[0] < PROMPT
    assert server.records == []
    assert s.join().devices[0].error is None
    assert list(s) == []


@pytest.mark.parametrize(
    ("detect_skips", "stop_after"),
    [(False, "features"), (True, "features"), (True, "api level")],
)
def test_lifecycle_a_stop_between_the_start_steps_runs_no_further_command(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    stop_after: str,
    *,
    detect_skips: bool,
) -> None:
    """A stop that arrives as a step ends must not let the next step run.

    The API level would be read, the device clock would fail, and the start
    marker would write into the device's log: none may happen after the stop.
    """
    server.add_sequence(
        "date +%s", ShellScript(steps=[("stderr", b"odd\n")], exit_status=1)
    )
    server.answer("getprop ro.build.version.sdk", b"24\n")
    (device,) = attach(server, "a")
    s = mode.device_stream(device, since="now", detect_skips=detect_skips)
    if stop_after == "features":
        mode.after_features_check(monkeypatch, device, s.stop)
    else:
        judge = _stream._judge_logd

        def judged(*args: Any) -> None:  # noqa: ANN401
            judge(*args)
            s.stop()

        monkeypatch.setattr(_stream, "_judge_logd", judged)
        monkeypatch.setattr(_astream, "_judge_logd", judged)
    assert s.start() is s
    ran = [program_of(record.command).split()[0] for record in server.records]
    assert ran == ([] if stop_after == "features" else ["getprop"])  # no logcat
    assert s.join().devices[0].error is None
    assert list(s) == []


@pytest.mark.parametrize("request_name", ["stop", "kill"])
def test_lifecycle_a_stop_or_kill_while_the_api_level_is_read_ends_the_start(
    server: FakeAdbServer, mode: Mode, request_name: str
) -> None:
    """The start does not wait for a hanging ``getprop`` nor run anything after it."""
    server.oneoff["getprop"] = ShellScript(steps=[Wait("getprop")])
    (device,) = attach(server, "a")
    s = mode.device_stream(device, detect_skips=True)
    requested_at: list[float] = []

    def requester() -> None:
        assert server.wait_reached("getprop", GUARD)
        requested_at.append(time.monotonic())
        getattr(s, request_name)()

    thread = threading.Thread(target=requester)
    thread.start()
    with kill_if_hung(s):
        assert s.start() is s
        returned = time.monotonic()
    thread.join(GUARD)
    assert returned - requested_at[0] < PROMPT
    ran = [program_of(record.command).split()[0] for record in server.records]
    assert ran == ["getprop"]  # no date, marker or logcat
    assert s.join(GUARD).devices[0].error is None
    assert list(s) == []


def test_lifecycle_stop_during_the_connection_handshake(
    server: FakeAdbServer, mode: Mode
) -> None:
    (device,) = attach(server, "a")
    server.silent_prefix = "shell,v2"
    s = mode.device_stream(device)
    stopped_at: list[float] = []

    def stopper() -> None:
        assert server.silent_started.wait(GUARD)
        stopped_at.append(time.monotonic())
        s.stop()

    thread = threading.Thread(target=stopper)
    thread.start()
    assert s.start() is s
    returned = time.monotonic()
    thread.join()
    assert returned - stopped_at[0] < PROMPT
    assert stream_threads() == []  # no reader was started
    assert server.records == []  # and the connection that was being opened is closed
    assert server.wait_idle(GUARD)
    assert s.join().devices[0].error is None
    assert list(s) == []


def test_lifecycle_kill_during_the_connection_handshake(
    server: FakeAdbServer, mode: Mode
) -> None:
    (device,) = attach(server, "a")
    server.silent_prefix = "shell,v2"
    s = mode.device_stream(device)
    stopped_at: list[float] = []

    def killer() -> None:
        assert server.silent_started.wait(GUARD)
        stopped_at.append(time.monotonic())
        s.kill()

    thread = threading.Thread(target=killer)
    thread.start()
    assert s.start() is s
    returned = time.monotonic()
    thread.join()
    assert returned - stopped_at[0] < PROMPT
    assert s.join().devices[0].error is None


def test_lifecycle_stop_while_a_reader_waits_for_data(
    server: FakeAdbServer, mode: Mode
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 1)))
    s = mode.device_stream(device).start()
    assert next(iter(s)).message == "m0"
    began = time.monotonic()
    s.stop()
    s.join(GUARD)
    assert time.monotonic() - began < PROMPT
    assert s.summary.devices[0].error is None


def test_lifecycle_start_failure_on_the_second_device_closes_everything(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    devices = attach(server, "a", "b")
    server.add_sequence("logcat", hold("a"), serial="a")
    server.fail["host:transport:b"] = "device 'b' not found"
    s = mode.stream(devices)
    with pytest.raises(LogprobeError) as info:
        s.start()
    assert info.value.code == "device_not_found"
    assert server.wait_idle(GUARD)  # the first connection was closed again ...
    assert len(server.records) == 1  # ... after it had been opened
    assert stream_threads() == []
    assert s._core.expected == 0  # no reader was launched, thread or task
    assert s.summary.devices[0].error is None
    assert s.summary.devices[1].error is info.value
    with pytest.raises(RuntimeError):
        s.start()
    with pytest.raises(RuntimeError):
        iter(s)
    with pytest.raises(LogprobeError) as joined:
        s.join()
    assert joined.value is info.value


def test_lifecycle_a_stop_while_the_second_device_connects_closes_the_first(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    devices = attach(server, "a", "b")
    server.add_sequence("logcat", hold("a"), serial="a")
    server.silent_prefix = "host:transport:b"
    s = mode.stream(devices)
    stopped_at: list[float] = []

    def stopper() -> None:
        assert server.silent_started.wait(GUARD)
        stopped_at.append(time.monotonic())
        s.stop()

    thread = threading.Thread(target=stopper)
    thread.start()
    try:
        assert s.start() is s
        returned = time.monotonic()
    finally:
        thread.join(GUARD)
    assert returned - stopped_at[0] < PROMPT
    # The first device's connection is closed again, well before the fake's own
    # limit on a wait would end it.
    assert server.wait_idle(LATE)
    assert len(server.records) == 1  # after it had been opened
    assert stream_threads() == []
    assert s._core.expected == 0  # no reader was launched, thread or task
    summary = s.join()
    assert [device.error for device in summary.devices] == [None, None]
    assert all(device.ended_at is not None for device in summary.devices)
    assert list(s) == []


def test_lifecycle_a_missing_shell_v2_fails_before_anything_is_opened(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    devices = attach(server, "a", "b")
    server.features["b"] = ["cmd"]
    s = mode.stream(devices)
    with pytest.raises(LogprobeError) as info:
        s.start()
    assert info.value.code == "adb_error"
    assert info.value.details["missing_feature"] == "shell_v2"
    assert server.records == []
    assert not any(r.startswith("host:transport") for r in server.requests)
    assert s.summary.devices[1].error is info.value


def test_lifecycle_keyboard_interrupt_in_start_closes_everything(
    server: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    devices = attach(server, "a", "b")
    server.add_sequence("logcat", hold("a"), serial="a")

    def interrupted(
        _argv: Sequence[str], _cancelled: Callable[[], bool] | None = None
    ) -> ShellStream:
        raise KeyboardInterrupt

    s = stream(devices)
    monkeypatch.setattr(devices[1], "_open_logcat", interrupted)
    with pytest.raises(KeyboardInterrupt):
        s.start()
    assert server.wait_idle(GUARD)
    assert stream_threads() == []
    with pytest.raises(RuntimeError):
        s.start()


def test_lifecycle_a_hung_server_in_start_is_an_adb_error(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    (device,) = attach(server, "a")
    mode.open_fails(monkeypatch, device, TimeoutError("timed out"))
    s = mode.device_stream(device)
    with pytest.raises(LogprobeError) as info:
        s.start()
    assert info.value.code == "adb_error"
    assert isinstance(info.value.__cause__, TimeoutError)
    assert s.summary.devices[0].error is info.value


def test_lifecycle_an_abandoned_stream_stops_its_reader(server: FakeAdbServer) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 5)))
    s = device.stream().start()
    assert len(stream_threads()) == 1
    del s
    gc.collect()
    wait_threads_gone()
    assert server.wait_idle(GUARD)


def test_lifecycle_an_abandoned_stream_with_on_entry_stops_both_threads(
    server: FakeAdbServer,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 5)))
    got = []
    s = device.stream(on_entry=lambda e: got.append(e)).start()
    wait_until(lambda: len(got) == 5)
    assert {t.name for t in stream_threads()} == {
        "logprobe-reader-a",
        "logprobe-consumer",
    }
    del s
    gc.collect()
    wait_threads_gone()


def test_lifecycle_thread_names_counts_and_daemons(server: FakeAdbServer) -> None:
    devices = attach(server, "a", "b")
    for serial in ("a", "b"):
        server.add_sequence("logcat", hold(serial), serial=serial)
    s = stream(devices).start()
    threads = stream_threads()
    assert {t.name for t in threads} == {"logprobe-reader-a", "logprobe-reader-b"}
    assert all(t.daemon for t in threads)
    assert len(threads) == 2
    s.stop()
    s.join()
    wait_threads_gone()
    server.add_sequence("logcat", hold("a", name="again"), serial="a")
    with devices[0].stream(on_entry=lambda _e: None):
        assert {t.name for t in stream_threads()} == {
            "logprobe-reader-a",
            "logprobe-consumer",
        }
        assert len(stream_threads()) == 2
        assert all(t.daemon for t in stream_threads())


def test_lifecycle_a_failing_device_stops_the_others_after_the_queue_is_delivered(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    devices = attach(server, "a", "b")
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[("stdout", lines(0, 30)), Wait("a-fail")],
            exit_status=2,
        ),
        serial="a",
    )
    server.add_sequence("logcat", hold("b", lines(0, 30, tag="b")), serial="b")
    s = mode.stream(devices).start()
    # Both devices' lines are queued before the failure, so none can be lost.
    wait_until(lambda: s._core.outbox.pending_lines == 60)
    server.release("a-fail")
    mode.wait_readers_ended(s, LATE)  # the failure is handled before anything is read
    got = []
    error = None
    with kill_if_hung(s):
        try:
            got.extend((e.serial, e.message) for e in s)
        except LogprobeError as raised:
            error = raised
    assert error is not None
    assert error.code == "logcat_failed"
    assert error.details["serial"] == "a"
    assert [m for who, m in got if who == "a"] == names(0, 30)
    assert [m for who, m in got if who == "b"] == names(0, 30)
    summary = s.summary
    assert summary.devices[0].error is error
    # The other device was only stopped: it ended without an error.
    assert summary.devices[1].error is None
    assert summary.devices[1].ended_at is not None
    with pytest.raises(LogprobeError) as joined:
        s.join()
    assert joined.value is error


def test_lifecycle_a_failing_device_frees_a_reader_that_waits_on_the_full_queue(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    devices = attach(server, "a", "b")
    server.add_sequence(
        "logcat",
        ShellScript(steps=[Wait("a-fail")], exit_status=2),
        serial="a",
    )
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[
                ("stdout", lines(0, 1, tag="b")),
                Wait("b-second"),
                ("stdout", lines(1, 1, tag="b")),
                Wait("b-end", live=True),
            ]
        ),
        serial="b",
    )
    s = mode.stream(devices, buffer_lines=1).start()
    outbox = s._core.outbox
    wait_until(lambda: outbox.pending_lines == 1)  # the queue is at its cap
    server.release("b-second")
    wait_until(lambda: outbox.waiting == 1)  # b's next line waits for room
    server.release("a-fail")
    # Nobody consumes yet: the failure alone must let the waiting reader in and
    # end both readers.
    mode.wait_readers_ended(s, LATE)
    got: list[str] = []
    error = None
    with kill_if_hung(s):
        try:
            got.extend(entry.message for entry in s)
        except LogprobeError as raised:
            error = raised
    assert got == names(0, 2)
    assert error is not None
    assert error.code == "logcat_failed"
    assert error.details["serial"] == "a"
    summary = s.summary
    assert summary.devices[0].error is error
    assert summary.devices[1].error is None
    assert all(device.ended_at is not None for device in summary.devices)
    with pytest.raises(LogprobeError) as joined:
        s.join()
    assert joined.value is error


# --- Ctrl-C ----------------------------------------------------------------------


def test_lifecycle_ctrl_c_while_iterating_leaves_the_with_block_quickly(
    server: FakeAdbServer,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 1)))
    outboxes: list[_stream.Outbox] = []

    def iteration_waits() -> bool:
        # The main thread has registered as a waiter for a chunk (second fetch).
        return bool(outboxes) and bool(outboxes[0]._ready._waiters)  # ty: ignore[missing-attribute]

    with real_sigint(), interrupt_main_when(iteration_waits):
        began = 0.0
        with pytest.raises(KeyboardInterrupt), device.stream() as s:  # noqa: PT012
            it = iter(s)
            assert next(it).message == "m0"
            with kill_if_hung(s):  # fails the test if Ctrl-C never comes
                began = time.monotonic()
                outboxes.append(s._core.outbox)
                for _ in it:  # waits for more; the interrupt arrives meanwhile
                    pass
        assert time.monotonic() - began < CTRL_C
    assert s._core.outbox.killed
    wait_threads_gone()
    assert server.wait_idle(GUARD)


def test_lifecycle_ctrl_c_with_a_stuck_callback_does_not_wait_for_it(
    server: FakeAdbServer,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 20)))
    inside = threading.Event()
    release = threading.Event()
    calls: list[str] = []

    def on_entry(entry: LogEntry) -> None:
        calls.append(entry.message)
        inside.set()
        release.wait(GUARD)

    go = threading.Event()
    with real_sigint(), interrupt_main_when(go.is_set):
        began = 0.0
        with pytest.raises(KeyboardInterrupt), device.stream(on_entry=on_entry):  # noqa: PT012
            assert inside.wait(GUARD)
            began = time.monotonic()
            go.set()
            # Poll for delivery in short sleeps. (Not Event.wait slices, which
            # wait in a Condition; see interrupt_main_when.)
            for _ in range(int(GUARD / 0.01)):
                time.sleep(0.01)
        assert time.monotonic() - began < CTRL_C
    # The readers ended and their sockets are closed; the consumer thread
    # stays until the callback returns, and then calls nothing more.
    wait_until(lambda: [t.name for t in stream_threads()] == ["logprobe-consumer"])
    assert server.wait_idle(GUARD)
    release.set()
    wait_threads_gone()
    assert calls == ["m0"]


def test_lifecycle_ctrl_c_while_joining_kills_the_stream(
    server: FakeAdbServer,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 20)))
    inside = threading.Event()
    release = threading.Event()

    def on_entry(_entry: LogEntry) -> None:
        inside.set()
        release.wait(GUARD)

    s = device.stream(on_entry=on_entry).start()
    assert inside.wait(GUARD)
    reader = s._core.units[0].thread
    assert reader is not None
    real_join = reader.join

    def interrupting_join(timeout: float | None = None) -> None:
        # Ctrl-C arrives exactly while join() is waiting (once).
        reader.join = real_join
        _thread.interrupt_main()
        real_join(timeout)

    reader.join = interrupting_join
    with real_sigint():
        began = time.monotonic()
        with pytest.raises(KeyboardInterrupt):
            s.join()
        assert time.monotonic() - began < CTRL_C
    assert s._core.outbox.killed
    release.set()
    s.join()


# --- end of the connection ---------------------------------------------------------


@pytest.mark.parametrize(
    ("exit_status", "stderr", "output", "code"),
    [
        (None, b"", True, "device_lost"),
        (0, b"", True, "device_lost"),
        (143, b"", False, "device_lost"),
        (1, b"", True, "logcat_failed"),
        (1, b"logcat: bad\n", False, "logcat_failed"),
        (2, b"usage\n", False, "logcat_failed"),
    ],
)
def test_the_end_of_a_connection_ends_the_stream_with_an_error(
    server: FakeAdbServer,
    mode: Mode,
    exit_status: int | None,
    stderr: bytes,
    output: bool,  # noqa: FBT001
    code: str,
) -> None:
    (device,) = attach(server, "a")
    steps: list[Any] = [("stderr", stderr)] if stderr else []
    if output:
        steps.append(("stdout", lines(0, 2)))
    server.add_sequence("logcat", ShellScript(steps=steps, exit_status=exit_status))
    s = mode.device_stream(device).start()
    got, error = collect(s)
    assert isinstance(error, LogprobeError)
    assert error.code == code
    assert got == (names(0, 2) if output else [])
    assert error.details["serial"] == "a"
    assert error.details["exit_status"] == exit_status
    assert len(server.records) == 1  # no reconnect was tried
    if code == "logcat_failed":
        assert error.details["stderr"] == stderr.decode().splitlines()


def test_a_requested_stop_is_a_normal_end(server: FakeAdbServer, mode: Mode) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 2)))
    s = mode.device_stream(device).start()
    wait_until(lambda: s.summary.devices[0].entries == 2)
    s.stop()
    got, error = collect(s)
    assert got == names(0, 2)
    assert error is None
    summary = s.join()
    assert summary.devices[0].error is None
    assert summary.complete


def test_stderr_is_logged_at_a_limited_rate_and_the_tail_is_kept(
    server: FakeAdbServer, mode: Mode, caplog: pytest.LogCaptureFixture
) -> None:
    (device,) = attach(server, "a")
    err = b"".join(f"warning {n}\n".encode() for n in range(40))
    server.add_sequence(
        "logcat",
        ShellScript(steps=[("stderr", err), ("stdout", lines(0, 1))], exit_status=2),
    )
    with caplog.at_level(logging.WARNING, logger="logprobe"):
        s = mode.device_stream(device).start()
        _, error = collect(s)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert 1 <= len(warnings) <= 10
    assert "warning 0" in warnings[0].getMessage()
    assert isinstance(error, LogprobeError)
    assert error.details["stderr"] == [f"warning {n}" for n in range(20, 40)]


def test_stderr_tail_rate_limit_with_a_clock() -> None:
    now = [100.0]
    tail = _stream._StderrTail("a", clock=lambda: now[0])
    handler = _Capture()
    logger = logging.getLogger("logprobe._stream")
    logger.addHandler(handler)
    try:
        tail.feed(b"".join(f"l{n}\n".encode() for n in range(25)))
        assert len(handler.messages) == 10
        now[0] += 0.9
        tail.feed(b"x\n")
        assert len(handler.messages) == 10
        now[0] += 0.2  # a second after the first line of the window
        tail.feed(b"y\nz\n")
        assert len(handler.messages) == 12
    finally:
        logger.removeHandler(handler)
    assert tail.lines()[-3:] == ["x", "y", "z"]
    assert len(tail.lines()) == 20


def test_stderr_tail_handles_partial_long_and_crlf_lines() -> None:
    tail = _stream._StderrTail("a", clock=lambda: 0.0)
    tail.feed(b"one\r\ntw")
    tail.feed(b"o\n\n" + b"z" * 5000 + b"\npart")
    lines_ = tail.lines()
    assert lines_[:2] == ["one", "two"]
    assert lines_[2] == "z" * 1024
    assert lines_[3] == "part"


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def test_a_reader_with_a_broken_decoder_ends_the_stream_with_an_error(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", ShellScript(steps=[("stdout", lines(0, 1))]))

    def broken(_self: object, _out: bytes) -> list[Any]:
        msg = "bug"
        raise ZeroDivisionError(msg)

    monkeypatch.setattr(_stream.Feeder, "feed", broken)
    s = mode.device_stream(device).start()
    _, error = collect(s)
    assert isinstance(error, LogprobeError)
    assert error.code == "internal_error"
    assert isinstance(error.__cause__, ZeroDivisionError)


def test_the_shell_stream_exposes_its_socket(server: FakeAdbServer) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", ShellScript(steps=[("stdout", b"x\n")]))
    conn = device._open_logcat(["logcat"])
    try:
        assert conn.sock.recv(1) != b""
    finally:
        conn.close()


def test_summary_can_be_read_while_running(server: FakeAdbServer, mode: Mode) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 7)))
    s = mode.device_stream(device).start()
    wait_until(lambda: s.summary.devices[0].entries == 7)
    running = s.summary.devices[0]
    assert running.ended_at is None
    assert running.lines == 7
    s.stop()
    s.join()
    assert s.summary.devices[0].ended_at is not None


def test_summary_can_be_read_while_a_callback_consumes(
    server: FakeAdbServer,
) -> None:
    """Blocking only: a consumer thread reads while the summary is taken."""
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 7)))
    s = device.stream(on_entry=lambda _e: None).start()
    wait_until(lambda: s.summary.devices[0].entries == 7)
    running = s.summary.devices[0]
    assert running.ended_at is None
    assert running.lines == 7
    s.stop()
    s.join()
    assert s.summary.devices[0].ended_at is not None


# --- leftovers of an iteration, the app conditions, and corner cases -----------------


def test_a_new_iteration_carries_on_after_a_break(
    server: FakeAdbServer, mode: Mode
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 10)))
    s = mode.device_stream(device).start()
    wait_until(lambda: s.summary.devices[0].entries == 10)
    first = []
    for entry in s:
        first.append(entry.message)
        if entry.message == "m2":
            break
    s.stop()
    assert first == names(0, 3)
    assert [e.message for e in s] == names(3, 7)


def test_a_new_iteration_carries_on_after_next_and_close(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 10)))
    s = mode.device_stream(device).start()
    wait_until(lambda: s.summary.devices[0].entries == 10)
    it = iter(s)
    assert next(it).message == "m0"
    it.close()  # ty: ignore[missing-attribute]
    s.stop()
    rest = list(s.items())
    assert [e.message for e in rest if isinstance(e, LogEntry)] == names(1, 9)
    assert not [item for item in rest if isinstance(item, Gap)]


@pytest.mark.parametrize(
    "where",
    [Crash(package="com.example"), Anr(package="com.example")],
    ids=["crash", "anr"],
)
def test_crash_and_anr_with_a_package_filter_without_attribution(
    server: FakeAdbServer, mode: Mode, where: Crash | Anr
) -> None:
    (device,) = attach(server, "a")
    payload = (
        logline(0)
        + logline(
            1,
            tag="AndroidRuntime",
            level="E",
            message="Process: com.example, PID: 1234",
        )
        + logline(
            2,
            tag="ActivityManager",
            level="E",
            message="ANR in com.example (com.example/.Main)",
        )
        + logline(
            3,
            tag="AndroidRuntime",
            level="E",
            message="Process: com.other, PID: 99",
        )
        + logline(
            4, tag="ActivityManager", level="E", message="ANR in com.other (x/.Y)"
        )
    )
    server.add_sequence("logcat", ShellScript(steps=[("stdout", payload)]))
    s = mode.device_stream(device, where=where).start()
    got, error = collect(s)
    expected = (
        ["Process: com.example, PID: 1234"]
        if isinstance(where, Crash)
        else ["ANR in com.example (com.example/.Main)"]
    )
    assert error is not None  # the connection ended without a stop
    assert got == expected
    assert s.summary.devices[0].entries == 1
    assert s.summary.devices[0].lines == 5
    # These terms read the message text: no package list, no clock.
    assert [program_of(r.command).split()[0] for r in server.records] == ["logcat"]
    assert s._core.units[0].attributor is None


def test_crash_and_anr_with_a_package_combine_with_shortcuts(
    server: FakeAdbServer,
    mode: Mode,
) -> None:
    (device,) = attach(server, "a")
    payload = (
        logline(0)
        + logline(
            1,
            tag="AndroidRuntime",
            level="E",
            message="Process: com.example, PID: 1234",
        )
        + logline(
            2,
            tag="ActivityManager",
            level="E",
            message="ANR in com.example (com.example/.Main)",
        )
        + logline(3, tag="ActivityManager", level="I", message="ANR in com.example")
    )
    server.add_sequence("logcat", ShellScript(steps=[("stdout", payload)]))
    where = Crash(package="com.example") | Anr(package="com.example")
    s = mode.device_stream(
        device, where=where, level="E", message="com.example"
    ).start()
    got, _ = collect(s)
    assert got == [
        "Process: com.example, PID: 1234",
        "ANR in com.example (com.example/.Main)",
    ]


def _packet(kind: int, payload: bytes) -> bytes:
    return struct.pack("<BI", kind, len(payload)) + payload


class _ScriptedSocket:
    """A socket that returns the given chunks and then reports the end."""

    def __init__(self, *chunks: bytes) -> None:
        self._chunks = list(chunks)

    def settimeout(self, _timeout: float | None) -> None:
        pass

    def recv(self, _size: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""


class _ScriptedConnection:
    def __init__(self, *chunks: bytes) -> None:
        self.sock = _ScriptedSocket(*chunks)

    def close(self) -> None:
        pass


def _run_reader(
    server: FakeAdbServer, *chunks: bytes
) -> tuple[_stream._Unit, list[str]]:
    """Run one reader over scripted chunks; return the unit and what it queued."""
    (device,) = attach(server, "a")
    unit = _stream._Unit(device, None, 0.0)
    unit.conn = _ScriptedConnection(*chunks)  # ty: ignore[invalid-assignment]
    core = _stream._Core([unit], _stream.Outbox(100, 1 << 20))
    core.expected = 1
    _stream._reader(core, unit)
    delivered: list[str] = []
    while (chunk := core.outbox.take(0)) is not None:
        for segment in chunk:
            if type(segment) is list:
                delivered.extend(entry.message for entry in segment)
    return unit, delivered


def test_bytes_after_the_exit_packet_are_ignored(server: FakeAdbServer) -> None:
    data = _packet(1, lines(0, 3)) + _packet(3, b"\x00") + b"Z"
    unit, delivered = _run_reader(server, data)
    assert delivered == names(0, 3)
    assert unit.error is not None
    assert unit.error.code == "device_lost"  # an exit status 0 is still an end
    assert unit.error.details["exit_status"] == 0


def test_output_before_an_empty_exit_packet_is_delivered(
    server: FakeAdbServer,
) -> None:
    unit, delivered = _run_reader(server, _packet(1, lines(0, 3)) + _packet(3, b""))
    assert delivered == names(0, 3)
    assert unit.error is not None
    assert unit.error.code == "adb_error"


def test_the_stderr_tail_keeps_at_most_twenty_lines_with_the_unfinished_one() -> None:
    tail = _stream._StderrTail("a")
    tail.feed(b"".join(f"e{n}\n".encode() for n in range(25)) + b"partial")
    kept = tail.lines()
    assert len(kept) == 20
    assert kept[0] == "e6"
    assert kept[-2:] == ["e24", "partial"]


def test_a_killed_stream_does_not_hold_queued_entries(
    server: FakeAdbServer, mode: Mode
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 3)))
    s = mode.device_stream(device).start()
    wait_until(lambda: s._core.outbox.pending_lines == 3)
    s.kill()
    s.join(GUARD)
    assert s._core.outbox.pending_lines == 0
    assert list(s) == []


@pytest.mark.parametrize("on_entry_raises_ctrl_c", [True, False])
def test_lifecycle_the_body_exception_wins_over_a_keyboard_interrupt_of_the_callback(
    server: FakeAdbServer,
    caplog: pytest.LogCaptureFixture,
    *,
    on_entry_raises_ctrl_c: bool,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a", lines(0, 3)))
    raised = KeyboardInterrupt("from on_entry")

    def on_entry(_entry: LogEntry) -> None:
        if on_entry_raises_ctrl_c:
            raise raised

    with caplog.at_level(logging.ERROR, logger="logprobe"):  # noqa: SIM117
        with pytest.raises(ValueError, match="body"):  # noqa: PT012
            with device.stream(on_entry=on_entry) as s:
                if on_entry_raises_ctrl_c:
                    wait_until(
                        lambda: (
                            s._core.consumer is not None
                            and not s._core.consumer.is_alive()
                        )
                    )
                msg = "body"
                raise ValueError(msg)
    records = [r for r in caplog.records if r.levelno == logging.ERROR]
    if on_entry_raises_ctrl_c:
        assert len(records) == 1
        assert records[0].exc_info
        assert records[0].exc_info[1] is raised
    else:
        assert not records


def test_lifecycle_a_stream_error_is_logged_when_the_body_raises_ctrl_c(
    server: FakeAdbServer, mode: Mode, caplog: pytest.LogCaptureFixture
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence(
        "logcat", ShellScript(steps=[("stdout", lines(0, 1))], exit_status=3)
    )
    with caplog.at_level(logging.ERROR, logger="logprobe"):  # noqa: SIM117
        with pytest.raises(KeyboardInterrupt):  # noqa: PT012
            with mode.device_stream(device) as s:
                mode.wait_readers_ended(s, GUARD)
                raise KeyboardInterrupt
    error = s.summary.devices[0].error
    assert error is not None
    assert error.code == "logcat_failed"
    records = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(records) == 1
    assert records[0].exc_info
    assert records[0].exc_info[1] is error


def test_lifecycle_a_start_failure_of_any_kind_is_raised_again_by_join(
    server: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a"))
    real_start = threading.Thread.start
    refusal = RuntimeError("can't start new thread")

    def refuse(self: threading.Thread) -> None:
        if self.name.startswith("logprobe-"):
            raise refusal
        real_start(self)

    monkeypatch.setattr(threading.Thread, "start", refuse)
    s = device.stream()
    with pytest.raises(RuntimeError) as info:
        s.start()
    assert info.value is refusal
    assert server.wait_idle(GUARD)
    assert stream_threads() == []
    with pytest.raises(RuntimeError) as joined:
        s.join()
    assert joined.value is refusal
    assert s.summary.devices[0].error is None
    with pytest.raises(RuntimeError):
        s.start()


def test_lifecycle_a_reader_that_cannot_start_stops_the_one_that_did(
    server: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    devices = attach(server, "a", "b")
    for serial in ("a", "b"):
        server.add_sequence("logcat", hold(serial), serial=serial)
    real_start = threading.Thread.start
    refusal = RuntimeError("can't start new thread")

    def refuse_the_second(self: threading.Thread) -> None:
        if self.name == "logprobe-reader-b":
            raise refusal
        real_start(self)

    monkeypatch.setattr(threading.Thread, "start", refuse_the_second)
    s = stream(devices)
    with pytest.raises(RuntimeError) as info:
        s.start()
    assert info.value is refusal
    wait_threads_gone()  # the first reader had started and ended
    assert server.wait_idle(GUARD)
    assert s._core.outbox.killed
    assert s._core.expected == 0
    with pytest.raises(RuntimeError) as joined:
        s.join()
    assert joined.value is refusal
    for device in s.summary.devices:
        assert device.error is None
        assert device.ended_at is not None
    with pytest.raises(RuntimeError) as again:
        s.start()
    assert again.value is not refusal


def test_lifecycle_ctrl_c_in_a_bare_iteration_kills_the_stream(
    server: FakeAdbServer,
) -> None:
    (device,) = attach(server, "a")
    server.add_sequence("logcat", hold("a"))
    s = device.stream().start()
    outbox = s._core.outbox
    real_take = outbox.take

    def interrupted_take(timeout: float | None = None) -> Sequence[object] | None:
        # Ctrl-C arrives exactly while the iteration waits for a chunk (once).
        outbox.take = real_take
        _thread.interrupt_main()
        return real_take(timeout)

    outbox.take = interrupted_take
    with real_sigint():
        with pytest.raises(KeyboardInterrupt):
            next(iter(s))
        assert outbox.killed
        again = iter(s)  # the interrupted iteration gave its place back
        assert list(again) == []
    s.join(GUARD)
    wait_threads_gone()
    assert s.summary.devices[0].error is None
