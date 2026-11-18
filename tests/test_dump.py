"""Device.dump and Device.adump against the scripted fake adb server.

Most tests run against both versions through the ``dump`` fixture. The
asyncio version runs on a fresh event loop per call. A task left running, an
asyncio log record, or a ResourceWarning (an unclosed transport) fails the
test, and every shell stream a dump opened must be closed at the end.
"""

from __future__ import annotations

import asyncio
import contextlib
import gc
import itertools
import shlex
import threading
from typing import TYPE_CHECKING

import pytest

from logprobe import (
    Anr,
    Crash,
    Device,
    Level,
    LogEntry,
    LogprobeError,
    Not,
    Package,
    Pid,
    Tag,
    _aadb,
    _adb,
    _adump,
    _dump,
)
from logprobe._framing import MIN_MAX_LINE_BYTES
from tests.fake_adb_server import FakeAdbServer, ShellScript, Wait, program_of

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Iterator

    Dump = Callable[..., list[LogEntry]]

pytestmark = pytest.mark.filterwarnings("error::ResourceWarning")

SERIAL = "emulator-5554"
LOGCAT = "logcat -v threadtime -v year -v usec -v zone -v uid"
#: Upper bound for one asyncio dump in a test; a hang fails instead of blocking.
GUARD = 10.0


def line(
    n: int = 0, msg: str = "hello", tag: str = "tag", level: str = "I", pid: int = 100
) -> str:
    """One line in the live format, ``n`` seconds after a fixed start."""
    return (
        f"2026-11-04 04:21:{n:02d}.000000 +0000 10146 {pid:5d} {pid:5d} "
        f"{level} {tag:<8}: {msg}"
    )


def text(*lines: str) -> bytes:
    return "".join(f"{each}\n" for each in lines).encode()


def run[T](scenario: Coroutine[object, object, T]) -> T:
    """Run ``scenario`` on a fresh event loop; a hang fails after ``GUARD`` s.

    A task still running when ``scenario`` returned or raised fails the test:
    ``asyncio.run`` would cancel it without a word.
    """

    async def guarded() -> T:
        try:
            async with asyncio.timeout(GUARD):
                return await scenario
        finally:
            # Also when the scenario raised: an error path may leak a task.
            left = asyncio.all_tasks() - {asyncio.current_task()}
            assert not left, f"tasks left running: {left}"

    return asyncio.run(guarded())


@pytest.fixture(params=["blocking", "async"])
def dump(
    request: pytest.FixtureRequest, caplog: pytest.LogCaptureFixture
) -> Iterator[Dump]:
    """Call ``Device.dump``, or run ``Device.adump`` to its end on a fresh loop."""
    if request.param == "blocking":
        yield lambda device, *args, **kwargs: device.dump(*args, **kwargs)
        return
    yield lambda device, *args, **kwargs: run(device.adump(*args, **kwargs))
    gc.collect()
    assert [r.getMessage() for r in caplog.records if r.name == "asyncio"] == []


@pytest.fixture
def device(fake: FakeAdbServer) -> Device:
    fake.add_device(SERIAL)
    fake.features[SERIAL] = ["shell_v2"]
    return Device(SERIAL, adb_server=fake.address, start_server=False)


@pytest.fixture(autouse=True)
def streams(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[list[_adb.ShellStream | _aadb.AsyncShellStream]]:
    """Record every shell stream a dump opens; each one must end up closed.

    The check looks at the client's own socket or transport, so it cannot be
    satisfied by the server closing its side or by garbage collection closing
    a leaked one.
    """
    opened: list[_adb.ShellStream | _aadb.AsyncShellStream] = []
    original = _dump._open
    original_async = _adump._open

    def recording(
        address: _adb.ServerAddress, serial: str, argv: list[str]
    ) -> _adb.ShellStream:
        stream = original(address, serial, argv)
        opened.append(stream)
        return stream

    async def recording_async(
        address: _adb.ServerAddress, serial: str, argv: list[str]
    ) -> _aadb.AsyncShellStream:
        stream = await original_async(address, serial, argv)
        opened.append(stream)
        return stream

    monkeypatch.setattr(_dump, "_open", recording)
    monkeypatch.setattr(_adump, "_open", recording_async)
    yield opened
    for each in opened:
        if isinstance(each, _adb.ShellStream):
            assert each._sock.fileno() == -1
        else:
            assert each._writer.transport.is_closing()


def script(
    fake: FakeAdbServer, *steps: object, exit_status: int | None = 0
) -> ShellScript:
    shell = ShellScript(steps=list(steps), exit_status=exit_status)  # ty: ignore[invalid-argument-type]
    fake.add_sequence("logcat", shell)
    return shell


def closed(fake: FakeAdbServer) -> None:
    """Every connection the fake accepted is closed again (the client closed it)."""
    assert fake.wait_idle()


# --- results ------------------------------------------------------------------


def test_dump_returns_entries_and_the_last_line_without_lf(
    fake: FakeAdbServer, device: Device, dump: Dump
) -> None:
    script(fake, ("stdout", text(line(1, "a"), line(2, "b")) + line(3, "c").encode()))
    entries = dump(device)
    assert [e.message for e in entries] == ["a", "b", "c"]
    assert {e.serial for e in entries} == {SERIAL}
    assert [r.command for r in fake.records] == [fake.records[0].command]
    assert program_of(fake.records[0].command) == shlex.join([*LOGCAT.split(), "-d"])
    closed(fake)


def test_dump_empty_log(fake: FakeAdbServer, device: Device, dump: Dump) -> None:
    script(fake)
    assert dump(device) == []
    closed(fake)


def test_dump_joins_lines_split_across_packets(
    fake: FakeAdbServer, device: Device, dump: Dump
) -> None:
    whole = text(line(1, "first"), line(2, "second"))
    script(fake, ("stdout", whole[:40]), ("stdout", whole[40:]))
    assert [e.message for e in dump(device)] == ["first", "second"]


def test_tail_adds_t_to_the_command(
    fake: FakeAdbServer, device: Device, dump: Dump
) -> None:
    script(fake, ("stdout", text(line(1, "a"))))
    dump(device, tail=7)
    words = shlex.split(program_of(fake.records[0].command))
    assert words[-3:] == ["-d", "-t", "7"]
    closed(fake)


def test_where_and_shortcuts_filter(
    fake: FakeAdbServer, device: Device, dump: Dump
) -> None:
    lines = [
        line(1, "keep me", "net", "W", 11),
        line(2, "keep me", "net", "D", 11),  # level too low
        line(3, "other", "net", "W", 11),  # message
        line(4, "keep me", "ui", "W", 11),  # tag
        line(5, "keep me", "net", "W", 12),  # pid
        line(6, "keep me", "net", "E", 11),
    ]
    script(fake, ("stdout", text(*lines)))
    got = dump(device, level="W", tag=["net"], message="keep", pid=11)
    assert [e.logged_at.second for e in got] == [1, 6]
    script(fake, ("stdout", text(*lines)))
    got = dump(device, Tag("ui") | (Level == "E"))
    assert [e.logged_at.second for e in got] == [4, 6]
    closed(fake)


def test_crash_with_package_filters_by_text(
    fake: FakeAdbServer, device: Device, dump: Dump
) -> None:
    crash = [
        line(1, "FATAL EXCEPTION: main", "AndroidRuntime", "E"),
        line(2, "Process: com.example.app, PID: 5", "AndroidRuntime", "E"),
        line(3, "unrelated"),
    ]
    script(fake, ("stdout", text(*crash)))
    kept = dump(device, Crash("com.example.app"))
    assert [e.message for e in kept] == ["Process: com.example.app, PID: 5"]
    closed(fake)


def test_unparsed_and_dividers(fake: FakeAdbServer, device: Device, dump: Dump) -> None:
    script(
        fake,
        (
            "stdout",
            b"--------- beginning of main\n" + text("not a log line", line(1, "ok")),
        ),
    )
    entries = dump(device)
    assert [e.parsed for e in entries] == [False, True]
    assert entries[0].message == "not a log line"


def test_unparsed_entries_meet_the_condition(
    fake: FakeAdbServer, device: Device, dump: Dump
) -> None:
    script(fake, ("stdout", text("not a log line", line(1, "ok"))))
    assert [e.parsed for e in dump(device, Tag("tag"))] == [True]


def test_over_long_line_is_truncated(
    fake: FakeAdbServer, device: Device, dump: Dump
) -> None:
    big = line(1, "x" * (MIN_MAX_LINE_BYTES * 20))
    script(fake, ("stdout", text(big, line(2, "after"))))
    entries = dump(device)
    assert [e.truncated for e in entries] == [True, False]
    assert entries[1].message == "after"


# --- failures -----------------------------------------------------------------


def test_nonzero_exit_is_logcat_failed(
    fake: FakeAdbServer, device: Device, dump: Dump
) -> None:
    script(
        fake,
        ("stdout", text(line(1, "a")) + b"partial"),
        ("stderr", b"x" * 5000 + b"logcat: bad option"),
        exit_status=3,
    )
    with pytest.raises(LogprobeError) as info:
        dump(device)
    error = info.value
    assert error.code == "logcat_failed"
    assert error.details["exit_status"] == 3
    assert error.details["serial"] == SERIAL
    stderr = error.details["stderr"]
    assert isinstance(stderr, str)
    assert stderr.endswith("logcat: bad option")
    assert len(stderr) == 2000
    closed(fake)


def test_stderr_tail_does_not_start_inside_a_character(
    fake: FakeAdbServer, device: Device, dump: Dump
) -> None:
    script(fake, ("stderr", ("あ" * 1000).encode()), exit_status=1)
    with pytest.raises(LogprobeError) as info:
        dump(device)
    stderr = info.value.details["stderr"]
    assert isinstance(stderr, str)
    assert "\ufffd" not in stderr
    assert set(stderr) == {"あ"}


def test_close_without_exit_packet_is_device_lost(
    fake: FakeAdbServer, device: Device, dump: Dump
) -> None:
    script(fake, ("stdout", text(line(1, "a")) + b"partial"), exit_status=None)
    with pytest.raises(LogprobeError) as info:
        dump(device)
    assert info.value.code == "device_lost"
    closed(fake)


def test_an_empty_exit_packet_is_adb_error(
    fake: FakeAdbServer, device: Device, dump: Dump
) -> None:
    script(fake, ("stdout", text(line(1, "a"))), ("exit", b""), exit_status=None)
    with pytest.raises(LogprobeError) as info:
        dump(device)
    assert info.value.code == "adb_error"
    closed(fake)


def test_missing_shell_v2(fake: FakeAdbServer, device: Device, dump: Dump) -> None:
    fake.features[SERIAL] = []
    with pytest.raises(LogprobeError) as info:
        dump(device)
    assert info.value.code == "adb_error"
    assert info.value.details["missing_feature"] == "shell_v2"
    assert fake.records == []
    closed(fake)


def test_stalled_device_times_out(
    fake: FakeAdbServer, device: Device, dump: Dump, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_dump, "IDLE_TIMEOUT", 0.3)
    script(fake, ("stdout", text(line(1, "a"))), Wait("hold"))
    with pytest.raises(TimeoutError, match="no output") as info:
        dump(device)
    # Keep the exception (and so the frames it references) alive: a leaked
    # socket would otherwise be closed by garbage collection.
    closed(fake)  # the stuck connection was closed by the client
    del info


def test_every_byte_restarts_the_idle_limit(
    fake: FakeAdbServer, device: Device, dump: Dump, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An empty log: only the exit packet comes, one byte at a time. Its six
    # bytes take longer than the limit and bring no output, but no gap
    # between two bytes comes near the limit.
    monkeypatch.setattr(_dump, "IDLE_TIMEOUT", 0.4)
    shell = script(fake)
    shell.fragment = True
    shell.byte_delay = 0.1
    assert dump(device) == []
    closed(fake)


def test_the_idle_limit_is_on_a_silent_device_not_on_a_slow_packet(
    fake: FakeAdbServer, device: Device, dump: Dump, monkeypatch: pytest.MonkeyPatch
) -> None:
    # One packet arrives a byte at a time over far longer than the limit, but
    # no gap between two bytes comes near it.
    monkeypatch.setattr(_dump, "IDLE_TIMEOUT", 0.2)
    shell = script(fake, ("stdout", text(line(1, "slow"))))
    shell.fragment = True
    shell.byte_delay = 0.005
    assert [e.message for e in dump(device)] == ["slow"]
    closed(fake)


def test_keyboard_interrupt_in_the_read_loop_closes_the_socket(
    fake: FakeAdbServer, device: Device, dump: Dump, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The fake holds the connection at the wait point until the client closes it.
    script(fake, ("stdout", text(line(1, "a"))), Wait("hold"))

    def interrupt(*_args: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(_dump.Feeder, "feed", interrupt)
    with pytest.raises(KeyboardInterrupt) as info:
        dump(device)
    closed(fake)
    del info


def test_waits_are_sliced(
    fake: FakeAdbServer, device: Device, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Callable[[], bool] | None] = []
    setup: dict[str, Callable[[], bool] | None] = {}
    open_shell = _adb.open_shell
    require_shell_v2 = _adb.require_shell_v2

    def spy_open(*args: object, **kwargs: object) -> object:
        setup["open_shell"] = kwargs.get("cancelled")  # ty: ignore[invalid-assignment]
        return open_shell(*args, **kwargs)  # ty: ignore[invalid-argument-type]

    def spy_features(*args: object, **kwargs: object) -> None:
        setup["require_shell_v2"] = kwargs.get("cancelled")  # ty: ignore[invalid-assignment]
        require_shell_v2(*args, **kwargs)  # ty: ignore[invalid-argument-type]

    monkeypatch.setattr(_adb, "open_shell", spy_open)
    monkeypatch.setattr(_adb, "require_shell_v2", spy_features)
    original = _adb.ShellStream.read

    def spy(
        self: _adb.ShellStream, cancelled: Callable[[], bool] | None = None
    ) -> object:
        seen.append(cancelled)
        return original(self, cancelled)

    monkeypatch.setattr(_adb.ShellStream, "read", spy)
    script(fake, ("stdout", text(line(1, "a"))))
    device.dump()
    assert seen
    assert all(callable(each) for each in seen)
    assert set(setup) == {"open_shell", "require_shell_v2"}
    assert all(callable(each) for each in setup.values())


# --- arguments ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"tail": 0}, ValueError),
        ({"tail": -1}, ValueError),
        ({"tail": True}, TypeError),
        ({"tail": "5"}, TypeError),
        ({"tail": 1.5}, TypeError),
        ({"where": "Tag"}, TypeError),
        ({"where": lambda _entry: True}, TypeError),
        ({"level": "Z"}, ValueError),
        ({"tag": []}, ValueError),
        ({"pid": "1"}, TypeError),
        # A bad tail wins over the unsupported package filter in both versions.
        ({"tail": 0, "package": "a.b"}, ValueError),
    ],
)
def test_argument_errors_before_any_io(
    fake: FakeAdbServer,
    device: Device,
    dump: Dump,
    kwargs: dict[str, object],
    error: type[Exception],
) -> None:
    requests = list(fake.requests)
    with pytest.raises(error):
        dump(device, **kwargs)
    assert fake.requests == requests
    assert fake.records == []


def test_tail_one_is_accepted(fake: FakeAdbServer, device: Device, dump: Dump) -> None:
    script(fake, ("stdout", text(line(1, "a"))))
    assert len(dump(device, tail=1)) == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {"package": "com.example"},
        {"package": ["a.b", "c.d"]},
        {"where": Package("a.b")},
        {"where": Not(Package("a.b"))},
        {"where": Tag("x") & (Pid(1) | Package("a.b")), "level": "W"},
    ],
)
def test_package_condition_is_not_implemented(
    fake: FakeAdbServer, device: Device, dump: Dump, kwargs: dict[str, object]
) -> None:
    requests = list(fake.requests)
    with pytest.raises(NotImplementedError, match="package"):
        dump(device, **kwargs)
    assert fake.requests == requests
    assert fake.records == []


def test_anr_with_package_is_allowed(
    fake: FakeAdbServer, device: Device, dump: Dump
) -> None:
    script(fake, ("stdout", text(line(1, "a"))))
    assert dump(device, Anr("com.example")) == []


def test_a_chatty_notice_is_an_entry_of_a_dump_and_makes_no_gap(
    fake: FakeAdbServer, device: Device, dump: Dump
) -> None:
    from tests.device_facts import level_dir, load

    notices = load(level_dir(24), "C06")["facts"]["notice_details"]
    recorded = [each["line"] for each in notices[:2]]
    script(fake, ("stdout", text(line(0, "a"), *recorded, line(9, "b"))))
    entries = dump(device)
    assert [type(each) for each in entries] == [LogEntry] * 4
    assert [each.tag for each in entries] == ["tag", "chatty", "chatty", "tag"]


# --- asyncio only ---------------------------------------------------------------


def test_adump_checks_its_arguments_when_awaited(
    fake: FakeAdbServer, device: Device
) -> None:
    requests = list(fake.requests)
    pending = device.adump(tail=0)  # creating the coroutine checks nothing yet
    with pytest.raises(ValueError, match="tail"):
        run(pending)
    assert fake.requests == requests
    assert fake.records == []


@pytest.mark.parametrize("output", [False, True], ids=["no-output", "after-output"])
def test_a_cancelled_adump_closes_the_connection(
    fake: FakeAdbServer,
    device: Device,
    streams: list[_adb.ShellStream | _aadb.AsyncShellStream],
    monkeypatch: pytest.MonkeyPatch,
    *,
    output: bool,
) -> None:
    steps = [("stdout", text(line(1, "a")))] if output else []
    script(fake, *steps, Wait("hold"))
    fed: list[bytes] = []
    take = _dump.Collector.take

    def recording(self: _dump.Collector, kind: str, data: bytes) -> None:
        fed.append(data)
        take(self, kind, data)

    monkeypatch.setattr(_dump.Collector, "take", recording)

    async def scenario() -> None:
        task = asyncio.create_task(device.adump())
        # Cancel only once the shell stream is open (the handshake is over)
        # and, with output, once that output was fed: the task then waits
        # for more output inside the dump's own read loop.
        while not (streams and (fed or not output)):  # noqa: ASYNC110  (the dump task)
            await asyncio.sleep(0.005)
        while not fake.wait_reached("hold", 0):  # noqa: ASYNC110  (the fake's thread)
            await asyncio.sleep(0.005)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    run(scenario())
    assert len(streams) == 1
    closed(fake)


def test_adump_starts_no_thread(
    fake: FakeAdbServer, device: Device, monkeypatch: pytest.MonkeyPatch
) -> None:
    started: list[str] = []
    caller = threading.current_thread()
    original = threading.Thread.start

    def spy(self: threading.Thread) -> None:
        # The fake server's own threads start from its thread, not this one.
        if threading.current_thread() is caller:
            started.append(self.name)
        original(self)

    monkeypatch.setattr(threading.Thread, "start", spy)
    script(fake, ("stdout", text(line(1, "a"), line(2, "b"))))
    assert [e.message for e in run(device.adump())] == ["a", "b"]
    assert started == []


class _ReadyStream:
    """An open shell stream whose output is all there: no read waits."""

    def __init__(self, events: list[tuple[str, bytes]]) -> None:
        self._events = events
        self.exit_status: int | None = None

    async def __aenter__(self) -> _ReadyStream:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None

    def set_timeout(self, timeout: float | None) -> None:
        pass  # no read waits

    async def read_part(self) -> tuple[str, bytes] | None:
        if self._events:
            return self._events.pop(0)
        self.exit_status = 0
        return None


def ready_output(
    monkeypatch: pytest.MonkeyPatch, events: list[tuple[str, bytes]]
) -> None:
    """Make the next asyncio dump read ``events`` from a :class:`_ReadyStream`."""

    async def ready(*_args: object) -> _ReadyStream:
        return _ReadyStream(events)

    monkeypatch.setattr(_adump, "_open", ready)


def test_adump_feeds_the_output_that_is_ready_in_one_piece(
    device: Device, monkeypatch: pytest.MonkeyPatch
) -> None:
    ready_output(monkeypatch, [("stdout", text(line(n, f"m{n}"))) for n in range(5)])
    fed: list[bytes] = []
    take = _dump.Collector.take

    def recording(self: _dump.Collector, kind: str, data: bytes) -> None:
        fed.append(data)
        take(self, kind, data)

    monkeypatch.setattr(_dump.Collector, "take", recording)
    assert [e.message for e in run(device.adump())] == [f"m{n}" for n in range(5)]
    assert fed == [text(*(line(n, f"m{n}") for n in range(5)))]


def test_adump_lets_other_tasks_run_between_reads(
    device: Device, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Each read brings more than one batch takes (about 8 KiB), so every read
    # is fed on its own.
    ready_output(
        monkeypatch,
        [("stdout", text(*[line(n, f"m{n}")] * 200)) for n in range(5)],
    )
    ticks = 0
    seen: list[int] = []
    take = _dump.Collector.take

    def counting(self: _dump.Collector, kind: str, data: bytes) -> None:
        seen.append(ticks)
        take(self, kind, data)

    monkeypatch.setattr(_dump.Collector, "take", counting)

    async def ticker() -> None:
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0)

    async def scenario() -> list[LogEntry]:
        other = asyncio.create_task(ticker())
        try:
            return await device.adump()
        finally:
            other.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await other

    got = [e.message for e in run(scenario())]
    assert got == [f"m{n}" for n in range(5) for _ in range(200)]
    # The other task ran between every two reads, though none of them waited.
    assert len(seen) == 5
    assert all(later > earlier for earlier, later in itertools.pairwise(seen))
