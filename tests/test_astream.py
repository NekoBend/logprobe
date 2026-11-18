"""What only the asyncio log stream has: tasks, cancellation, a loop of its own.

These tests run on the loop's own thread with ``asyncio.run``. The behaviour
the blocking and the asyncio stream share is tested once for both, in the
modules of the blocking stream. Every test here has a named failure it guards.
A fixture fails a test that leaves a task or a transport behind (an asyncio log
record, or a ResourceWarning).
"""

from __future__ import annotations

import asyncio
import gc
import inspect
import threading
from typing import TYPE_CHECKING, Any, Literal

import pytest

import logprobe
from logprobe import (
    AsyncLogStream,
    Device,
    Gap,
    LogprobeError,
    _astream,
    _resume,
    _stream,
)
from logprobe import _feed as feed_module
from tests.fake_adb_server import FakeAdbServer, Omit, ShellScript, Wait
from tests.test_stream import GUARD, PROMPT, attach, hold, lines, names
from tests.test_stream_marks import echo_markers
from tests.test_stream_resume import BASE, at, expect_t, released, staying

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator

pytestmark = pytest.mark.filterwarnings("error::ResourceWarning")

TICK = 0.02


@pytest.fixture(autouse=True)
def clean_event_loops(caplog: pytest.LogCaptureFixture) -> Generator[None]:
    """Fail a test that leaves a pending task or an unclosed transport behind."""
    yield
    gc.collect()
    problems = [r.getMessage() for r in caplog.records if r.name == "asyncio"]
    assert problems == []


@pytest.fixture(autouse=True)
def fast_tick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_astream, "TICK", TICK)
    monkeypatch.setattr(_stream, "TICK", TICK)


@pytest.fixture
def slow_tick(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every wait last 30 seconds unless something ends it: no flag is seen."""
    monkeypatch.setattr(_astream, "TICK", 30.0)
    monkeypatch.setattr(_stream, "TICK", 30.0)


@pytest.fixture(autouse=True)
def fast_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_resume, "backoff", lambda _failures: 0.01)


@pytest.fixture
def server(fake: FakeAdbServer) -> Generator[FakeAdbServer]:
    """The fake server; at the end every connection must be closed."""
    yield fake
    assert fake.wait_idle(GUARD), "a connection to the adb server stayed open"


def run(scenario: Callable[[], Awaitable[None]], *, debug: bool = False) -> None:
    """Run ``scenario`` on a fresh loop; a hang fails after ``GUARD`` seconds.

    In debug mode the loop raises when a loop object is touched from another
    thread without ``call_soon_threadsafe``.
    """

    async def guarded() -> None:
        async with asyncio.timeout(GUARD):
            await scenario()

    asyncio.run(guarded(), debug=debug)


def open_stream(
    server: FakeAdbServer,
    *serials: str,
    reconnect: float = 0.0,
    since: Literal["now"] | None = None,
    buffer_lines: int = 10_000,
) -> AsyncLogStream:
    devices = attach(server, *(serials or ("a",)))
    return logprobe.astream(
        devices, reconnect=reconnect, since=since, buffer_lines=buffer_lines
    )


async def until(condition: Callable[[], object]) -> None:
    """Let the loop run until ``condition`` holds (a guard against hangs only)."""
    while not condition():  # noqa: ASYNC110  (a condition of another thread)
        await asyncio.sleep(0.005)


async def reached(server: FakeAdbServer, name: str) -> None:
    await until(lambda: server.wait_reached(name, 0))


async def closed(server: FakeAdbServer) -> None:
    """Let the loop run until the fake sees every connection closed."""
    await until(lambda: server.wait_idle(0))


async def collect(s: AsyncLogStream) -> tuple[list[str], LogprobeError | None]:
    """The messages of every entry, and the error that ended the stream."""
    got: list[str] = []
    try:
        async for entry in s:
            got.append(entry.message)  # noqa: PERF401  (the error must not lose them)
    except LogprobeError as error:
        return got, error
    return got, None


def shape(items: list[Any]) -> list[str]:
    return [
        f"{item.reason}/{item.cause}" if isinstance(item, Gap) else item.message
        for item in items
    ]


# --- arguments ---------------------------------------------------------------


def test_astream_takes_the_arguments_of_stream_without_on_entry(
    server: FakeAdbServer,
) -> None:
    """The two entry points cannot drift apart, and nothing is awaited or sent."""
    assert not inspect.iscoroutinefunction(logprobe.astream)

    def parameters(function: Callable[..., Any]) -> dict[str, object]:
        found = inspect.signature(function).parameters
        return {n: (p.kind, p.default) for n, p in found.items() if n != "self"}

    stream = parameters(logprobe.stream)
    stream.pop("on_entry")
    assert parameters(logprobe.astream) == stream
    method = parameters(Device.stream)
    method.pop("on_entry")
    assert parameters(Device.astream) == method

    (device,) = attach(server, "a")
    before = list(server.requests)
    s = device.astream(level="W")
    assert isinstance(s, AsyncLogStream)
    assert s.serials == ("a",)
    assert server.requests == before
    with pytest.raises(NotImplementedError, match="astream"):
        device.astream(package="com.example")


# --- iteration ---------------------------------------------------------------


def test_iteration_delivers_all_entries_then_the_streams_error_once(
    server: FakeAdbServer,
) -> None:
    """The error comes after the queued entries, and is the same object everywhere."""
    server.add_sequence("logcat", ShellScript(steps=[("stdout", lines(0, 50))]))
    s = open_stream(server)

    async def scenario() -> None:
        got: list[str] = []
        ended: LogprobeError | None = None
        with pytest.raises(LogprobeError) as raised:
            async with s:  # the exit raises the same error again
                got, ended = await collect(s)
        assert got == names(0, 50)
        error = raised.value
        assert error is ended
        assert error.code == "device_lost"
        with pytest.raises(LogprobeError) as again:
            await s.join()
        assert again.value is error
        assert s.summary.devices[0].entries == 50

    run(scenario)


@pytest.mark.parametrize("gaps", [True, False])
def test_items_yields_a_gap_in_place_and_plain_iteration_skips_it(
    server: FakeAdbServer, *, gaps: bool
) -> None:
    server.add_sequence(
        "logcat",
        released(("stdout", at(0, "m0") + at(0.5, "m1") + at(1, "m2") + at(2, "m3"))),
        staying(
            Omit(at(1, "m2")), ("stdout", at(2, "m3") + at(3, "m4")), t=expect_t(2)
        ),
    )
    s = open_stream(server, reconnect=60.0)
    expected = ["m0", "m1", "m2", "m3", "ring_rotated/released", "m4"]
    if not gaps:
        expected.remove("ring_rotated/released")

    async def scenario() -> None:
        got = []
        async with s:
            async for item in s.items() if gaps else s:
                got.append(item)
                if len(got) == len(expected):
                    s.stop()
        assert shape(got) == expected

    run(scenario)


def test_a_slow_consumer_loses_nothing_and_the_reader_waits_for_room(
    server: FakeAdbServer,
) -> None:
    count = 3000
    server.add_sequence("logcat", hold("a", lines(0, count)))
    s = open_stream(server, buffer_lines=20)
    got: list[str] = []

    async def scenario() -> None:
        async with s:
            async for entry in s:
                got.append(entry.message)
                if len(got) % 100 == 0:
                    await asyncio.sleep(0.002)
                if len(got) == count:
                    s.stop()
            assert s._core.outbox.backpressure().get("a", 0.0) > 0

    run(scenario)
    assert got == names(0, count)


# --- start and cancellation --------------------------------------------------


@pytest.mark.parametrize(
    "step", ["features", "date", "marker", "logcat", "second_logcat"]
)
def test_a_start_that_is_cancelled_at_any_step_leaves_nothing_open(
    server: FakeAdbServer, step: str
) -> None:
    """The step that the task waits in is closed, and the stream counts as ended.

    In the ``second_logcat`` step the first device's connection is already open
    and is closed too; no reader task is created.
    """
    serials = ("a", "b") if step == "second_logcat" else ("a",)
    if step == "features":
        server.silent_prefix = "host-serial:"
    elif step == "logcat":
        server.silent_prefix = "shell,v2"
    elif step == "second_logcat":
        server.add_sequence("logcat", hold("a"), serial="a")
        server.silent_prefix = "host:transport:b"
    elif step == "date":
        server.oneoff["date +%s"] = ShellScript(steps=[Wait("date")])
    else:
        server.answer("date +%s", b"1000\n")
        server.oneoff["log -t"] = ShellScript(steps=[Wait("marker")])
    s = open_stream(
        server, *serials, since="now" if step in {"date", "marker"} else None
    )

    async def scenario() -> None:
        task = asyncio.create_task(s.start())
        if step in {"features", "logcat", "second_logcat"}:
            await until(server.silent_started.is_set)
        else:
            await reached(server, step)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        async with asyncio.timeout(1.0):  # closed by the cancellation itself
            await closed(server)
        assert s._core.outbox.killed
        assert s._core.expected == 0  # no reader task was created
        if step == "second_logcat":
            assert len(server.records) == 1  # the first connection had been opened
        assert [item async for item in s] == []
        summary = await s.join()
        assert [device.error for device in summary.devices] == [None] * len(serials)
        assert all(device.ended_at is not None for device in summary.devices)
        with pytest.raises(RuntimeError):
            await s.start()

    run(scenario)


@pytest.mark.usefixtures("slow_tick")
def test_cancelling_the_task_that_iterates_kills_the_stream_and_closes_everything(
    server: FakeAdbServer,
) -> None:
    server.add_sequence("logcat", hold("a", lines(0, 3)))
    s = open_stream(server)

    async def body() -> None:
        async with s:
            async for _entry in s:
                pass

    async def scenario() -> None:
        task = asyncio.create_task(body())
        await until(lambda: s.summary.devices[0].lines == 3)
        await until(lambda: s._core.outbox.pending_lines == 0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await closed(server)
        assert s._core.outbox.killed
        assert s.summary.devices[0].ended_at is not None

    run(scenario)


def test_leaving_at_once_ends_the_summary_of_readers_that_never_ran(
    server: FakeAdbServer,
) -> None:
    """A reader task cancelled before its first step still gets an end time."""
    server.add_sequence("logcat", hold("a", lines(0, 2)))
    s = open_stream(server)

    async def scenario() -> None:
        async with s:
            pass  # the exit comes before the reader task ran
        assert s.summary.devices[0].ended_at is not None
        assert s.summary.devices[0].flush == "not_requested"
        await closed(server)

    run(scenario)


@pytest.mark.usefixtures("slow_tick")
def test_a_second_cancellation_inside_the_exit_leaves_nothing_open(
    server: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    server.add_sequence("logcat", hold("a", lines(0, 1)), serial="a")
    server.add_sequence("logcat", hold("b", lines(0, 1)), serial="b")
    s = open_stream(server, "a", "b")
    real = AsyncLogStream._reap
    entered: list[asyncio.Event] = []
    aborted: list[bool] = []

    async def reap(self: AsyncLogStream) -> None:
        entered[0].set()  # the exit is under way: its wait for the readers follows
        await real(self)

    real_tasks = AsyncLogStream._tasks

    def tasks_after_abort(self: AsyncLogStream) -> list[asyncio.Task[None]]:
        # `_reap` asks for the tasks right after it aborted the connections and
        # before its first wait: no transport may be left open at that point.
        if not aborted:
            aborted.extend(u.stream._closed for u in self._units if u.stream)
        return real_tasks(self)

    monkeypatch.setattr(AsyncLogStream, "_reap", reap)
    monkeypatch.setattr(AsyncLogStream, "_tasks", tasks_after_abort)

    async def body() -> None:
        async with s:
            await asyncio.sleep(GUARD)

    async def scenario() -> None:
        entered.append(asyncio.Event())
        task = asyncio.create_task(body())
        await until(lambda: sum(d.lines for d in s.summary.devices) == 2)
        task.cancel()
        await entered[0].wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await closed(server)
        assert aborted == [True, True]

    run(scenario)


@pytest.mark.usefixtures("slow_tick")
def test_a_cancellation_while_the_exit_joins_a_drained_stream_leaves_nothing_open(
    server: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A killed stream is drained, so leaving the block normally joins the
    # readers. They would see the kill only after a tick (30 s here): a
    # cancellation of that wait must close the connection at once itself.
    server.add_sequence("logcat", hold("a", lines(0, 1)), serial="a")
    s = open_stream(server, "a")
    real = AsyncLogStream._wait_ended
    entered: list[asyncio.Event] = []

    async def wait_ended(self: AsyncLogStream, timeout: float | None) -> None:
        entered[0].set()
        await real(self, timeout)

    monkeypatch.setattr(AsyncLogStream, "_wait_ended", wait_ended)

    async def body() -> None:
        async with s:
            await until(lambda: s.summary.devices[0].lines == 1)
            s.kill()

    async def scenario() -> None:
        entered.append(asyncio.Event())
        task = asyncio.create_task(body())
        await entered[0].wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        async with asyncio.timeout(PROMPT + 1.0):
            await closed(server)

    run(scenario)


@pytest.mark.usefixtures("slow_tick")
def test_an_entry_is_delivered_at_once_and_not_after_a_tick(
    server: FakeAdbServer,
) -> None:
    """The reader takes what is ready and goes on; it does not wait out a slice."""
    server.add_sequence("logcat", hold("a", lines(0, 3)))
    s = open_stream(server)

    async def scenario() -> None:
        async with s:
            async with asyncio.timeout(2.0):
                first = await anext(aiter(s))
            assert first.message == "m0"

    run(scenario)


def test_asyncio_run_twice_in_a_row_works(server: FakeAdbServer) -> None:
    """Nothing the stream or its queue keeps belongs to the first loop."""
    for run_number in range(2):
        server.add_sequence("logcat", hold("a", lines(0, 5), name=f"hold-{run_number}"))
        s = open_stream(server)

        async def scenario(s: AsyncLogStream = s) -> None:
            async with s:
                got = []
                async for entry in s:
                    got.append(entry.message)
                    if len(got) == 5:
                        s.stop()
            assert got == names(0, 5)

        run(scenario)
        assert server.wait_idle(GUARD)


@pytest.mark.usefixtures("slow_tick")
def test_a_reader_cancelled_by_the_loop_shutting_down_closes_its_connection(
    server: FakeAdbServer,
) -> None:
    server.add_sequence("logcat", hold("a", lines(0, 2)))
    s = open_stream(server)

    async def scenario() -> None:
        await s.start()  # nobody leaves the stream: the loop ends with it running
        await until(lambda: s.summary.devices[0].lines == 2)

    run(scenario)
    assert server.wait_idle(GUARD)
    assert s._core.outbox.killed  # nobody could take what it queued
    assert s.summary.devices[0].ended_at is not None


def test_an_abandoned_stream_ends_its_readers(server: FakeAdbServer) -> None:
    server.add_sequence("logcat", hold("a", lines(0, 2)))

    async def start() -> list[asyncio.Task[None]]:
        s = open_stream(server)
        await s.start()
        await until(lambda: s.summary.devices[0].lines == 2)
        return [u.task for u in s._units if u.task is not None]

    async def scenario() -> None:
        tasks = await start()
        gc.collect()  # the stream is gone; its finalizer set the kill flag
        async with asyncio.timeout(PROMPT):
            await asyncio.wait(tasks)
        await closed(server)

    run(scenario)


# --- join and stop -----------------------------------------------------------


def test_a_join_that_times_out_leaves_the_stream_running(
    server: FakeAdbServer,
) -> None:
    server.add_sequence("logcat", hold("a", lines(0, 2)))
    s = open_stream(server)

    async def scenario() -> None:
        async with s:
            with pytest.raises(TimeoutError):
                await s.join(0.1)
            assert s.summary.devices[0].ended_at is None
            s.stop()
            summary = await s.join()
        assert summary.devices[0].error is None
        assert summary.devices[0].ended_at is not None

    run(scenario)


@pytest.mark.parametrize("how", ["stop", "kill", "flush"])
def test_stop_kill_and_flush_work_from_another_thread(
    server: FakeAdbServer, how: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    loop_thread: list[int] = []
    interrupt = _astream.AsyncOutbox.interrupt_waiters

    def interrupt_on_the_loop_only(self: _astream.AsyncOutbox) -> None:
        # Waking a parked put from another thread would leave the reader
        # stuck in debug mode, so refuse it here and let the test fail.
        if threading.get_ident() != loop_thread[0]:
            msg = "a waiting put was woken from another thread"
            raise AssertionError(msg)
        interrupt(self)

    monkeypatch.setattr(
        _astream.AsyncOutbox, "interrupt_waiters", interrupt_on_the_loop_only
    )
    echo_markers(server)
    # Two packets, so that the second line meets a full queue (one line) and
    # the reader is waiting in a put when the other thread calls.
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[
                ("stdout", lines(0, 1)),
                Wait("second"),
                ("stdout", lines(1, 1)),
                Wait("hold-a", live=True),
            ],
            exit_status=0,
        ),
    )
    s = open_stream(server, buffer_lines=1)
    failures: list[BaseException] = []
    waiting: list[int] = []

    def call() -> None:
        waiting.append(s._core.outbox.waiting)
        try:
            if how == "flush":
                s.stop(flush=5.0)
            else:
                getattr(s, how)()
        except BaseException as error:  # noqa: BLE001
            failures.append(error)

    async def scenario() -> None:
        loop_thread.append(threading.get_ident())
        # Debug mode is here to catch loop objects touched from the other
        # thread; its warning about slow steps would fail a test on a busy
        # machine.
        asyncio.get_running_loop().slow_callback_duration = GUARD
        async with s:
            await until(lambda: s.summary.devices[0].lines == 1)
            server.release("second")
            await until(lambda: s._core.outbox.waiting == 1)
            caller = threading.Thread(target=call)
            caller.start()
            caller.join(GUARD)
            assert not caller.is_alive()
            async with asyncio.timeout(PROMPT + 1.0):
                got, error = await collect(s)
            summary = await s.join()
        assert error is None
        # A kill drops what was queued; a stop delivers it.
        assert got == ([] if how == "kill" else names(0, 2))
        assert summary.devices[0].flush == (
            "done" if how == "flush" else "not_requested"
        )

    run(scenario, debug=True)
    assert waiting == [1]  # the reader really was waiting in a put
    assert failures == []  # nothing refused a call made from there


def test_a_flush_asked_on_another_thread_wins_over_a_later_one_on_the_loop(
    server: FakeAdbServer,
) -> None:
    echo_markers(server)
    server.add_sequence("logcat", hold("a", lines(0, 2)))
    s = open_stream(server)
    budgets: list[float] = []

    async def scenario() -> None:
        async with s:
            await until(lambda: s.summary.devices[0].lines == 2)
            # The loop does not run while this task waits for the thread, so
            # the handed-over request is noted but not applied yet.
            caller = threading.Thread(target=lambda: s.stop(flush=60.0))
            caller.start()
            caller.join(GUARD)
            assert not caller.is_alive()
            s.stop(flush=1.0)  # later, so it does nothing
            await asyncio.sleep(0)  # the handed-over call runs
            flush = s._core.flush
            assert flush is not None
            budgets.append(flush.seconds)
            s.kill()

    run(scenario)
    assert budgets == [60.0]


def test_a_flush_asked_on_another_thread_counts_when_a_stop_ends_the_reader_first(
    server: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The other thread calls while the reader is in the middle of a step, so
    # the reader sees the stop and ends before the loop runs the handed-over
    # flush; the flush must still end as cancelled, as on the blocking stream.
    server.add_sequence("logcat", hold("a", lines(0, 2)))
    s = open_stream(server)
    feed = _astream._feed_output
    called: list[bool] = []

    def feed_and_call(
        unit: _stream._Unit, run: _stream._RunBase, stderr: bytes, stdout: bytes
    ) -> list[_stream.Chunk]:
        fed = feed(unit, run, stderr, stdout)
        if not called:
            called.append(True)
            caller = threading.Thread(target=lambda: (s.stop(flush=60.0), s.stop()))
            caller.start()
            caller.join(GUARD)
        return fed

    monkeypatch.setattr(_astream, "_feed_output", feed_and_call)

    async def scenario() -> None:
        async with s:
            await s.join(GUARD)

    run(scenario)
    assert called == [True]
    assert s.summary.devices[0].flush == "cancelled"


def test_a_flush_asked_on_another_thread_gives_back_the_queue_waits_after_the_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The loop applies the request later than the call; the queue waits are
    # still counted from the moment of the call.
    core = _astream._ACore([], _astream.AsyncOutbox(1, 1 << 20))
    core.outbox._since[object()] = ("a", 0.0)  # waiting since before the call
    core.outbox._since[object()] = ("b", 7.0)  # began to wait after the call
    monkeypatch.setattr(_astream, "perf_counter", lambda: 5.0)
    core.ask_flush(1.0)  # the call, at 5
    monkeypatch.setattr(_astream, "perf_counter", lambda: 15.0)
    core.apply_asked_flush()  # the loop applies it at 15
    flush = core.flush
    assert flush is not None
    # Both readers waited from the call (or later) until 15: all of it is
    # given back, so the budget is used up only by the time they did not wait.
    assert flush.left("a", 15.0, 15.0) == 1.0
    assert flush.left("b", 15.0, 8.0) == -1.0


def test_a_flush_from_another_thread_after_the_loop_closed_does_nothing(
    server: FakeAdbServer,
) -> None:
    server.add_sequence("logcat", ShellScript(steps=[("stdout", lines(0, 1))]))
    s = open_stream(server)

    async def scenario() -> None:
        async with s:
            await collect(s)

    with pytest.raises(LogprobeError):
        run(scenario)
    errors: list[BaseException] = []

    def call() -> None:
        try:
            s.stop(flush=1.0)
        except BaseException as error:  # noqa: BLE001
            errors.append(error)

    caller = threading.Thread(target=call)
    caller.start()
    caller.join(GUARD)
    assert errors == []


def test_no_thread_is_started_by_a_stream_with_a_reconnect_and_a_flush(
    server: FakeAdbServer,
) -> None:
    echo_markers(server)
    server.add_sequence(
        "logcat",
        released(("stdout", at(0, "m0") + at(1, "m1"))),
        staying(("stdout", at(1, "m1") + at(2, "m2")), name="end"),
    )

    def own_threads() -> set[str]:
        # The fake server's handler threads come and go with its connections.
        return {
            t.name for t in threading.enumerate() if "process_request" not in t.name
        }

    before = own_threads()
    seen: set[str] = set()
    s = open_stream(server, reconnect=60.0)

    async def sample() -> None:
        while True:
            seen.update(own_threads())
            await asyncio.sleep(0.001)

    async def scenario() -> None:
        watcher = asyncio.create_task(sample())
        async with s:
            got = []
            async for entry in s:
                got.append(entry.message)
                if len(got) == 3:
                    s.stop(flush=5.0)
            assert got == ["m0", "m1", "m2"]
        assert s.summary.devices[0].reconnects == 1
        assert s.summary.devices[0].flush == "done"
        watcher.cancel()
        with pytest.raises(asyncio.CancelledError):
            await watcher

    run(scenario)
    assert seen <= before
    assert own_threads() == before


def test_the_stream_is_not_iterated_while_another_iteration_is_open(
    server: FakeAdbServer,
) -> None:
    s = open_stream(server)

    async def scenario() -> None:
        with pytest.raises(RuntimeError, match="start"):
            s.items()
        server.add_sequence("logcat", hold("a", lines(0, 1)))
        async with s:
            first = aiter(s)
            with pytest.raises(RuntimeError, match="already"):
                aiter(s)
            assert (await anext(first)).message == "m0"
            with pytest.raises(TimeoutError):
                async with asyncio.timeout(0.05):
                    await anext(first)  # cancelled: ends that iteration
            server.inject(lines(1, 2))
            got = []
            async for entry in s:  # a new one may start and loses nothing
                got.append(entry.message)
                if len(got) == 2:
                    s.stop()
            assert got == ["m1", "m2"]

    run(scenario)


# --- the end of a reader -----------------------------------------------------


def test_a_reader_cancelled_while_it_queues_its_end_kills_the_stream(
    server: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nobody would take what is queued: the consumer must not wait for it."""
    (device,) = attach(server, "a")
    unit = _astream._AUnit(device, None, 0.0)
    core = _astream._ACore([unit], _astream.AsyncOutbox(1, 1 << 20))

    async def served(*_args: object) -> None:
        return None

    monkeypatch.setattr(_astream, "_serve", served)

    async def scenario() -> None:
        await core.outbox.put([_stream._DeviceEnded("x")], 0, "x")  # the queue is full
        task = asyncio.create_task(_astream._reader(core, unit))
        await until(lambda: core.outbox.waiting == 1)  # in its last put
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert core.outbox.killed

    run(scenario)


def test_an_exit_request_in_a_reader_is_retrieved_and_kills_the_stream(
    server: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``SystemExit`` leaves ``asyncio.run``; no task may keep it unretrieved."""
    server.add_sequence("logcat", hold("a", lines(0, 2)))
    s = open_stream(server)

    def exiting(*_args: object) -> None:
        raise SystemExit(3)

    monkeypatch.setattr(_astream, "_feed_output", exiting)

    async def scenario() -> None:
        await s.start()
        await asyncio.sleep(GUARD)

    with pytest.raises(SystemExit):
        run(scenario)
    assert s._core.outbox.killed
    server.release("hold-a")


# --- what only the scripted reader can show ----------------------------------


class _Clock:
    """A clock that a scripted read moves forward."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _ScriptedStream:
    """Stands in for the connection: parts of output, ``None`` for a silent read.

    The read that follows a part is cut at once, as the reader cuts it when it
    already has data; it takes no time.
    """

    exit_status = None

    def __init__(self, clock: _Clock, *chunks: bytes | None) -> None:
        self._clock = clock
        self._chunks = list(chunks)
        self._cut_next = False
        self.reads_after_the_script = 0

    async def read_part(self) -> tuple[str, bytes] | None:
        if self._cut_next:
            self._cut_next = False
            raise TimeoutError
        if not self._chunks:
            self.reads_after_the_script += 1
            return None
        chunk = self._chunks.pop(0)
        if chunk is None:
            self._clock.now += 0.6  # a read of a silent connection ran out of time
            raise TimeoutError
        self._cut_next = True
        return ("stdout", chunk)

    def close(self) -> None:
        pass


def test_data_that_completes_no_line_still_counts_as_data_for_the_check(
    server: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    (device,) = attach(server, "a")
    unit = _astream._AUnit(device, None, 0.0)
    unit.feeder.feed(at(10, "A"))
    plan = _resume.plan_resume(unit.feeder, "disconnected", BASE)
    unit.feeder.begin_connection(plan.check)
    clock = _Clock()
    monkeypatch.setattr(_astream, "monotonic", clock)
    line = at(10, "A")
    # A replayed line comes in three parts, each after 0.6 s of silence: 1.2 s in
    # all, but never one second (the idle time of a check) without data.
    stream = _ScriptedStream(clock, line[:20], None, line[20:40], None, line[40:], None)
    run_ = _astream._ARun(stream, "a", plan.check)  # ty: ignore[invalid-argument-type]
    core = _astream._ACore([unit], _astream.AsyncOutbox(10, 1 << 20))

    async def scenario() -> None:
        await _astream._read(core, unit, run_)
        assert await core.outbox.take(0) is None  # no gap, no line: A was a replay
        assert unit.feeder.duplicates == 1
        assert run_.pending() is not None  # the check still waits for a new line

    run(scenario)


@pytest.mark.parametrize("request_name", ["request_stop", "request_kill"])
def test_a_check_that_ends_on_a_full_queue_does_not_read_again_after_a_stop(
    server: FakeAdbServer, monkeypatch: pytest.MonkeyPatch, request_name: str
) -> None:
    monkeypatch.setattr(feed_module, "HISTORY_LINES", 3)
    (device,) = attach(server, "a")
    unit = _astream._AUnit(device, None, 0.0)
    outbox = _astream.AsyncOutbox(1, 1 << 20)
    core = _astream._ACore([unit], outbox)
    clock = _Clock()
    monkeypatch.setattr(_astream, "monotonic", clock)
    stream = _ScriptedStream(clock, None, None)  # silence ends the check with a gap

    async def scenario() -> None:
        history = [at(10 + k / 10, name) for k, name in enumerate("abcd")]
        await _astream._enqueue(core, unit, unit.feeder.feed(b"".join(history)))
        plan = _resume.plan_resume(unit.feeder, "disconnected", BASE)
        unit.feeder.begin_connection(plan.check)
        run_ = _astream._ARun(stream, "a", plan.check)  # ty: ignore[invalid-argument-type]
        task = asyncio.create_task(_astream._read(core, unit, run_))
        await until(lambda: outbox.waiting == 1)  # the gap waits for room
        getattr(outbox, request_name)()
        await asyncio.wait_for(task, GUARD)
        assert stream.reads_after_the_script == 0  # it looked at the flags first

    run(scenario)
