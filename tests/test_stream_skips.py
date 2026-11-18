"""``detect_skips``: a reader of an older logd closes its connection itself.

An older logd (API levels 25 and below, and 30) does not cut off a reader that
falls behind: it skips lines without any notice. With ``detect_skips`` the
reader of such a device closes its connection once it waited too long for room
in the queue, waits until the queue is half empty and resumes, so that what the
device no longer has is reported as a gap. Every test here runs against both
versions of the stream (the ``mode`` fixture).

The fake adb server plays the device. A silent skip is an ``Omit`` on a
connection that stays open; the stall limit is shortened through
``_resume.STALL_AFTER``; the order of events is fixed with waiting points and
conditions, never with sleeps (a consumer that is slow on purpose sleeps between
entries). The expected lines are built from the scripts: the fake counts what it
wrote to the socket, not what the reader took.
"""

from __future__ import annotations

import logging
import math
import socket
import time
from datetime import timedelta
from typing import TYPE_CHECKING, Any, NamedTuple

import pytest

from logprobe import (
    Gap,
    LogEntry,
    LogprobeError,
    _aadb,
    _adb,
    _aoutbox,
    _astream,
    _marks,
    _outbox,
    _resume,
    _stream,
)
from logprobe import _feed as feed_module
from tests.fake_adb_server import (
    FakeAdbServer,
    Omit,
    ShellScript,
    Wait,
    packet,
    program_of,
)
from tests.test_stream import (
    GUARD,
    attach,
    hold,
    kill_if_hung,
    stream_threads,
    wait_until,
)
from tests.test_stream_resume import BASE, at, expect_t, run, shape, staying

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from tests.fake_adb_server import ConnectionRecord
    from tests.stream_modes import Mode, StreamLike


pytestmark = pytest.mark.filterwarnings("error::ResourceWarning")

STALL = 0.2  # the stall limit of these tests, in seconds
SDK = "getprop ro.build.version.sdk"
NEWER = "cuts slow readers off itself"
UNREADABLE = "could not read the API level"
CLOSED = "closed its logcat connection"

# One scenario: A fills the queue (4 lines), B is read while it is full, E is
# what logd skips meanwhile, C comes after. The cursor after B is 5 s, so a
# resume starts at 4 s.
A = [at(n, f"m{n}") for n in range(4)]
B = [at(4, "m4"), at(5, "m5")]
E = [at(5 + k / 10, f"s{k}") for k in range(1, 4)]
C = [at(6, "m6"), at(7, "m7")]


def messages(lines: list[bytes]) -> list[str]:
    return [line.decode().rsplit(": ", 1)[1].rstrip("\n") for line in lines]


@pytest.fixture(autouse=True)
def no_threads_left() -> Iterator[None]:
    before = stream_threads()
    yield
    wait_until(lambda: stream_threads() == before, GUARD)


@pytest.fixture(autouse=True)
def fast_tick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_stream, "TICK", 0.02)
    monkeypatch.setattr(_astream, "TICK", 0.02)


@pytest.fixture(autouse=True)
def short_stall(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_resume, "STALL_AFTER", STALL)


def api_level(
    server: FakeAdbServer, serial: str, stdout: bytes, exit_status: int | None = 0
) -> None:
    """Make ``getprop ro.build.version.sdk`` on ``serial`` print ``stdout``."""
    steps: list = [("stdout", stdout)] if stdout else []
    server.add_sequence(
        SDK, ShellScript(steps=steps, exit_status=exit_status), serial=serial
    )


def first_connection() -> ShellScript:
    """A fills the queue; B is read once the test releases ``full``; it stays open."""
    return ShellScript(
        steps=[
            ("stdout", b"".join(A)),
            Wait("full"),
            ("stdout", b"".join(B)),
            Wait("blocked", live=True),
        ]
    )


def records(
    server: FakeAdbServer, program: str, serial: str = "a"
) -> list[ConnectionRecord]:
    """The shell connections to ``serial`` whose command starts with ``program``."""
    return [
        record
        for record in list(server.records)
        if record.serial == serial and program_of(record.command).startswith(program)
    ]


def begin(
    server: FakeAdbServer,
    mode: Mode,
    *serials: str,
    detect_skips: bool = True,
    buffer_lines: int = 4,
    reconnect: float = 60.0,
) -> StreamLike:
    """A started stream over ``serials`` (default one device)."""
    return mode.stream(
        attach(server, *(serials or ("a",))),
        detect_skips=detect_skips,
        buffer_lines=buffer_lines,
        reconnect=reconnect,
    ).start()


def closed_by_the_reader(server: FakeAdbServer, number: int, serial: str = "a") -> None:
    """Wait until the reader closed logcat connection ``number`` of ``serial``.

    The connections the tests use for this end only when the client closes.
    """
    wait_until(lambda: len(records(server, "logcat", serial)) > number)
    assert records(server, "logcat", serial)[number].done.wait(GUARD)


def stall(server: FakeAdbServer, s: StreamLike) -> None:
    """Let the first connection's reader find the queue full until it gives up."""
    outbox = s._core.outbox
    wait_until(lambda: outbox.pending_lines == outbox.max_lines)
    server.release("full")
    closed_by_the_reader(server, 0)


# --- without the flag -------------------------------------------------------------


def test_without_the_flag_no_getprop_runs_and_the_reader_never_cuts(
    server: FakeAdbServer, mode: Mode
) -> None:
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[
                ("stdout", b"".join(A)),
                Wait("full"),
                ("stdout", b"".join(B)),
                Omit(b"".join(E)),
                Wait("blocked"),
                ("stdout", b"".join(C)),
                Wait("end", live=True),
            ]
        ),
    )
    s = begin(server, mode, detect_skips=False)
    outbox = s._core.outbox
    wait_until(lambda: outbox.pending_lines == 4)
    server.release("full")
    wait_until(lambda: outbox.waiting == 1)
    # far longer than a reader with the flag would wait before it closes
    wait_until(lambda: outbox.backpressure().get("a", 0.0) > 3 * STALL)
    server.release("blocked")
    items, error = run(s, 8)
    assert error is None
    written, omitted = A + B + E + C, E
    assert shape(items) == [m for m in messages(written) if m not in messages(omitted)]
    assert server.expected_loss() == b"".join(omitted)  # lost without a gap
    assert len(records(server, "logcat")) == 1
    assert records(server, "getprop") == []
    summary = s.summary.devices[0]
    assert (summary.reconnects, summary.gaps) == (0, 0)


# --- reading the API level ---------------------------------------------------------


def _start_steps(server: FakeAdbServer) -> list[tuple[str, str]]:
    """The features checks and shell commands, in order: (what, serial)."""
    steps: list[tuple[str, str]] = []
    serial = ""
    for request in list(server.requests):
        if request.startswith("host-serial:") and request.endswith(":features"):
            steps.append(("features", request.split(":")[1]))
        elif request.startswith("host:transport:"):
            serial = request.removeprefix("host:transport:")
        elif request.startswith("shell,v2,raw:"):
            program = program_of(request.removeprefix("shell,v2,raw:"))
            steps.append((program.split()[0], serial))
    return steps


def test_the_flag_reads_the_api_level_once_per_device_before_the_clock(
    server: FakeAdbServer, mode: Mode
) -> None:
    server.answer("date +%s", b"%d\n" % int(BASE.timestamp()))
    for serial in ("a", "b"):
        api_level(server, serial, b"24\n")
        server.add_sequence("logcat", hold(serial), serial=serial)
    devices = attach(server, "a", "b")
    s = mode.stream(devices, since="now", detect_skips=True, reconnect=0.0).start()
    assert server.wait_reached("hold-a")
    assert server.wait_reached("hold-b")
    s.stop()
    s.join(GUARD)
    assert _start_steps(server) == [
        ("features", "a"),
        ("getprop", "a"),
        ("date", "a"),
        ("log", "a"),
        ("features", "b"),
        ("getprop", "b"),
        ("date", "b"),
        ("log", "b"),
        ("logcat", "a"),
        ("logcat", "b"),
    ]


@pytest.mark.parametrize("sdk", [26, 31, 36])
def test_a_newer_logd_ignores_the_flag_logs_one_info_and_never_cuts(
    server: FakeAdbServer, mode: Mode, caplog: pytest.LogCaptureFixture, sdk: int
) -> None:
    api_level(server, "a", b"%d\n" % sdk)
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[
                ("stdout", b"".join(A)),
                Wait("full"),
                ("stdout", b"".join(B)),
                Wait("end", live=True),
            ]
        ),
    )
    with caplog.at_level(logging.INFO, logger="logprobe"):
        s = begin(server, mode)
        outbox = s._core.outbox
        wait_until(lambda: outbox.pending_lines == 4)
        server.release("full")
        wait_until(lambda: outbox.waiting == 1)
        wait_until(lambda: outbox.backpressure().get("a", 0.0) > 3 * STALL)
        items, error = run(s, 6)
    assert error is None
    assert shape(items) == messages(A + B)
    assert len(records(server, "logcat")) == 1
    assert s.summary.devices[0].reconnects == 0
    said = [(r.levelname, r.getMessage()) for r in caplog.records]
    assert [entry for entry in said if NEWER in entry[1]] == [
        (
            "INFO",
            f"logd on a (API level {sdk}) cuts slow readers off itself; "
            "detect_skips is not needed there and is ignored",
        )
    ]
    assert not [entry for entry in said if UNREADABLE in entry[1] or CLOSED in entry[1]]


_UNREADABLE = {
    "exit status": (
        ShellScript(steps=[("stdout", b"24\n")], exit_status=1),
        "exit status 1",
    ),
    "empty": (ShellScript(), "printed ''"),
    "text": (ShellScript(steps=[("stdout", b"unknown\n")]), "printed 'unknown'"),
    "dropped": (
        ShellScript(steps=[("stdout", b"24\n")], exit_status=None),
        "no exit status",
    ),
    "hung": (ShellScript(steps=[Wait("never")]), "timed out"),
    # more digits than int() converts by default (4300); the first 80 are shown
    "overlong": (
        ShellScript(steps=[("stdout", b"1" * 5000 + b"\n")]),
        f"printed '{'1' * 80}'",
    ),
}


@pytest.mark.parametrize("case", list(_UNREADABLE))
def test_an_unreadable_api_level_counts_as_old_with_one_warning(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    case: str,
) -> None:
    script, reason = _UNREADABLE[case]
    monkeypatch.setattr(_marks, "COMMAND_LIMIT", 0.2)  # the hung command gives up
    server.add_sequence(SDK, script, serial="a")
    server.add_sequence(
        "logcat",
        first_connection(),
        staying(("stdout", b"".join(B + C)), t=expect_t(5)),  # all comes back
    )
    with caplog.at_level(logging.WARNING, logger="logprobe"):
        s = begin(server, mode)  # the start succeeds
        stall(server, s)
        items, error = run(s, 8)
    assert error is None
    assert shape(items) == messages(A + B + C)
    assert s.summary.devices[0].reconnects == 1
    assert [r.getMessage() for r in caplog.records if UNREADABLE in r.getMessage()] == [
        f"could not read the API level of a ({reason}); detect_skips treats its "
        "logd as one that skips lines silently"
    ]


@pytest.mark.parametrize(
    ("message", "code"),
    [("device offline", "device_offline"), ("closed", "adb_error")],
)
def test_an_adb_error_while_reading_the_api_level_fails_the_start(
    server: FakeAdbServer, mode: Mode, message: str, code: str
) -> None:
    command = _adb.device_command(SDK.split())
    server.fail[_adb.shell_request(command)] = message
    server.add_sequence("logcat", hold("a"))
    s = mode.stream(attach(server, "a"), detect_skips=True)
    with pytest.raises(LogprobeError) as raised:
        s.start()
    assert raised.value.code == code
    assert s.summary.devices[0].error is raised.value
    assert records(server, "logcat") == []  # nothing was opened after it
    with pytest.raises(LogprobeError) as again:
        s.join(GUARD)
    assert again.value is raised.value


# --- an older logd ------------------------------------------------------------------


@pytest.mark.parametrize("sdk", [24, 25, 30])
def test_an_older_logd_reader_closes_itself_resumes_and_reports_the_lost_lines(
    server: FakeAdbServer, mode: Mode, caplog: pytest.LogCaptureFixture, sdk: int
) -> None:
    api_level(server, "a", b"%d\n" % sdk)
    server.add_sequence(
        "logcat",
        first_connection(),
        # The device no longer has B, nor what it skipped: the replay lacks them.
        # The -T value shows that B, held when the reader gave up, counted as read.
        staying(Omit(b"".join(B + E)), ("stdout", b"".join(C)), t=expect_t(5)),
    )
    with caplog.at_level(logging.INFO, logger="logprobe"):
        s = begin(server, mode)
        stall(server, s)
        items, error = run(s, 9)
    assert error is None
    assert shape(items) == [*messages(A + B), "ring_rotated/stalled", *messages(C)]
    gap = items[6]
    assert isinstance(gap, Gap)
    assert (gap.serial, gap.start_at) == ("a", BASE + timedelta(seconds=4))
    summary = s.summary.devices[0]
    assert (summary.reconnects, summary.gaps) == (1, 1)
    assert not s.summary.complete
    assert len(records(server, "getprop")) == 1  # never again after a reconnect
    # Arming the check on an older logd logs nothing; only the stall is logged.
    logged = [
        (r.levelname, r.getMessage())
        for r in caplog.records
        if r.name.startswith("logprobe")
    ]
    assert logged == [
        (
            "WARNING",
            f"the reader of a closed its logcat connection after waiting {STALL:g} s "
            "for room in the queue; it reconnects once the queue is half empty",
        )
    ]


def test_a_stall_whose_replay_returns_every_read_line_reports_no_gap(
    server: FakeAdbServer, mode: Mode
) -> None:
    api_level(server, "a", b"24\n")
    first = first_connection()
    first.steps.insert(3, Omit(b"".join(E)))  # skipped while the reader was stuck
    server.add_sequence(
        "logcat",
        first,
        staying(("stdout", b"".join(B + E + C)), t=expect_t(5)),
    )
    s = begin(server, mode)
    stall(server, s)
    items, error = run(s, 11)
    assert error is None
    assert shape(items) == messages(A + B + E + C)  # E is back, nothing twice
    summary = s.summary.devices[0]
    assert (summary.reconnects, summary.gaps) == (1, 0)


def test_after_a_stall_the_reader_reconnects_only_once_the_queue_is_half_empty(
    server: FakeAdbServer, mode: Mode
) -> None:
    api_level(server, "a", b"24\n")
    steps: list = []
    for n in range(4):  # one line per chunk, so the test takes one at a time
        steps += [("stdout", at(n, f"m{n}")), Wait(f"w{n}")]
    steps += [("stdout", at(4, "m4")), Wait("blocked", live=True)]
    server.add_sequence(
        "logcat",
        ShellScript(steps=steps),
        staying(("stdout", at(3, "m3") + at(4, "m4") + at(5, "m5")), t=expect_t(4)),
    )
    s = begin(server, mode)
    outbox = s._core.outbox
    for n in range(4):
        wait_until(lambda n=n: outbox.pending_lines == n + 1)
        server.release(f"w{n}")
    closed_by_the_reader(server, 0)  # m4 is held
    items = iter(s)
    with kill_if_hung(s):
        assert next(items).message == "m0"  # m4 goes in: 4 lines queued
        wait_until(lambda: outbox._draining == 1)
        for taken in ("m1", None):
            # still above half: the reader waits and does not connect
            before = outbox.backpressure()["a"]
            wait_until(lambda before=before: outbox.backpressure()["a"] > before + 0.1)
            assert len(records(server, "logcat")) == 1
            if taken is not None:
                assert next(items).message == taken  # 3 lines left
        assert next(items).message == "m2"  # 2 lines left: half
        wait_until(lambda: len(records(server, "logcat")) == 2)
        rest = [next(items).message for _ in range(3)]
        s.stop()
        s.join(GUARD)
    assert rest == ["m3", "m4", "m5"]
    assert s.summary.devices[0].gaps == 0
    assert outbox.backpressure()["a"] > 2 * 0.1 + STALL


def test_a_slow_consumer_that_keeps_taking_never_makes_the_reader_cut(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only a wait of one read counts, not how long the queue stays full."""
    limit = 0.5
    monkeypatch.setattr(_resume, "STALL_AFTER", limit)
    count = 60
    api_level(server, "a", b"24\n")
    server.add_sequence("logcat", hold("a"))
    mode.patch_read_size(monkeypatch, 80)  # about one line a read
    s = begin(server, mode, buffer_lines=1)
    assert server.wait_reached("hold-a")
    for n in range(count):  # one packet each
        server.inject(at(n / 100, f"m{n}"))
    got: list[str] = []
    with kill_if_hung(s):
        for item in s.items():
            assert isinstance(item, LogEntry)
            got.append(item.message)
            if len(got) == count:
                s.stop()
            time.sleep(limit / 25)  # slower than the reader, never close to the limit
    assert got == [f"m{n}" for n in range(count)]
    assert len(records(server, "logcat")) == 1
    assert s.summary.devices[0].reconnects == 0
    # the queue was at its cap for longer than the limit in all
    assert s._core.outbox.backpressure()["a"] > limit


def test_the_limit_counts_every_wait_of_one_read(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Waits for room add up over the chunks of one read (logd is not read
    meanwhile): chunks that each wait less than the limit, but longer in all,
    still make the reader close the connection.
    """
    limit = 0.4
    monkeypatch.setattr(_resume, "STALL_AFTER", limit)
    monkeypatch.setattr(feed_module, "CHUNK_ENTRIES", 2)  # one read, three chunks
    x = [at(0, "x0"), at(1, "x1")]
    y = [at(2 + n / 10, f"y{n}") for n in range(6)]
    api_level(server, "a", b"24\n")
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[
                ("stdout", b"".join(x)),
                Wait("full"),
                ("stdout", b"".join(y)),
                Wait("blocked", live=True),
            ]
        ),
        staying(("stdout", b"".join(y) + at(3, "c0")), t=expect_t(2.5)),
    )
    s = begin(server, mode, buffer_lines=2)
    outbox = s._core.outbox
    wait_until(lambda: outbox.pending_lines == 2)
    server.release("full")
    items = iter(s)
    got: list[str] = []
    with kill_if_hung(s):
        # The first chunk waits about 0.25 s until the consumer takes x0; the
        # second has about 0.15 s of the limit left and gives up, so the reader
        # closes the connection; the held chunk goes in once x1 and y0 are taken.
        for waited, takes in ((0.25, 1), (0.3, 2)):
            mark = outbox.backpressure().get("a", 0.0)
            wait_until(
                lambda mark=mark, waited=waited: (
                    outbox.backpressure().get("a", 0.0) > mark + waited
                )
            )
            got += [next(items).message for _ in range(takes)]
        got += [next(items).message for _ in range(9 - len(got))]
        s.stop()
        s.join(GUARD)
    assert got == [*messages(x), *messages(y), "c0"]
    summary = s.summary.devices[0]
    assert (summary.reconnects, summary.gaps) == (1, 0)


def unread_bytes(mode: Mode, s: StreamLike) -> int:
    """Bytes that reached the only device's reader and that it has not read yet.

    The asyncio reader's transport moves what arrives into its stream reader's
    buffer at once; the blocking reader leaves it in the socket, where a peek
    from this thread sees it while the reader waits for room in the queue.
    """
    unit = s._core.units[0]
    if mode.is_async:
        assert isinstance(unit, _astream._AUnit)
        assert unit.stream is not None
        reader = unit.stream._reader
        # A private attribute of asyncio.StreamReader: fail plainly if it goes.
        assert hasattr(reader, "_buffer"), "asyncio.StreamReader has no _buffer"
        return len(getattr(reader, "_buffer"))  # noqa: B009
    assert isinstance(unit, _stream._Unit)
    assert unit.conn is not None
    try:
        return len(unit.conn.sock.recv(1 << 17, socket.MSG_PEEK))
    except TimeoutError:  # the socket keeps the reader's short timeout
        return 0


def received_sizes(mode: Mode, monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """The sizes of the network reads of logcat output that bring bytes, in order."""
    sizes: list[int] = []
    if mode.is_async:
        collect = _aadb.collect_parts

        def counted_parts(decoder: Any, chunk: bytes, pending: Any) -> Any:  # noqa: ANN401
            sizes.append(len(chunk))
            return collect(decoder, chunk, pending)

        monkeypatch.setattr(_aadb, "collect_parts", counted_parts)
    else:
        receive = _stream._receive

        def counted_receive(sock: socket.socket) -> bytes | None:
            data = receive(sock)
            if data:
                sizes.append(len(data))
            return data

        monkeypatch.setattr(_stream, "_receive", counted_receive)
    return sizes


class Put(NamedTuple):
    """One put of a chunk of lines into the queue, by either reader."""

    lines: list[str]  # the messages of the chunk's lines
    limit: float | None  # the limit the reader gave the put; None: no limit
    result: object  # the seconds waited, STALLED, or None (interrupted)


def recorded_puts(monkeypatch: pytest.MonkeyPatch) -> list[Put]:
    """Every put into a queue from now on, with its limit and result, in order."""
    puts: list[Put] = []

    def lines(segments: list[object]) -> list[str]:
        return [
            entry.message
            for segment in segments
            if isinstance(segment, list)
            for entry in segment
        ]

    put = _outbox.Outbox.put
    aput = _aoutbox.AsyncOutbox.put

    def recording(self: Any, segments: Any, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        result = put(self, segments, *args, **kwargs)
        puts.append(Put(lines(segments), kwargs.get("limit"), result))
        return result

    async def arecording(self: Any, segments: Any, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        result = await aput(self, segments, *args, **kwargs)
        puts.append(Put(lines(segments), kwargs.get("limit"), result))
        return result

    monkeypatch.setattr(_outbox.Outbox, "put", recording)
    monkeypatch.setattr(_aoutbox.AsyncOutbox, "put", arecording)
    return puts


def check_one_limit(
    puts: list[Put], batches: list[list[str]], limit: float, waited: float
) -> None:
    """The limited puts of one read's ``batches`` shared one limit.

    The first batch got the whole limit, each later one what the batches
    before it had left; the last gave up with less than ``limit - waited / 2``
    left (the batch before it waited at least ``waited``), and no other put
    gave up.
    """
    firsts = {batch[0] for batch in batches}
    read = [
        put
        for put in puts
        if put.limit is not None and put.lines and put.lines[0] in firsts
    ]
    assert [put.lines for put in read] == batches
    left = limit  # a new read: the whole limit
    for put in read[:-1]:
        assert put.limit == pytest.approx(left)
        assert isinstance(put.result, float)  # this batch alone did not give up
        left -= put.result
    gave_up = read[-1].limit
    assert gave_up == pytest.approx(left)
    assert gave_up is not None
    assert gave_up < limit - waited / 2
    assert [put.lines for put in puts if put.result is _outbox.STALLED] == [batches[-1]]


def test_the_limit_counts_every_batch_of_one_network_read(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Waits for room add up over everything one read from the device brought,
    however the reader cuts it: the asyncio reader feeds a read in batches of
    about 8 KiB, the blocking reader in chunks (here three lines each, the
    size of one batch). Each batch here waits less than the limit, the waits
    of the read in all reach it: the reader closes the connection, still
    queues the whole read (the resumed connection no longer has it) and
    resumes from its last line.

    The read is one network read: its twelve packets go out in one write while
    the reader waits for room for an earlier line, and the test lets that line
    in only once the whole write has reached the reader. The sizes the reader
    received are checked too.

    The checks do not depend on when the stall happens: the limit each put of
    the read was given shows that the batches shared one limit. The setup
    takes no part of it: w waits under a long limit, and the device gets the
    limit under test only once w waits, for the reads after w's. The limit is
    long next to the 0.3 s the test watches the second batch wait: a consumer
    descheduled for a moment after that still lets the second batch in long
    before it could give up, so it is the third batch that gives up.
    """
    limit = 3.0
    second = 0.3  # the second batch waits at least this long
    monkeypatch.setattr(_resume, "STALL_AFTER", 60.0)  # for x and w
    monkeypatch.setattr(feed_module, "CHUNK_ENTRIES", 3)
    x = [at(0, "x0"), at(1, "x1")]
    w = [at(1.5, "w")]
    # One line a packet, about 2.9 KB each (a long tag): three fill one batch.
    r = [at(2 + n / 10, f"r{n}", tag="T" * 2800) for n in range(12)]
    c = [at(4, "c0"), at(5, "c1")]
    last = 2 + 11 / 10  # the time of r11, the last line read
    one_read = sum(len(packet(1, line)) for line in r)
    received = received_sizes(mode, monkeypatch)
    puts = recorded_puts(monkeypatch)
    steps: list = [
        ("stdout", b"".join(x)),
        Wait("full"),
        ("stdout", w[0]),
        Wait("w"),
        *[("stdout", line) for line in r],
        Wait("blocked", live=True),
    ]
    api_level(server, "a", b"24\n")
    server.add_sequence(
        "logcat",
        # coalesce: the packets between two waiting points go out in one write
        ShellScript(steps=steps, coalesce=True),
        # The device no longer has the read: it reaches the client only through
        # the first connection. The -T value shows that r11 counted as read.
        staying(Omit(b"".join(r)), ("stdout", b"".join(c)), t=expect_t(last)),
    )
    s = begin(server, mode, buffer_lines=2)
    outbox = s._core.outbox
    wait_until(lambda: outbox.pending_lines == 2)  # x fills the queue
    server.release("full")
    wait_until(lambda: outbox.backpressure().get("a", 0.0) > 0)  # w waits
    s._core.units[0].stall_after = limit  # for the read under test
    server.release("w")
    assert server.wait_reached("blocked")  # the read was written
    wait_until(lambda: unread_bytes(mode, s) >= one_read)
    items = iter(s.items())
    got: list[LogEntry | Gap] = []
    with kill_if_hung(s):
        # Taking x lets w in; the reader receives the read, its first batch
        # goes in at once (the queue was below its cap), the second waits.
        got.append(next(items))
        wait_until(lambda: outbox.pending_lines == 1 + 3)
        mark = outbox.backpressure()["a"]
        wait_until(lambda: outbox.backpressure()["a"] > mark + second)
        # Taking w and the first batch lets the second in; nothing more is
        # taken until the third batch gives up with what the read had left.
        got += [next(items) for _ in range(3)]
        wait_until(lambda: any(put.result is _outbox.STALLED for put in puts))
        for item in items:  # the rest of the read, the gap and c
            got.append(item)
            if isinstance(item, LogEntry) and item.message == "c1":
                break
        s.stop()
        s.join(GUARD)
    check_one_limit(puts, [messages(r[n : n + 3]) for n in (0, 3, 6)], limit, second)
    assert [put.limit for put in puts if put.lines == ["w"]] == [60.0]
    assert one_read in received  # the twelve packets came in one read
    assert shape(got) == [*messages(x + w + r), "ring_rotated/stalled", *messages(c)]
    gap = got[len(x + w + r)]
    assert isinstance(gap, Gap)
    assert gap.start_at == BASE + timedelta(seconds=last) - feed_module.OVERLAP
    summary = s.summary.devices[0]
    assert (summary.reconnects, summary.gaps) == (1, 1)


def test_an_exit_status_in_the_read_the_reader_gave_up_on_ends_the_device(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """logcat failed in the very read whose lines found the queue full: the
    reader still closes the connection and queues the read, but the end is the
    command's failure, which ``reconnect=0`` does not retry, not a stall.

    The read is one network read: B and the exit packet go out in one write
    while the reader waits for room for w, and w gets in only once both
    reached the reader. w's wait has a long limit, so the setup takes no part
    of the one under test; B's read gets the short one.
    """
    monkeypatch.setattr(_resume, "STALL_AFTER", 60.0)
    x = [at(3, "x0")]  # fills the queue of one line
    w = [at(3.5, "w")]
    one_read = len(packet(1, b"".join(B))) + len(packet(3, b"\x02"))
    received = received_sizes(mode, monkeypatch)
    puts = recorded_puts(monkeypatch)
    api_level(server, "a", b"24\n")
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[
                ("stdout", x[0]),
                Wait("full"),
                ("stdout", w[0]),
                Wait("w"),
                ("stdout", b"".join(B)),
            ],
            exit_status=2,
            coalesce=True,  # B and the exit packet in one write
        ),
    )
    s = begin(server, mode, buffer_lines=1, reconnect=0.0)
    outbox = s._core.outbox
    wait_until(lambda: outbox.pending_lines == 1)  # x fills the queue
    server.release("full")
    wait_until(lambda: outbox.backpressure().get("a", 0.0) > 0)  # w waits
    server.release("w")
    closed_by_the_reader(server, 0)  # the fake wrote B and the exit packet
    wait_until(lambda: unread_bytes(mode, s) >= one_read)
    s._core.units[0].stall_after = STALL  # for B's read
    items = iter(s.items())
    got: list[LogEntry | Gap] = []
    error: LogprobeError | None = None
    with kill_if_hung(s):
        got.append(next(items))  # x: lets w in; B then waits past the limit
        wait_until(lambda: any(put.result is _outbox.STALLED for put in puts))
        try:
            got.extend(items)
        except LogprobeError as raised:
            error = raised
    assert one_read in received  # B and the exit packet came in one read
    assert [put.lines for put in puts if put.result is _outbox.STALLED] == [messages(B)]
    assert shape(got) == messages(x + w + B)  # the read was still queued
    assert error is not None
    assert error.code == "logcat_failed"
    summary = s.summary.devices[0]
    assert summary.error is error
    assert (summary.reconnects, summary.gaps) == (0, 0)
    assert len(records(server, "logcat")) == 1


def half_empty_waits(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Count every wait for a half-empty queue from now on, by either reader."""
    calls: list[int] = []
    wait = _outbox.Outbox.wait_half_empty
    await_ = _aoutbox.AsyncOutbox.wait_half_empty

    def counted(self: Any, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        calls.append(1)
        return wait(self, *args, **kwargs)

    async def acounted(self: Any, *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        calls.append(1)
        return await await_(self, *args, **kwargs)

    monkeypatch.setattr(_outbox.Outbox, "wait_half_empty", counted)
    monkeypatch.setattr(_aoutbox.AsyncOutbox, "wait_half_empty", acounted)
    return calls


class LongRead(NamedTuple):
    """What `long_read_with_an_exit_status` saw."""

    s: StreamLike
    got: list[LogEntry | Gap]
    error: LogprobeError | None
    stalled: list[list[str]]  # the lines of the puts that gave up
    halves: list[int]  # one entry per wait for a half-empty queue
    in_one_read: bool  # the whole read reached the reader in one network read


# The read of `long_read_with_an_exit_status`: one line a packet, about 2.9 KB
# each (a long tag), so three fill one asyncio batch; and what a resumed
# connection sends after it.
LONG = [at(4 + n / 10, f"b{n}", tag="T" * 2800) for n in range(9)]
AFTER_LONG = [at(6, "c0"), at(7, "c1")]


def long_read_with_an_exit_status(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    stderr: bytes,
) -> LongRead:
    """Let the reader give up on a read of `LONG`, ``stderr`` and ``status``.

    The read is one network read: the lines, stderr and the exit packet go out
    in one write while the reader waits for room for w, and w gets in only
    once all of it reached the reader. w's wait has a long limit; the read
    gets the short one. With exit status 1 a resumed connection sends
    `AFTER_LONG`; the device no longer has the read. The consumer takes x,
    waits until a put gave up, then takes the rest and stops after c1.
    """
    monkeypatch.setattr(_resume, "STALL_AFTER", 60.0)
    x = [at(3, "x0")]  # fills the queue of one line
    w = [at(3.5, "w")]
    one_read = sum(len(packet(1, line)) for line in LONG) + len(packet(3, b"\x02"))
    if stderr:
        one_read += len(packet(2, stderr))
    received = received_sizes(mode, monkeypatch)
    puts = recorded_puts(monkeypatch)
    halves = half_empty_waits(monkeypatch)
    steps: list = [
        ("stdout", x[0]),
        Wait("full"),
        ("stdout", w[0]),
        Wait("w"),
        *[("stdout", line) for line in LONG],
    ]
    if stderr:
        steps.append(("stderr", stderr))
    # coalesce: the lines, stderr and the exit packet go out in one write
    scripts = [ShellScript(steps=steps, exit_status=status, coalesce=True)]
    if status == 1:
        last = 4 + 8 / 10  # the time of b8, the last line read
        scripts.append(
            staying(
                Omit(b"".join(LONG)),
                ("stdout", b"".join(AFTER_LONG)),
                t=expect_t(last),
            )
        )
    api_level(server, "a", b"24\n")
    server.add_sequence("logcat", *scripts)
    s = begin(server, mode, buffer_lines=1, reconnect=0.0)
    outbox = s._core.outbox
    wait_until(lambda: outbox.pending_lines == 1)  # x fills the queue
    server.release("full")
    wait_until(lambda: outbox.backpressure().get("a", 0.0) > 0)  # w waits
    server.release("w")
    closed_by_the_reader(server, 0)  # the fake wrote the whole read
    wait_until(lambda: unread_bytes(mode, s) >= one_read)
    unit = s._core.units[0]
    long_limit = unit.stall_after  # the setup's long limit
    unit.stall_after = STALL  # for the read under test
    items = iter(s.items())
    got: list[LogEntry | Gap] = []
    error: LogprobeError | None = None
    with kill_if_hung(s):
        got.append(next(items))  # x: lets w in; the read then waits past the limit
        wait_until(lambda: any(put.result is _outbox.STALLED for put in puts))
        # Only that read is under test: a slow drain after it must not stall again.
        unit.stall_after = long_limit
        try:
            for item in items:
                got.append(item)
                if isinstance(item, LogEntry) and item.message == "c1":
                    s.stop()
            s.join(GUARD)
        except LogprobeError as raised:
            error = raised
    stalled = [put.lines for put in puts if put.result is _outbox.STALLED]
    return LongRead(s, got, error, stalled, halves, one_read in received)


@pytest.mark.parametrize("end", ["failed", "released"])
def test_an_exit_status_after_the_batch_that_gave_up_still_ends_the_connection(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    end: str,
) -> None:
    """The read the reader gave up on is several batches long and its exit
    packet comes last: the asyncio reader gives up on the first batch and
    finds the exit status only among the events it queues after the stall.
    The exit status still names the end, not the stall.

    Exit status 2 is a logcat failure, which ``reconnect=0`` does not retry.
    Exit status 1 with logd's EOF message is a released reader: the reader
    reconnects at once, without waiting for a half-empty queue and without the
    stall warning, and the gap carries the cause ``released``.
    """
    x_w = ["x0", "w"]
    if end == "failed":
        status, stderr = 2, b""
    else:
        status, stderr = 1, b"read: unexpected EOF!\n"
    with caplog.at_level(logging.WARNING, logger="logprobe"):
        seen = long_read_with_an_exit_status(server, mode, monkeypatch, status, stderr)
    assert seen.in_one_read
    # The asyncio reader gave up on the first batch, so it took the exit packet
    # after the stall; the blocking reader puts the receive's lines in one chunk.
    first = messages(LONG[:3] if mode.is_async else LONG)
    assert seen.stalled == [first]
    assert seen.halves == []  # an exit status ends no connection as a stall
    assert not [r for r in caplog.records if CLOSED in r.getMessage()]
    summary = seen.s.summary.devices[0]
    if end == "failed":
        assert shape(seen.got) == [*x_w, *messages(LONG)]  # every line once
        assert seen.error is not None
        assert seen.error.code == "logcat_failed"
        assert seen.error.details["exit_status"] == 2
        assert summary.error is seen.error
        assert (summary.reconnects, summary.gaps) == (0, 0)
        assert len(records(server, "logcat")) == 1
    else:
        assert seen.error is None
        cause = "ring_rotated/released"
        assert shape(seen.got) == [*x_w, *messages(LONG), cause, *messages(AFTER_LONG)]
        assert (summary.reconnects, summary.gaps) == (1, 1)
        assert len(records(server, "logcat")) == 2


def test_a_stall_during_a_slow_flush_delivers_every_line_and_one_gap(
    server: FakeAdbServer, mode: Mode
) -> None:
    budget = 0.5
    held = [at(4, "m4"), at(4.5, "m4.5"), at(5, "m5")]  # more than half the queue
    more = [at(6 + n / 100, f"c{n}") for n in range(20)]
    api_level(server, "a", b"24\n")
    server.add_sequence(
        "logcat",
        ShellScript(
            steps=[
                ("stdout", b"".join(A)),
                Wait("full"),
                ("stdout", b"".join(held)),
                Wait("blocked", live=True),
            ]
        ),
        staying(Omit(b"".join(held + E)), name="c1", t=expect_t(5)),
    )
    s = begin(server, mode)
    outbox = s._core.outbox
    wait_until(lambda: outbox.pending_lines == 4)
    s.stop(flush=budget)
    wait_until(lambda: server.logged)  # the marker is written at once
    token = server.logged[0][1]
    stall(server, s)
    # The consumer takes nothing for longer than the budget, before and after
    # the reader gave up, and then again while the reader waits for the queue
    # to be half empty: none of it uses up the budget.
    wait_until(lambda: outbox.backpressure()["a"] > budget)
    got: list[LogEntry | Gap] = []
    with kill_if_hung(s):
        for number, item in enumerate(s.items()):
            got.append(item)
            if number == 0:  # A was taken, the held lines went in
                wait_until(lambda: outbox._draining == 1)
                mark = outbox.backpressure()["a"]
                wait_until(lambda mark=mark: outbox.backpressure()["a"] > mark + budget)
            elif number == len(A):  # the held lines were taken: half empty
                assert server.wait_reached("c1")  # the resumed connection
                server.inject(
                    b"".join(more) + at(8, token, tag="logprobe") + at(9, "after")
                )
            time.sleep(0.004)  # a slow consumer
    written, omitted = A + held + E + more, E
    delivered = [m for m in messages(written) if m not in messages(omitted)]
    assert [m for m in shape(got) if "/" not in m] == delivered
    gaps = [item for item in got if isinstance(item, Gap)]
    assert len(gaps) == 1
    assert shape(got).index("ring_rotated/stalled") == 7  # where it resumed
    assert gaps[0].start_at == BASE + timedelta(seconds=4)
    assert s.summary.devices[0].flush == "done"
    assert outbox.backpressure()["a"] > 2 * budget


def test_a_flush_during_a_wait_for_room_keeps_the_time_already_waited(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A flush request lets the reader write its marker in the middle of a wait;
    the time waited before it still counts towards the limit of that read.

    The flush must reach the reader while it waits and before its limit. So
    that no slow test thread can miss that window, the queue holds a deadline
    back until a flush has interrupted its waiters: until then the reader waits
    as long as it takes, however long it already waited.
    """
    limit = 0.6
    monkeypatch.setattr(_resume, "STALL_AFTER", limit)
    unheld = _outbox._Ledger._slice

    def held_until_interrupted(
        self: _outbox._Ledger, deadline: float | None
    ) -> float | None:
        return unheld(self, deadline if self._interrupted else None)

    monkeypatch.setattr(_outbox._Ledger, "_slice", held_until_interrupted)
    api_level(server, "a", b"24\n")
    server.add_sequence(
        "logcat",
        first_connection(),
        staying(Omit(b"".join(B + E)), name="c1", t=expect_t(5)),
    )
    # The reader's wait in all, and whether the marker was written, when it gives up.
    seen: list[tuple[float, bool]] = []

    def recording(stall: Callable[[Any], None]) -> Callable[[Any], None]:
        def record(run: object) -> None:
            seen.append((s._core.outbox.backpressure()["a"], bool(server.logged)))
            stall(run)

        return record

    monkeypatch.setattr(_stream._Run, "stall", recording(_stream._Run.stall))
    monkeypatch.setattr(_astream._ARun, "stall", recording(_astream._ARun.stall))
    s = begin(server, mode)
    outbox = s._core.outbox
    wait_until(lambda: outbox.pending_lines == 4)
    server.release("full")
    wait_until(lambda: outbox.backpressure().get("a", 0.0) > 0.4)
    s.stop(flush=GUARD)
    wait_until(lambda: s._core.flush is not None)  # the async loop makes it real
    flush = s._core.flush
    assert flush is not None
    before = flush.waited["a"]  # the reader's wait when the flush was requested
    closed_by_the_reader(server, 0)
    token = server.logged[0][1]
    got: list[LogEntry | Gap] = []
    with kill_if_hung(s):
        for number, item in enumerate(s.items()):
            got.append(item)
            if number == len(A):  # B is being taken: the queue is half empty
                assert server.wait_reached("c1")  # the resumed connection
                server.inject(b"".join(C) + at(8, token, tag="logprobe"))
    (waited, marked), *more = seen
    assert more == []
    assert marked  # the flush interrupted the wait before the reader gave up
    # The rest of the limit after the marker, if any is left: had the wait before
    # the flush not counted, the limit in full would have come on top of it.
    assert limit <= waited < max(limit, before) + 0.25 < before + limit
    assert shape(got) == [*messages(A + B), "ring_rotated/stalled", *messages(C)]
    assert len([item for item in got if isinstance(item, Gap)]) == 1
    assert s.summary.devices[0].flush == "done"


def three_stalls_with_reconnect_0(server: FakeAdbServer, mode: Mode) -> None:
    """Make the reader stall three times in a row, with ``reconnect=0``; check that
    the stream reads on to the end without an error.

    `QUICK_LIMIT` quick ends in a row would end the device with an error.
    """
    lines = [at(n, f"m{n}") for n in range(8)]
    api_level(server, "a", b"24\n")
    # Each later connection replays from one second before the cursor: the two
    # lines read last, then one new line, which fills the queue again.
    connections = [
        ShellScript(
            steps=[
                ("stdout", b"".join(lines[max(0, 2 * k - 1) : 2 * k + 2])),
                Wait(f"f{k}"),
                ("stdout", lines[2 * k + 2]),
                Wait(f"s{k}", live=True),
            ],
            expect_t=None if k == 0 else expect_t(2 * k),
        )
        for k in range(3)
    ]
    server.add_sequence(
        "logcat", *connections, staying(("stdout", b"".join(lines[5:])), t=expect_t(6))
    )
    s = begin(server, mode, buffer_lines=2, reconnect=0.0)
    outbox = s._core.outbox
    items = iter(s)
    got: list[str] = []
    with kill_if_hung(s):
        # What the consumer takes after each stall until the queue is half empty
        # and the reader is back: the queue holds two chunks again by then.
        for k, takes in enumerate((1, 3, 2)):
            assert server.wait_reached(f"f{k}")
            wait_until(lambda: outbox.pending_lines == 2)
            server.release(f"f{k}")
            closed_by_the_reader(server, k)
            got += [next(items).message for _ in range(takes)]
        got += [next(items).message for _ in range(2)]
        s.stop()
        summary = s.join(GUARD)
    assert got == [f"m{n}" for n in range(8)]
    assert summary.devices[0].error is None
    assert (summary.devices[0].reconnects, summary.devices[0].gaps) == (3, 0)
    assert len(records(server, "getprop")) == 1


def test_repeated_stalls_are_no_failure_even_with_reconnect_0(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A stalled connection is older than the STALL seconds it waited, so it is no
    # quick end even when the two limits are equal, as they are by default.
    monkeypatch.setattr(_resume, "QUICK_END", STALL)
    three_stalls_with_reconnect_0(server, mode)


def test_a_stall_is_no_quick_end_even_on_a_coarse_slow_monotonic_clock(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The age of a stalled connection does not depend on ``time.monotonic``.

    ``monotonic`` can advance in steps of about 16 ms (Windows), so a connection
    can look up to one step shorter than the waits for room that ended it, and a
    stall of `QUICK_END` seconds would then count as a quick end. Where the steps
    fall decides whether that happens; this clock also runs at half speed, so
    that every stall here would look like a quick end if its age came from
    ``monotonic`` alone.
    """
    monkeypatch.setattr(_resume, "QUICK_END", STALL)
    step = 1 / 64

    def coarse_and_slow() -> float:
        return math.floor(time.monotonic() / 2 / step) * step

    monkeypatch.setattr(_stream, "monotonic", coarse_and_slow)
    monkeypatch.setattr(_astream, "monotonic", coarse_and_slow)
    three_stalls_with_reconnect_0(server, mode)


def test_only_the_older_device_closes_itself_when_two_devices_share_a_full_queue(
    server: FakeAdbServer, mode: Mode, caplog: pytest.LogCaptureFixture
) -> None:
    api_level(server, "a", b"24\n")
    api_level(server, "b", b"36\n")
    for serial in ("a", "b"):
        server.add_sequence(
            "logcat",
            ShellScript(
                steps=[
                    ("stdout", at(0, f"{serial}0")),
                    Wait(f"full-{serial}"),
                    ("stdout", at(1, f"{serial}1")),
                    Wait(f"end-{serial}", live=True),
                ]
            ),
            serial=serial,
        )
    server.add_sequence(
        "logcat",
        staying(("stdout", at(1, "a1") + at(2, "a2")), name="again-a", t=expect_t(1)),
        serial="a",
    )
    with caplog.at_level(logging.INFO, logger="logprobe"):
        s = begin(server, mode, "a", "b", buffer_lines=2)
        outbox = s._core.outbox
        wait_until(lambda: outbox.pending_lines == 2)
        server.release("full-a")
        server.release("full-b")
        closed_by_the_reader(server, 0, "a")
        # b has waited past the limit as well, and still holds its connection
        wait_until(lambda: outbox.backpressure().get("b", 0.0) > 2 * STALL)
        assert not records(server, "logcat", "b")[0].done.is_set()
        got: list[tuple[str | None, str]] = []
        with kill_if_hung(s):
            for entry in s:
                got.append((entry.serial, entry.message))
                if len(got) == 5:
                    s.stop()
    assert [m for who, m in got if who == "a"] == ["a0", "a1", "a2"]
    assert [m for who, m in got if who == "b"] == ["b0", "b1"]
    by_serial = {d.serial: d for d in s.summary.devices}
    assert (by_serial["a"].reconnects, by_serial["b"].reconnects) == (1, 0)
    assert len(records(server, "logcat", "b")) == 1
    assert [len(records(server, "getprop", serial)) for serial in "ab"] == [1, 1]
    said = [r.getMessage() for r in caplog.records]
    assert [m for m in said if NEWER in m] == [
        "logd on b (API level 36) cuts slow readers off itself; "
        "detect_skips is not needed there and is ignored"
    ]
    assert [m for m in said if CLOSED in m and "reader of a " in m] != []
    assert [m for m in said if CLOSED in m and "reader of b " in m] == []
