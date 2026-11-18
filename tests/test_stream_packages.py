"""Streams with a condition on the app: the package list, the verdicts, the pause.

Every test here runs against the blocking and the asyncio stream (the ``mode``
fixture), except the few about a thread or a task that only one of them has.
The fake adb server answers the package list (``pm list packages -U``,
``dumpsys package packages``) and the device clock (``date +%s``); a list that
must not answer waits at a `Wait` step that the test never releases (or
releases when it is ready), so the timings depend on no fixed sleep, except a
few reader ticks to show that nothing arrives meanwhile.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import sys
import threading
import time
from datetime import timedelta
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest

from logprobe import (
    Anr,
    Crash,
    Device,
    Gap,
    LogEntry,
    LogprobeError,
    Package,
    Tag,
    _adb,
    _astream,
    _attribution,
    _marks,
    _resume,
    _stream,
)
from logprobe import _feed as feed_module
from logprobe._adb import TICK
from logprobe._attribution import PackageAttributor
from tests.device_facts import level_dir, load, step
from tests.fake_adb_server import (
    Cut,
    FakeAdbServer,
    ShellScript,
    Wait,
    packet,
    program_of,
)
from tests.test_stream import (
    GUARD,
    PROMPT,
    attach,
    kill_if_hung,
    stream_threads,
    wait_until,
)
from tests.test_stream_resume import (
    BASE,
    expect_t,
    released,
    run,
    shape,
    staying,
)
from tests.test_stream_skips import _start_steps, received_sizes, unread_bytes

if TYPE_CHECKING:
    from collections.abc import Iterator

    from logprobe import AsyncLogStream, Condition
    from tests.fake_adb_server import ConnectionRecord, Step
    from tests.stream_modes import Mode, StreamLike


pytestmark = pytest.mark.filterwarnings("error::ResourceWarning")

PM = "pm list packages -U"
DUMPSYS = "dumpsys package packages"
CLOCK = b"%d\n" % int(
    BASE.timestamp()
)  # the device clock: lines at 0 s and later are new
A = "com.example.a"
B = "com.example.b"
C = "com.example.c"
APP_A = 10053
NEW = 19990  # app ids no list names until a test says so
NEW2 = 19991
GMS = "com.google.android.gms"
UNATTRIBUTED = "counted as unattributed (first:"
LIST_FAILED = "could not list the packages of"
TOO_LATE = "the package list did not come within the time a read may wait"


def uat(seconds: float, message: str, uid: int = APP_A, tag: str = "T") -> bytes:
    """One line ``seconds`` after ``BASE`` (the device clock) with ``uid``."""
    moment = BASE + timedelta(seconds=seconds)
    clock = f"{moment:%Y-%m-%d %H:%M:%S}.{moment.microsecond:06d} +0000"
    return f"{clock} {uid:5d}   100   100 I {tag}: {message}\n".encode()


def pm_list(uids: dict[str, int], *steps: Step) -> ShellScript:
    """``pm list packages -U`` naming ``uids`` and an unrelated app."""
    listed = {"com.example.unrelated": 10500, **uids}
    text = "".join(f"package:{name} uid:{uid}\n" for name, uid in listed.items())
    return ShellScript(steps=[*steps, ("stdout", text.encode())])


def recorded(level: int, name: str) -> list[str]:
    return step(load(level_dir(level), "C03"), name)["stdout"]


def text(lines: list[str]) -> bytes:
    return "".join(f"{line}\n" for line in lines).encode()


def records(server: FakeAdbServer, program: str) -> list[ConnectionRecord]:
    return [
        r for r in list(server.records) if program_of(r.command).startswith(program)
    ]


def programs(server: FakeAdbServer) -> list[str]:
    return [program_of(r.command).split()[0] for r in list(server.records)]


def live(name: str = "live") -> ShellScript:
    """A logcat that stays open and forwards the injected lines."""
    return staying(name=name)


def begin(
    server: FakeAdbServer,
    mode: Mode,
    where: Condition | None,
    *,
    logcat: ShellScript | None = None,
    uids: dict[str, int] | None = None,
    **kwargs: Any,  # noqa: ANN401
) -> StreamLike:
    """Start a stream of device ``a``; ``uids`` answers every list (when given)."""
    (device,) = attach(server, "a")
    server.answer("date +%s", CLOCK)
    if uids is not None:
        server.oneoff[PM] = pm_list(uids)
    server.add_sequence("logcat", live() if logcat is None else logcat)
    return mode.device_stream(device, where, **kwargs).start()


def finish(
    s: StreamLike, items: Iterator[LogEntry | Gap] | None = None
) -> list[LogEntry | Gap]:
    """Stop ``s`` and take what is left (from ``items``, an open iteration)."""
    s.stop()
    rest = list(s.items() if items is None else items)
    s.join(GUARD)
    return rest


def attributor_of(s: StreamLike) -> PackageAttributor:
    attributor = s._core.units[0].attributor
    assert attributor is not None
    return attributor


def logged(caplog: pytest.LogCaptureFixture, part: str) -> list[str]:
    return [r.getMessage() for r in caplog.records if part in r.getMessage()]


@pytest.fixture(autouse=True)
def no_threads_left() -> Iterator[None]:
    before = stream_threads()
    yield
    wait_until(lambda: stream_threads() == before, GUARD)


@pytest.fixture(autouse=True)
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    """Short reader ticks, and no pacing between two lists (tests set their own)."""
    monkeypatch.setattr(_stream, "TICK", 0.02)
    monkeypatch.setattr(_astream, "TICK", 0.02)
    monkeypatch.setattr(_attribution, "LIST_INTERVAL", 0.0)


@pytest.fixture
def fast_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_resume, "backoff", lambda _failures: 0.01)


# -- No condition on the app -------------------------------------------------------


@pytest.mark.parametrize(
    "where",
    [None, Tag("T"), Crash(package=A) | Tag("T"), Anr(package=A) | Tag("T")],
    ids=["none", "tag", "crash", "anr"],
)
def test_without_a_package_term_no_attributor_is_made_and_no_list_runs(
    server: FakeAdbServer, mode: Mode, where: Condition | None
) -> None:
    s = begin(server, mode, where, logcat=staying(("stdout", uat(-1, "m"))))
    items, error = run(s, 1)
    assert error is None
    assert shape(items) == ["m"]
    assert s._core.units[0].attributor is None
    assert programs(server) == ["logcat"]
    assert s.summary.devices[0].entries == 1


# -- The backlog -------------------------------------------------------------------


@pytest.mark.parametrize("level", [24, 36])
def test_the_startup_backlog_is_attributed_from_the_list_read_before_reading(
    server: FakeAdbServer,
    mode: Mode,
    level: int,
) -> None:
    if level == 24:
        # Android 7 does not know -U and still exits with status 0.
        server.answer(PM, b"Error: Unknown option: -U\n")
        server.answer(DUMPSYS, text(recorded(24, "dumpsys_package_packages")))
        watched, uid = "com.google.android.gsf", 10014  # shared with gms
    else:
        server.answer(PM, text(recorded(36, "pm_list_packages_U")))
        watched, uid = GMS, 10146
    backlog = recorded(level, "dump")
    s = begin(server, mode, Package(watched), logcat=staying(("stdout", text(backlog))))
    items, error = run(s, 1)
    assert error is None
    assert [(e.uid, e.package) for e in items if isinstance(e, LogEntry)] == [
        (uid, watched)
    ]
    expected = (
        ["date", "pm", "dumpsys", "logcat"] if level == 24 else ["date", "pm", "logcat"]
    )
    assert programs(server) == expected
    summary = s.summary.devices[0]
    assert (summary.unattributed, summary.entries, summary.lines) == (
        0,
        1,
        len(backlog),
    )
    assert summary.complete


def test_a_device_without_dash_u_takes_later_lists_from_dumpsys_straight_away(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_attribution, "RECHECK_INTERVAL", 0.2)
    server.answer(PM, b"Error: Unknown option: -U\n")
    server.answer(DUMPSYS, text(recorded(24, "dumpsys_package_packages")))
    s = begin(server, mode, Package(GMS))
    wait_until(
        lambda: len([r for r in records(server, DUMPSYS) if r.done.is_set()]) >= 2
    )
    finish(s)
    assert len(records(server, PM)) == 1
    assert s.summary.devices[0].unattributed == 0


def test_a_large_backlog_with_removed_apps_needs_no_second_list(
    server: FakeAdbServer, mode: Mode
) -> None:
    app_uids = (10097, 10135, 10146, 10147, 10153, 10182, 10183)
    lines = []
    for i in range(20_000):
        if i % 100 == 50:
            uid = NEW  # an app removed before the start: not in the list
        elif i % 1000 < 198:
            uid = app_uids[i % len(app_uids)]
        else:
            uid = 1000
        lines.append(uat(-100 + i / 1000, f"m{i}", uid))
    expected = [
        f"m{i}"
        for i in range(20_000)
        if i % 100 != 50 and i % 1000 < 198 and app_uids[i % 7] == 10146
    ]
    server.answer(PM, text(recorded(36, "pm_list_packages_U")))
    s = begin(server, mode, Package(GMS), logcat=staying(("stdout", b"".join(lines))))
    items, error = run(s, len(expected))
    assert error is None
    assert shape(items) == expected
    assert len(records(server, PM)) == 1
    assert s.summary.devices[0].unattributed == 0


# -- Apps installed while reading ----------------------------------------------------


def test_an_app_installed_while_reading_is_listed_before_its_read_is_delivered(
    server: FakeAdbServer, mode: Mode, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="logprobe")
    server.add_sequence(PM, pm_list({}), pm_list({A: NEW}, Wait("gate")))
    s = begin(server, mode, Package(A))
    assert server.wait_reached("live", GUARD)
    server.inject(uat(1, "installed", NEW))
    # The read waits for the second list, which waits at the gate.
    assert server.wait_reached("gate", GUARD)
    time.sleep(5 * _stream.TICK)  # a few reader ticks, far below the read's 2 s
    assert s._core.outbox.pending_lines == 0
    server.release("gate")
    items = s.items()
    with kill_if_hung(s):
        first = next(items)
    assert len(records(server, PM)) == 2
    assert isinstance(first, LogEntry)
    assert (first.message, first.package) == ("installed", A)
    assert finish(s, items) == []
    assert s.summary.devices[0].unattributed == 0
    assert logged(caplog, "is not installed") == [
        f"{A} is not installed on a; its lines are matched once a later list shows it"
    ]


def command_starts(server: FakeAdbServer, program: str) -> list[float]:
    """When the fake began to serve each command starting with ``program``."""
    return [r.started_at for r in records(server, program)]


# The fake sees a command a little after the client started it, and the delay
# varies: two commands paced 0.4 s apart may reach it a few ms closer.
COMMAND_JITTER = 0.05


def test_lists_for_new_apps_are_paced(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_attribution, "LIST_INTERVAL", 0.4)
    server.add_sequence(PM, pm_list({}), pm_list({A: NEW}), pm_list({A: NEW, B: NEW2}))
    s = begin(server, mode, Package(A, B))
    assert server.wait_reached("live", GUARD)
    items = s.items()
    with kill_if_hung(s):
        server.inject(uat(1, "first", NEW))
        assert shape([next(items)]) == ["first"]
        server.inject(uat(2, "second", NEW2))
        second = next(items)
    assert isinstance(second, LogEntry)
    assert second.package == B
    starts = command_starts(server, PM)
    assert len(starts) == 3
    assert starts[1] - starts[0] >= 0.4 - COMMAND_JITTER
    assert starts[2] - starts[1] >= 0.4 - COMMAND_JITTER
    finish(s, items)
    assert s.summary.devices[0].unattributed == 0


def test_a_reinstall_seen_by_the_regular_list_counts_the_old_lines(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(_attribution, "RECHECK_INTERVAL", 0.5)
    server.add_sequence(
        PM, pm_list({A: APP_A}), pm_list({A: NEW}), ShellScript([Wait("third")])
    )
    backlog = b"".join(uat(-3 + k, f"old{k}") for k in range(3))
    s = begin(server, mode, Package(A), logcat=staying(("stdout", backlog)))
    items = s.items()
    with kill_if_hung(s):
        assert shape([next(items) for _ in range(3)]) == ["old0", "old1", "old2"]
    assert server.wait_reached("third", GUARD)
    finish(s, items)
    assert s.summary.devices[0].unattributed == 3
    assert logged(caplog, "has a new uid") == [
        "a: com.example.a has a new uid: 3 lines judged with the old uid since "
        "the last list are counted as unattributed"
    ]


# -- Failed lists ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "answers",
    [
        {PM: ShellScript([("stderr", b"boom\n")], exit_status=1)},
        {PM: ShellScript([], exit_status=None)},
        {PM: ShellScript([Cut("stdout", b"package:a uid:10053\n", 8)])},
        {
            PM: ShellScript([("stdout", b"package:com.example.a\n")]),
            DUMPSYS: ShellScript([("stdout", b"Error: Could not access the PM\n")]),
        },
    ],
    ids=["exit-1", "no-exit-status", "cut", "unusable-output"],
)
def test_a_failed_start_list_lets_the_stream_run_and_counts_the_app_lines(
    server: FakeAdbServer,
    mode: Mode,
    caplog: pytest.LogCaptureFixture,
    answers: dict[str, ShellScript],
) -> None:
    server.oneoff.update(answers)
    backlog = uat(-2, "app", APP_A) + uat(-1, "new", NEW) + uat(0, "sync", 1000, "sync")
    s = begin(
        server, mode, Package(A) | Tag("sync"), logcat=staying(("stdout", backlog))
    )
    items, error = run(s, 1)
    assert error is None
    assert shape(items) == ["sync"]
    summary = s.summary.devices[0]
    assert (summary.unattributed, summary.entries) == (2, 1)
    assert not summary.complete
    assert len(logged(caplog, LIST_FAILED)) == 1
    assert len(logged(caplog, UNATTRIBUTED)) == 1


def test_an_adb_error_during_the_start_list_fails_the_start(
    server: FakeAdbServer, mode: Mode
) -> None:
    (device,) = attach(server, "a")
    server.answer("date +%s", CLOCK)
    server.fail[f'shell,v2,raw:export ANDROID_LOG_TAGS=""; exec {PM}'] = (
        "device offline"
    )
    s = mode.device_stream(device, package=A)
    with pytest.raises(LogprobeError) as info:
        s.start()
    assert info.value.code == "device_offline"
    assert info.value.details["serial"] == "a"
    assert "logcat" not in programs(server)


def test_a_failed_list_while_reading_counts_that_reads_lines_and_warns_once(
    server: FakeAdbServer, mode: Mode, caplog: pytest.LogCaptureFixture
) -> None:
    server.add_sequence(PM, pm_list({A: APP_A}), ShellScript([], exit_status=1))
    s = begin(server, mode, ~Package(A))
    assert server.wait_reached("live", GUARD)
    items = s.items()
    server.inject(uat(1, "n1", NEW) + uat(1.5, "a", APP_A))
    server.inject(uat(2, "n2", NEW2))  # the device is blind now: no list
    with kill_if_hung(s):
        got = [next(items), next(items)]
    assert shape(got) == ["n1", "n2"]
    assert finish(s, items) == []
    assert len(records(server, PM)) == 2
    assert s.summary.devices[0].unattributed == 2
    assert len(logged(caplog, LIST_FAILED)) == 1
    assert logged(caplog, UNATTRIBUTED) == [
        "a: lines whose app could not be determined are counted as unattributed "
        "(first: the package list did not succeed (exit status 1))"
    ]


# -- Order and combinations ------------------------------------------------------------


def test_a_resume_gap_next_to_reads_that_wait_for_lists_keeps_its_place(
    server: FakeAdbServer, mode: Mode, fast_backoff: None
) -> None:
    del fast_backoff
    server.add_sequence(PM, pm_list({}), pm_list({A: NEW}), pm_list({A: NEW, B: NEW2}))
    first = (
        uat(0, "m0", NEW)
        + uat(0.5, "m1", 1000)
        + uat(1, "m2", 1000)
        + uat(2, "m3", 1000)
    )
    replay = uat(2, "m3", 1000) + uat(3, "m4", NEW2)  # m1 and m2 are gone
    logcat = [released(("stdout", first)), staying(("stdout", replay), t=expect_t(2))]
    (device,) = attach(server, "a")
    server.answer("date +%s", CLOCK)
    server.add_sequence("logcat", *logcat)
    s = mode.device_stream(device, Package(A, B), reconnect=60.0).start()
    items, error = run(s, 3)
    assert error is None
    assert shape(items) == ["m0", "ring_rotated/released", "m4"]
    assert s.summary.devices[0].unattributed == 0


@pytest.mark.parametrize(
    ("where", "kept"),
    [
        (Package("com.android.calllogbackup"), "com.android.calllogbackup"),
        (Package("com.android.providers.contacts"), "com.android.providers.contacts"),
        (
            Package("com.android.providers.contacts")
            & Package("com.android.calllogbackup"),
            "com.android.calllogbackup",
        ),
        (~Package("com.android.calllogbackup"), None),
    ],
    ids=["first", "second", "both", "not-first"],
)
def test_two_packages_with_one_uid_match_each_others_lines(
    server: FakeAdbServer, mode: Mode, where: Condition, kept: str | None
) -> None:
    server.answer(PM, text(recorded(36, "pm_list_packages_U")))
    backlog = uat(-2, "shared", 10097) + uat(-1, "sync", 1000, "sync")
    s = begin(server, mode, where | Tag("sync"), logcat=staying(("stdout", backlog)))
    items, error = run(s, 1 if kept is None else 2)
    assert error is None
    entries = [e for e in items if isinstance(e, LogEntry)]
    if kept is None:
        assert shape(items) == ["sync"]
    else:
        assert [(e.message, e.package) for e in entries] == [
            ("shared", kept),
            ("sync", None),
        ]


def test_a_flush_marker_in_a_read_that_needs_a_list_is_done_after_the_list(
    server: FakeAdbServer, mode: Mode
) -> None:
    server.add_sequence(PM, pm_list({}), pm_list({A: NEW}))

    def echo(tag: str, message: str) -> bytes:
        marker = uat(5, message, 1000, tag)
        return uat(4, "before", NEW) + marker + uat(6, "after", NEW)

    server.echo_logged = echo
    s = begin(server, mode, Package(A))
    assert server.wait_reached("live", GUARD)
    s.stop(flush=5.0)
    items = list(s.items())
    summary = s.join(GUARD)
    assert shape(items) == ["before"]
    device = summary.devices[0]
    assert (device.flush, device.unattributed) == ("done", 0)


def test_a_system_uid_package_warns_once_and_matches_its_uid(
    server: FakeAdbServer, mode: Mode, caplog: pytest.LogCaptureFixture
) -> None:
    settings = "com.android.settings"
    server.answer(PM, text(recorded(36, "pm_list_packages_U")))
    s = begin(
        server, mode, Package(settings), logcat=staying(("stdout", uat(-1, "s", 1000)))
    )
    items, error = run(s, 1)
    assert error is None
    assert [(e.message, e.package) for e in items if isinstance(e, LogEntry)] == [
        ("s", settings)
    ]
    assert logged(caplog, "system uid") == [
        "a: com.android.settings runs under the system uid 1000: every process of "
        "that uid is taken as belonging to it"
    ]


def test_a_secondary_user_line_matches_by_app_id(
    server: FakeAdbServer, mode: Mode
) -> None:
    server.answer(PM, text(recorded(36, "pm_list_packages_U")))
    backlog = uat(-2, "user10", 1010146) + uat(-1, "isolated", 99146)
    s = begin(
        server, mode, Package(GMS) | Tag("x"), logcat=staying(("stdout", backlog))
    )
    items, error = run(s, 1)
    assert error is None
    assert [(e.message, e.package) for e in items if isinstance(e, LogEntry)] == [
        ("user10", GMS)
    ]
    assert len(records(server, PM)) == 1  # the isolated process needs no list


def test_the_list_survives_a_reconnect(
    server: FakeAdbServer, mode: Mode, fast_backoff: None
) -> None:
    del fast_backoff
    server.oneoff[PM] = pm_list({A: APP_A})
    (device,) = attach(server, "a")
    server.answer("date +%s", CLOCK)
    server.add_sequence(
        "logcat",
        released(("stdout", uat(0, "m0"))),
        staying(("stdout", uat(0, "m0") + uat(1, "m1")), t=expect_t(0)),
    )
    s = mode.device_stream(device, Package(A), reconnect=60.0).start()
    items, error = run(s, 2)
    assert error is None
    assert [(e.message, e.package) for e in items if isinstance(e, LogEntry)] == [
        ("m0", A),
        ("m1", A),
    ]
    assert len(records(server, PM)) == 1
    assert s.summary.devices[0].reconnects == 1


# -- The pause: slow lists, stop, kill and flush ---------------------------------


def test_a_list_that_does_not_answer_is_cut_at_the_reads_time_limit(
    server: FakeAdbServer, mode: Mode, caplog: pytest.LogCaptureFixture
) -> None:
    server.add_sequence(PM, pm_list({A: APP_A}), ShellScript([Wait("slow")]))
    s = begin(server, mode, ~Package(A))
    assert server.wait_reached("live", GUARD)
    items = s.items()
    injected = time.monotonic()
    server.inject(uat(1, "x", NEW))
    with kill_if_hung(s):
        first = next(items)
    arrived = time.monotonic() - injected
    assert _attribution.LIST_WAIT - TICK <= arrived <= _attribution.LIST_WAIT + PROMPT
    assert shape([first]) == ["x"]
    assert server.wait_done(records(server, PM)[1].index, GUARD)
    # The list had the read's whole time: the device counts as failed.
    assert attributor_of(s).blind
    assert finish(s, items) == []
    assert s.summary.devices[0].unattributed == 1
    assert logged(caplog, LIST_FAILED) == [
        "could not list the packages of a (the command 'pm list packages -U' was "
        "cut at a time limit of the stream); lines whose app is not known are "
        "counted as unattributed until the next list in 30 s"
    ]
    assert logged(caplog, UNATTRIBUTED) == [
        "a: lines whose app could not be determined are counted as unattributed "
        "(first: the package list was cut at a time limit of the stream)"
    ]


@pytest.mark.parametrize("held", [0.5, 1.2], ids=["list-cut", "no-list"])
@pytest.mark.parametrize("limit", ["no-limit", "stall-limit"])
def test_a_reads_time_for_its_list_counts_from_its_network_read(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    limit: str,
    held: float,
) -> None:
    """The time a read waits for its list counts from when it was received,
    and waits for room before it count: the second batch of a read (the
    asyncio reader feeds a read in batches of about 8 KiB, the blocking reader
    here in chunks of three lines, the size of one batch) waits for room, and
    the third, which needs a list, has only what is left of the read's time.

    The read is one network read: it goes out in one write while the reader
    waits for room for an earlier line, and that line goes in only once the
    whole write has reached the reader. After a wait of 0.5 s the list starts
    and is cut at the read's 2 s, a failed list; after 1.2 s less than the
    second a list needs is left, and no list is started.
    """
    limited = limit == "stall-limit"
    monkeypatch.setattr(feed_module, "CHUNK_ENTRIES", 3)
    monkeypatch.setattr(_resume, "STALL_AFTER", 60.0)  # never reached here
    x = uat(0, "x0", 1000) + uat(1, "x1", 1000)
    w = uat(1.5, "w", 1000)
    # One line a packet, about 2.9 KB each (a long tag): three fill one batch.
    r = [
        uat(2 + n / 10, f"r{n}", NEW if n == 8 else 1000, "T" * 2800) for n in range(9)
    ]
    one_read = sum(len(packet(1, line)) for line in r)
    sizes = received_sizes(mode, monkeypatch)
    server.add_sequence(PM, pm_list({A: APP_A}), ShellScript([Wait("slow")]))
    if limited:
        server.answer("getprop", b"24\n")
    steps: list = [
        ("stdout", x),
        Wait("full"),
        ("stdout", w),
        Wait("w"),
        *[("stdout", line) for line in r],
        Wait("blocked", live=True),
    ]
    # coalesce: the packets between two waiting points go out in one write
    script = ShellScript(steps=steps, coalesce=True)
    s = begin(
        server, mode, ~Package(A), logcat=script, buffer_lines=2, detect_skips=limited
    )
    assert (s._core.units[0].stall_after is not None) == limited
    outbox = s._core.outbox
    wait_until(lambda: outbox.pending_lines == 2)  # x fills the queue
    server.release("full")
    wait_until(lambda: outbox.backpressure().get("a", 0.0) > 0)  # w waits
    server.release("w")
    assert server.wait_reached("blocked", GUARD)
    wait_until(lambda: unread_bytes(mode, s) >= one_read)
    items = iter(s.items())
    # Taking x0 (with x1, one chunk) lets w in; the reader receives the read,
    # r0-r2 go in at once (the queue was below its cap), r3-r5 wait.
    with kill_if_hung(s):
        got = [next(items)]
        received = time.monotonic()
        wait_until(lambda: outbox.pending_lines == 1 + 3)
        mark = outbox.backpressure()["a"]
        wait_until(lambda: outbox.backpressure()["a"] > mark + held)
        # Taking w and r0-r2 lets r3-r5 in; r8 then needs a list.
        got += [next(items) for _ in range(3)]
        if held < _attribution.LIST_WAIT - _attribution.LIST_MIN_TIME:
            wait_until(lambda: len(records(server, PM)) == 2)
            assert server.wait_done(records(server, PM)[1].index, GUARD)
            cut = time.monotonic() - received
            assert (
                _attribution.LIST_WAIT - PROMPT
                <= cut
                <= _attribution.LIST_WAIT + PROMPT
            )
            cause = "the package list was cut at a time limit of the stream"
        else:
            cause = TOO_LATE
        got += [next(items) for _ in range(8)]
    assert finish(s, items) == []
    assert one_read in sizes  # the nine packets came in one network read
    assert shape(got) == ["x0", "x1", "w", *(f"r{n}" for n in range(9))]
    listed = cause != TOO_LATE
    assert len(records(server, PM)) == 1 + listed
    assert attributor_of(s).blind == listed
    assert s.summary.devices[0].unattributed == 1
    assert len(logged(caplog, LIST_FAILED)) == listed
    assert logged(caplog, UNATTRIBUTED) == [
        f"a: lines whose app could not be determined are counted as unattributed "
        f"(first: {cause})"
    ]


def test_a_read_that_could_list_only_after_its_time_does_not_wait(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_attribution, "LIST_INTERVAL", 30.0)
    server.add_sequence(PM, pm_list({A: APP_A}), pm_list({A: APP_A, B: NEW}))
    s = begin(server, mode, ~Package(A))
    assert server.wait_reached("live", GUARD)
    items = s.items()
    injected = time.monotonic()
    server.inject(uat(1, "x", NEW))
    with kill_if_hung(s):
        assert shape([next(items)]) == ["x"]
    assert time.monotonic() - injected <= PROMPT
    assert finish(s, items) == []
    assert len(records(server, PM)) == 1
    assert not attributor_of(s).blind
    assert s.summary.devices[0].unattributed == 1


@pytest.mark.parametrize("request_name", ["stop", "kill"])
def test_a_stop_or_kill_while_a_read_waits_for_the_pacing_ends_the_reader_at_once(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    request_name: str,
) -> None:
    # The read comes just after the start list: it waits for the pacing,
    # which ends early enough for a list within its time.
    pacing_time = _attribution.LIST_WAIT - _attribution.LIST_MIN_TIME - 0.1
    monkeypatch.setattr(_attribution, "LIST_INTERVAL", pacing_time)
    pacing = threading.Event()
    original = PackageAttributor.ready_at

    def watched(self: PackageAttributor) -> float:
        pacing.set()
        return original(self)

    monkeypatch.setattr(PackageAttributor, "ready_at", watched)
    server.add_sequence(PM, pm_list({}), pm_list({A: NEW}))
    s = begin(server, mode, ~Package(C))
    assert server.wait_reached("live", GUARD)
    server.inject(uat(1, "n", NEW))
    assert pacing.wait(GUARD)
    assert len(records(server, PM)) == 1  # the read waits; no list started
    requested = time.monotonic()
    getattr(s, request_name)()
    mode.wait_readers_ended(s, GUARD)
    assert time.monotonic() - requested < PROMPT
    items = list(s.items())
    summary = s.join(GUARD).devices[0]
    assert len(records(server, PM)) == 1
    if request_name == "stop":
        assert shape(items) == ["n"]
        assert summary.unattributed == 1
    else:
        assert items == []
        assert summary.unattributed == 0


@pytest.mark.parametrize("request_name", ["stop", "kill"])
def test_a_stop_or_kill_during_a_slow_list_ends_the_reader_within_a_tick(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    request_name: str,
) -> None:
    monkeypatch.setattr(feed_module, "CHUNK_ENTRIES", 1)  # one line a chunk
    server.add_sequence(PM, pm_list({A: APP_A}), ShellScript([Wait("slow")]))
    logcat = staying(("stdout", uat(-1, "first", 1000)), name="live")
    s = begin(server, mode, ~Package(A), logcat=logcat, buffer_lines=1)
    assert server.wait_reached("live", GUARD)
    # x waits for the list; s, a later chunk of the same read, needs none.
    server.inject(uat(1, "x", NEW) + uat(1.5, "s", 1000))
    assert server.wait_reached("slow", GUARD)
    requested = time.monotonic()
    getattr(s, request_name)()
    mode.wait_readers_ended(s, GUARD)
    assert time.monotonic() - requested < PROMPT
    items = list(s.items())
    summary = s.join(GUARD).devices[0]
    if request_name == "stop":
        # The full queue does not hold up the read after a stop.
        assert shape(items) == ["first", "x", "s"]
        assert (summary.unattributed, summary.entries) == (1, 3)
    else:
        # Nothing of the read is judged or counted after the kill.
        assert items == []
        assert (summary.unattributed, summary.entries) == (0, 1)


@pytest.mark.parametrize("budget", [0.5, 1.0])
def test_a_flush_during_a_slow_list_cuts_it_at_the_flush_deadline(
    server: FakeAdbServer, mode: Mode, caplog: pytest.LogCaptureFixture, budget: float
) -> None:
    server.add_sequence(PM, pm_list({A: APP_A}), ShellScript([Wait("slow")]))
    s = begin(server, mode, ~Package(A))
    assert server.wait_reached("live", GUARD)
    server.inject(uat(1, "x", NEW))
    assert server.wait_reached("slow", GUARD)
    requested = time.monotonic()
    s.stop(flush=budget)
    assert server.wait_done(records(server, PM)[1].index, GUARD)
    cut = time.monotonic() - requested
    assert budget - TICK <= cut <= budget + PROMPT
    summary = s.join(GUARD).devices[0]
    assert time.monotonic() - requested <= budget + PROMPT
    # The reader was in the list when the flush began: no marker was written.
    assert summary.flush == "timed_out"
    assert shape(list(s.items())) == ["x"]
    assert summary.unattributed == 1
    # A list that was started and then cut is a failed list, however short.
    assert attributor_of(s).blind
    assert logged(caplog, LIST_FAILED) == [
        "could not list the packages of a (the command 'pm list packages -U' was "
        "cut at a time limit of the stream); lines whose app is not known are "
        "counted as unattributed until the next list in 30 s"
    ]


def test_a_stop_during_a_slow_list_delivers_the_rest_of_its_network_read(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stop while the first part of one network read waits for its list
    still delivers the rest of that read: the asyncio reader feeds it in
    batches of about 8 KiB, and the first packet (three long lines) fills one.
    """
    big = b"".join(
        uat(1 + n / 10, f"x{n}", NEW if n == 2 else 1000, "T" * 2800) for n in range(3)
    )
    rest = uat(1.5, "s", 1000)
    one_read = len(packet(1, big)) + len(packet(1, rest))
    sizes = received_sizes(mode, monkeypatch)
    server.add_sequence(PM, pm_list({A: APP_A}), ShellScript([Wait("slow")]))
    steps: list = [Wait("go"), ("stdout", big), ("stdout", rest)]
    # coalesce: both packets go out in one write
    logcat = ShellScript(steps=[*steps, Wait("blocked", live=True)], coalesce=True)
    s = begin(server, mode, ~Package(A), logcat=logcat)
    server.release("go")
    assert server.wait_reached("slow", GUARD)
    s.stop()
    items = list(s.items())
    summary = s.join(GUARD).devices[0]
    assert one_read in sizes  # the two packets came in one network read
    assert shape(items) == ["x0", "x1", "x2", "s"]
    assert (summary.unattributed, summary.gaps) == (1, 0)


def test_a_reads_time_for_its_list_counts_from_when_its_bytes_arrived(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The read's stderr is logged after its bytes arrived; a slow log handler
    uses up 1.2 s of the read's 2 s, so too little is left for a list."""
    slow = 1.2

    class Slow(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            if "wrote to stderr" in record.getMessage():
                time.sleep(slow)

    handler = Slow()
    logger = logging.getLogger("logprobe")
    logger.addHandler(handler)
    monkeypatch.setattr(logger, "level", logging.WARNING)
    sizes = received_sizes(mode, monkeypatch)
    line = uat(1, "x", NEW)
    server.add_sequence(PM, pm_list({A: APP_A}), pm_list({A: APP_A, B: NEW}))
    steps: list = [Wait("go"), ("stderr", b"slow\n"), ("stdout", line)]
    logcat = ShellScript(steps=[*steps, Wait("blocked", live=True)], coalesce=True)
    try:
        s = begin(server, mode, ~Package(A), logcat=logcat)
        server.release("go")
        items = s.items()
        with kill_if_hung(s):
            got = [next(items)]
        assert finish(s, items) == []
    finally:
        logger.removeHandler(handler)
    assert len(packet(2, b"slow\n")) + len(packet(1, line)) in sizes
    assert shape(got) == ["x"]
    assert len(records(server, PM)) == 1  # less than a second left: no list
    assert s.summary.devices[0].unattributed == 1


def test_a_regular_list_that_hangs_fails_after_the_command_limit(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(_attribution, "RECHECK_INTERVAL", 0.3)
    monkeypatch.setattr(_attribution, "LIST_WAIT", 0.2)  # a read's limit only
    monkeypatch.setattr(_marks, "COMMAND_LIMIT", 0.6)
    server.add_sequence(PM, pm_list({A: APP_A}), ShellScript([Wait("hang")]))
    s = begin(server, mode, Package(A))
    assert server.wait_reached("hang", GUARD)
    began = time.monotonic()
    assert server.wait_done(records(server, PM)[1].index, GUARD)
    took = time.monotonic() - began
    assert 0.6 - TICK <= took <= 0.6 + PROMPT
    wait_until(lambda: attributor_of(s).blind)  # the reader took its outcome
    finish(s)
    assert logged(caplog, LIST_FAILED) == [
        "could not list the packages of a (the command 'pm list packages -U' did "
        "not finish within 0.6 seconds); lines whose app is not known are counted "
        "as unattributed until the next list in 0.3 s"
    ]


def test_a_regular_list_may_take_longer_than_a_read_may_wait(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The regular list does not pause reading, so it has the time of any
    device command, not the time a read may wait for a list."""
    monkeypatch.setattr(_attribution, "RECHECK_INTERVAL", 0.3)
    monkeypatch.setattr(_attribution, "LIST_WAIT", 0.2)
    server.add_sequence(PM, pm_list({A: APP_A}), pm_list({A: NEW}, Wait("slow")))
    s = begin(server, mode, Package(A))
    assert server.wait_reached("slow", GUARD)
    no_more_regular(monkeypatch)
    time.sleep(0.4)  # twice what a read may wait
    server.release("slow")
    assert server.wait_done(records(server, PM)[1].index, GUARD)
    items = s.items()
    with kill_if_hung(s):
        wait_until(lambda: attributor_of(s)._app_ids == {A: NEW})
        server.inject(uat(1, "new", NEW))
        got = next(items)
    assert isinstance(got, LogEntry)
    assert (got.message, got.package) == ("new", A)
    assert finish(s, items) == []
    assert not attributor_of(s).blind
    assert len(records(server, PM)) == 2


def test_the_regular_list_keeps_the_pacing(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_attribution, "LIST_INTERVAL", 0.4)
    monkeypatch.setattr(_attribution, "RECHECK_INTERVAL", 0.05)
    s = begin(server, mode, Package(A), uids={A: APP_A})
    wait_until(lambda: len(records(server, PM)) >= 4)
    finish(s)
    starts = command_starts(server, PM)
    gaps = [later - earlier for earlier, later in itertools.pairwise(starts)]
    assert min(gaps) >= 0.4 - COMMAND_JITTER


def test_a_flush_marker_in_a_read_whose_list_hangs_times_out(
    server: FakeAdbServer, mode: Mode
) -> None:
    server.add_sequence(PM, pm_list({}), ShellScript([Wait("slow")]))

    def echo(tag: str, message: str) -> bytes:
        marker = uat(5, message, 1000, tag)
        return uat(4, "before", NEW) + marker + uat(6, "after", NEW)

    server.echo_logged = echo
    s = begin(server, mode, ~Package(C))
    assert server.wait_reached("live", GUARD)
    requested = time.monotonic()
    s.stop(flush=1.0)
    items = list(s.items())
    summary = s.join(GUARD)
    assert time.monotonic() - requested <= 1.0 + PROMPT
    assert shape(items) == ["before"]
    device = summary.devices[0]
    # The read takes a list only with enough time left; on a slow runner it
    # may not, and then the marker ends the flush. Either way the line counts.
    started = len(records(server, PM)) == 2
    assert (device.flush, device.unattributed) == (
        ("timed_out", 1) if started else ("done", 1)
    )


def test_a_flush_does_not_wait_for_a_regular_list_that_hangs(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The regular list starts with the flush and hangs; the marker comes back
    and the stream ends without waiting for the list, whose outcome is lost."""
    server.add_sequence(PM, pm_list({A: APP_A}), ShellScript([Wait("slow")]))
    cores: list[Any] = []

    def due(_self: PackageAttributor, _now: float) -> bool:
        return (
            bool(cores) and cores[0].flush is not None and len(records(server, PM)) == 1
        )

    monkeypatch.setattr(PackageAttributor, "list_due", due)
    s = begin(server, mode, Package(A))
    cores.append(s._core)
    assert server.wait_reached("live", GUARD)
    s.stop(flush=GUARD)
    assert server.wait_reached("slow", GUARD)  # after the marker was written
    ((tag, message),) = server.logged
    requested = time.monotonic()
    server.inject(uat(5, message, 1000, tag))  # the marker comes back
    summary = s.join(GUARD).devices[0]
    assert time.monotonic() - requested <= PROMPT
    assert len(records(server, PM)) == 2
    assert server.wait_done(records(server, PM)[1].index, GUARD)
    assert summary.flush == "done"
    assert not attributor_of(s).blind
    assert logged(caplog, LIST_FAILED) == []


def test_an_adb_error_from_a_list_while_reading_counts_as_a_failed_list(
    server: FakeAdbServer, mode: Mode, caplog: pytest.LogCaptureFixture
) -> None:
    request = f'shell,v2,raw:export ANDROID_LOG_TAGS=""; exec {PM}'
    s = begin(server, mode, ~Package(A), uids={A: APP_A})
    server.fail[request] = "device offline"  # from the second list on
    assert server.wait_reached("live", GUARD)
    items = s.items()
    server.inject(uat(1, "n1", NEW))
    with kill_if_hung(s):
        got = [next(items)]
        server.inject(uat(2, "n2", NEW2))  # the device is blind now: no list
        got.append(next(items))
    assert finish(s, items) == []
    assert shape(got) == ["n1", "n2"]
    assert server.requests.count(request) == 2
    assert attributor_of(s).blind
    summary = s.summary.devices[0]
    assert (summary.error, summary.unattributed) == (None, 2)
    (warning,) = logged(caplog, LIST_FAILED)
    assert "'pm list packages -U' failed (" in warning
    assert len(logged(caplog, UNATTRIBUTED)) == 1


def test_an_absent_app_id_stays_absent_across_a_list_that_does_not_name_it(
    server: FakeAdbServer, mode: Mode
) -> None:
    server.add_sequence(PM, pm_list({}), pm_list({}), pm_list({B: NEW2}))
    s = begin(server, mode, ~Package(A))
    assert server.wait_reached("live", GUARD)
    items = s.items()
    with kill_if_hung(s):
        server.inject(uat(1, "n1", NEW))  # the second list: NEW is absent
        got = [next(items)]
        server.inject(uat(2, "m", NEW2))  # the third list names NEW2, not NEW
        got.append(next(items))
        server.inject(uat(3, "n2", NEW))  # still absent: no fourth list
        got.append(next(items))
    assert finish(s, items) == []
    assert shape(got) == ["n1", "m", "n2"]
    assert len(records(server, PM)) == 3
    assert s.summary.devices[0].unattributed == 2  # n1, n2: app not checked


def test_a_flush_shorter_than_the_pacing_wait_ends_the_wait_at_once(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(_attribution, "LIST_INTERVAL", 0.9)
    pacing = threading.Event()
    original = PackageAttributor.ready_at

    def watched(self: PackageAttributor) -> float:
        pacing.set()
        return original(self)

    monkeypatch.setattr(PackageAttributor, "ready_at", watched)
    server.add_sequence(PM, pm_list({}), pm_list({B: NEW}))
    server.echo_logged = lambda tag, message: uat(5, message, 1000, tag)
    s = begin(server, mode, ~Package(C))
    assert server.wait_reached("live", GUARD)
    server.inject(uat(1, "n", NEW))
    assert pacing.wait(GUARD)
    requested = time.monotonic()
    s.stop(flush=0.3)
    items = list(s.items())
    summary = s.join(GUARD).devices[0]
    assert time.monotonic() - requested <= 0.3 + PROMPT
    assert shape(items) == ["n"]
    assert len(records(server, PM)) == 1
    assert (summary.flush, summary.unattributed) == ("done", 1)
    assert logged(caplog, UNATTRIBUTED) == [
        "a: lines whose app could not be determined are counted as unattributed "
        "(first: a deadline of the flush or of the start marker passed while it "
        "waited for the package list)"
    ]


@pytest.mark.parametrize("request_name", ["stop", "kill"])
@pytest.mark.parametrize("command", ["date +%s", PM])
def test_a_stop_or_kill_during_the_clock_or_the_start_list_ends_the_start(
    server: FakeAdbServer, mode: Mode, command: str, request_name: str
) -> None:
    (device,) = attach(server, "a")
    server.answer("date +%s", CLOCK)
    server.oneoff[PM] = pm_list({A: APP_A})
    server.oneoff[command] = ShellScript([Wait("gate")])
    s = mode.device_stream(device, package=A)

    def requester() -> None:
        assert server.wait_reached("gate", GUARD)
        getattr(s, request_name)()

    thread = threading.Thread(target=requester)
    thread.start()
    assert s.start() is s
    thread.join(GUARD)
    assert programs(server) == (
        ["date"] if command.startswith("date") else ["date", "pm"]
    )
    assert s.join(GUARD).devices[0].error is None
    assert list(s) == []


def test_a_hanging_start_list_is_cut_at_its_limit_and_leaves_the_device_blind(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(_marks, "COMMAND_LIMIT", 0.5)
    (device,) = attach(server, "a")
    server.answer("date +%s", CLOCK)
    server.oneoff[PM] = ShellScript([Wait("hang")])
    server.add_sequence("logcat", staying(("stdout", uat(-1, "x", NEW))))
    began = time.monotonic()
    s = mode.device_stream(device, ~Package(A)).start()
    assert 0.5 - TICK <= time.monotonic() - began <= 0.5 + LATE_START
    assert attributor_of(s).blind
    items, error = run(s, 1)
    assert error is None
    assert shape(items) == ["x"]
    assert s.summary.devices[0].unattributed == 1
    assert logged(caplog, LIST_FAILED) == [
        "could not list the packages of a (the command 'pm list packages -U' did "
        "not finish within the 0.5 seconds the start gives the list); lines whose "
        "app is not known are counted as unattributed until the next list in 30 s"
    ]


# A start does more than the list; this bounds the rest on a slow machine.
LATE_START = 1.5


# -- The start ---------------------------------------------------------------------


@pytest.mark.parametrize("since", [None, "now"])
def test_start_reads_the_clock_and_the_list_after_the_api_level(
    server: FakeAdbServer, mode: Mode, since: str | None
) -> None:
    devices = attach(server, "a", "b")
    server.answer("date +%s", CLOCK)
    server.answer("getprop", b"36\n")
    server.add_sequence(PM, pm_list({A: APP_A}), serial="a")
    server.add_sequence(
        PM, ShellScript([("stdout", b"Error: Unknown option: -U\n")]), serial="b"
    )
    server.add_sequence(
        DUMPSYS,
        ShellScript([("stdout", b"  Package [x.y] (1):\n    userId=10001\n")]),
        serial="b",
    )
    for serial in ("a", "b"):
        server.add_sequence("logcat", live(f"live-{serial}"), serial=serial)
    s = mode.stream(devices, package=A, since=since, detect_skips=True).start()
    s.stop()
    s.join(GUARD)
    if since is None:
        a = ["features", "getprop", "date", "pm"]
        b = ["features", "getprop", "date", "pm", "dumpsys"]
    else:
        a = ["features", "getprop", "pm", "date", "log"]
        b = ["features", "getprop", "pm", "dumpsys", "date", "log"]
    expected = [(w, "a") for w in a] + [(w, "b") for w in b]
    expected += [("logcat", "a"), ("logcat", "b")]
    assert _start_steps(server) == expected
    for unit in s._core.units:
        assert unit.attributor is not None
        assert unit.attributor.listed
        assert unit.attributor.boundary == (
            None if since else float(int(BASE.timestamp()))
        )


def test_a_clock_that_cannot_be_read_leaves_the_boundary_unset(
    server: FakeAdbServer, mode: Mode, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="logprobe")
    (device,) = attach(server, "a")
    server.answer("date +%s", b"", exit_status=1)
    server.oneoff[PM] = pm_list({A: APP_A})
    server.add_sequence("logcat", live())
    s = mode.device_stream(device, package=A).start()
    assert attributor_of(s).boundary is None
    finish(s)
    assert logged(caplog, "could not read the clock") == [
        "could not read the clock of a (exit status 1); app lines of removed "
        "packages in the backlog are checked against a new list"
    ]


# -- asyncio only --------------------------------------------------------------------


# -- The regular list beside the reader ------------------------------------------


def regular_soon(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the regular list due 0.3 s after the start list."""
    monkeypatch.setattr(_attribution, "RECHECK_INTERVAL", 0.3)


def no_more_regular(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the list after the running one due only in 30 s (no third list)."""
    monkeypatch.setattr(_attribution, "RECHECK_INTERVAL", 30.0)


def waiting_for_regular(monkeypatch: pytest.MonkeyPatch) -> threading.Event:
    """An event set once a read waits for the regular list (either reader)."""
    waiting = threading.Event()
    original = _stream._listing_wait_step

    def watched(*args: Any) -> Any:  # noqa: ANN401
        waiting.set()
        return original(*args)

    monkeypatch.setattr(_stream, "_listing_wait_step", watched)
    monkeypatch.setattr(_astream, "_listing_wait_step", watched)
    return waiting


def own_threads() -> set[threading.Thread]:
    """The threads of this process, without the fake server's handlers."""
    return {t for t in threading.enumerate() if "process_request" not in t.name}


def loop_tasks(mode: Mode) -> set[str]:
    """The names of the tasks on the asyncio mode's loop (none when blocking)."""
    loop = mode._loop
    if loop is None:
        return set()

    async def names() -> set[str]:
        current = asyncio.current_task()
        return {t.get_name() for t in asyncio.all_tasks() if t is not current}

    return loop.call(names())


def test_lines_the_last_list_explains_keep_arriving_while_the_regular_list_runs(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    regular_soon(monkeypatch)
    server.add_sequence(PM, pm_list({A: APP_A}), pm_list({A: APP_A}, Wait("regular")))
    s = begin(server, mode, Package(A))
    assert server.wait_reached("regular", GUARD)
    no_more_regular(monkeypatch)
    pending = records(server, PM)[1]
    items = s.items()
    with kill_if_hung(s):
        for k in range(3):
            server.inject(uat(1 + k, f"m{k}"))
            got = next(items)
            assert isinstance(got, LogEntry)
            assert (got.message, got.package) == (f"m{k}", A)
        assert not pending.done.is_set()  # the list still waits at its gate
        server.release("regular")
        assert server.wait_done(pending.index, GUARD)
        server.inject(uat(4, "m3"))
        assert shape([next(items)]) == ["m3"]
    assert finish(s, items) == []
    assert len(records(server, PM)) == 2
    summary = s.summary.devices[0]
    assert (summary.entries, summary.unattributed) == (4, 0)


def test_reads_during_the_regular_list_are_judged_with_the_list_before_it(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The regular list sees a reinstall: A moved to NEW, and B got A's old uid.
    regular_soon(monkeypatch)
    server.add_sequence(
        PM, pm_list({A: APP_A}), pm_list({A: NEW, B: APP_A}, Wait("regular"))
    )
    backlog = uat(-2, "old0") + uat(-1, "old1")
    s = begin(server, mode, Package(A), logcat=staying(("stdout", backlog)))
    items = s.items()
    with kill_if_hung(s):
        assert shape([next(items), next(items)]) == ["old0", "old1"]
        assert server.wait_reached("regular", GUARD)
        no_more_regular(monkeypatch)
        server.inject(uat(1, "during"))  # A's by the list before
        during = next(items)
        assert isinstance(during, LogEntry)
        assert (during.message, during.package) == ("during", A)
        server.release("regular")
        wait_until(lambda: logged(caplog, "has a new uid"))  # the reader took it
        # b-line has A's old uid: until the next regular list it may be a late line
        # of A, so it is counted, and Package(A) does not take it.
        server.inject(uat(2, "b-line") + uat(3, "a-line", NEW))
        after = next(items)
    assert isinstance(after, LogEntry)
    assert (after.message, after.package) == ("a-line", A)
    assert finish(s, items) == []
    assert len(records(server, PM)) == 2
    assert s.summary.devices[0].unattributed == 3 + 1
    assert logged(caplog, "has a new uid") == [
        "a: com.example.a has a new uid: 3 lines judged with the old uid since "
        "the last list are counted as unattributed"
    ]
    assert logged(caplog, UNATTRIBUTED) == [
        "a: lines whose app could not be determined are counted as unattributed "
        "(first: its uid belonged to a watched package until a recent package "
        "list)"
    ]


def test_a_read_that_needs_a_list_while_the_regular_list_runs_waits_for_it(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    regular_soon(monkeypatch)
    waiting = waiting_for_regular(monkeypatch)
    server.add_sequence(
        PM, pm_list({A: APP_A}), pm_list({A: APP_A, B: NEW}, Wait("regular"))
    )
    s = begin(server, mode, Package(A, B))
    assert server.wait_reached("regular", GUARD)
    no_more_regular(monkeypatch)
    server.inject(uat(1, "n", NEW))
    assert waiting.wait(GUARD)
    assert len(records(server, PM)) == 2  # no list of the read's own
    assert s._core.outbox.pending_lines == 0
    server.release("regular")
    items = s.items()
    with kill_if_hung(s):
        first = next(items)
    assert isinstance(first, LogEntry)
    assert (first.message, first.package) == ("n", B)
    assert finish(s, items) == []
    assert len(records(server, PM)) == 2
    assert s.summary.devices[0].unattributed == 0


def test_a_read_takes_its_own_list_when_the_regular_one_did_not_name_its_app(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The regular list started before the read arrived, so it cannot tell
    that the read's app is absent; the read's own list keeps the pacing."""
    monkeypatch.setattr(_attribution, "LIST_INTERVAL", 0.4)
    regular_soon(monkeypatch)
    waiting = waiting_for_regular(monkeypatch)
    server.add_sequence(
        PM,
        pm_list({A: APP_A}),
        pm_list({A: APP_A}, Wait("regular")),
        pm_list({A: APP_A, B: NEW}),
    )
    s = begin(server, mode, Package(A, B))
    assert server.wait_reached("regular", GUARD)
    no_more_regular(monkeypatch)
    server.inject(uat(1, "n", NEW))
    assert waiting.wait(GUARD)
    server.release("regular")
    items = s.items()
    with kill_if_hung(s):
        first = next(items)
    assert isinstance(first, LogEntry)
    assert (first.message, first.package) == ("n", B)
    assert finish(s, items) == []
    starts = command_starts(server, PM)
    assert len(starts) == 3
    assert starts[1] - starts[0] >= 0.4 - COMMAND_JITTER  # the regular list
    assert starts[2] - starts[1] >= 0.4 - COMMAND_JITTER  # and the read after it
    assert s.summary.devices[0].unattributed == 0


@pytest.mark.parametrize("request_name", ["stop", "kill"])
def test_a_stop_or_kill_while_the_regular_list_hangs_ends_within_a_tick(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    request_name: str,
) -> None:
    regular_soon(monkeypatch)
    server.add_sequence(PM, pm_list({A: APP_A}), ShellScript([Wait("hang")]))
    threads_before = own_threads()
    tasks_before = loop_tasks(mode)
    s = begin(server, mode, Package(A))
    assert server.wait_reached("hang", GUARD)
    if mode.is_async:
        assert "logprobe-list-a" in loop_tasks(mode)
        assert own_threads() == threads_before  # a task, not a thread
    else:
        assert "logprobe-list-a" in {t.name for t in own_threads()}
    requested = time.monotonic()
    getattr(s, request_name)()
    mode.wait_readers_ended(s, GUARD)
    assert time.monotonic() - requested < PROMPT
    assert list(s.items()) == []
    s.join(GUARD)
    assert own_threads() == threads_before
    assert loop_tasks(mode) == tasks_before
    assert server.wait_done(records(server, PM)[1].index, GUARD)
    assert not attributor_of(s).blind  # its outcome was not used


def test_a_reader_that_ends_by_itself_does_not_wait_for_the_regular_list(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The logcat ends (no reconnect) while the regular list hangs. The adb
    waits are not cut shorter than the list's own limit here, so a list told
    to give up notices only at that limit (the command limit, 2 s here); the
    end of the device does not wait for it, ``join`` does, and nothing is left
    after ``join``."""
    regular_soon(monkeypatch)
    monkeypatch.setattr(_adb, "TICK", 10.0)
    monkeypatch.setattr(_marks, "COMMAND_LIMIT", 2.0)
    server.add_sequence(PM, pm_list({A: APP_A}), ShellScript([Wait("hang")]))
    threads_before = stream_threads()  # the guard's timer may outlive its cancel
    tasks_before = loop_tasks(mode)
    logcat = ShellScript([Wait("go"), ("stdout", uat(1, "x"))])
    s = begin(server, mode, Package(A), logcat=logcat, reconnect=0)
    assert server.wait_reached("hang", GUARD)
    no_more_regular(monkeypatch)
    released_at = time.monotonic()
    server.release("go")
    items: list[LogEntry | Gap] = []
    ended = pytest.raises(LogprobeError, match="the log connection to a ended")
    with kill_if_hung(s), ended:
        items.extend(s.items())
    assert time.monotonic() - released_at < PROMPT
    assert shape(items) == ["x"]
    with pytest.raises(LogprobeError, match="the log connection to a ended"):
        s.join(GUARD)
    assert stream_threads() == threads_before
    assert loop_tasks(mode) == tasks_before
    assert server.wait_done(records(server, PM)[1].index, GUARD)


def test_a_flush_bounds_a_read_that_waits_for_the_regular_list(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The line before the marker needs a list while the regular list hangs:
    the read waits for that list only until the flush budget runs out."""
    regular_soon(monkeypatch)
    server.add_sequence(PM, pm_list({}), ShellScript([Wait("hang")]))
    server.echo_logged = lambda tag, message: (
        uat(4, "before", NEW) + uat(5, message, 1000, tag)
    )
    s = begin(server, mode, ~Package(C))
    assert server.wait_reached("hang", GUARD)
    no_more_regular(monkeypatch)
    began = time.monotonic()
    s.stop(flush=0.3)
    with kill_if_hung(s):
        items = list(s.items())
    took = time.monotonic() - began
    summary = s.join(GUARD).devices[0]
    assert took < 0.3 + PROMPT
    assert shape(items) == ["before"]
    assert len(records(server, PM)) == 2  # it waited, and took no list of its own
    assert (summary.flush, summary.unattributed) == ("timed_out", 1)


@pytest.mark.parametrize("mode", ["blocking"], indirect=True)
def test_a_regular_list_whose_thread_cannot_start_is_a_failed_list(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    regular_soon(monkeypatch)
    original = threading.Thread.start

    def start(thread: threading.Thread) -> None:
        if thread.name.startswith("logprobe-list-"):
            msg = "can't start new thread"
            raise RuntimeError(msg)
        original(thread)

    monkeypatch.setattr(threading.Thread, "start", start)
    server.add_sequence(PM, pm_list({A: APP_A}))
    s = begin(server, mode, ~Package(A))
    with kill_if_hung(s):
        wait_until(lambda: attributor_of(s).blind)
        no_more_regular(monkeypatch)
        items = s.items()
        server.inject(uat(1, "n1", NEW))
        got = [next(items)]
    assert finish(s, items) == []
    assert shape(got) == ["n1"]
    assert len(records(server, PM)) == 1  # no command ran for it
    assert s.summary.devices[0].unattributed == 1
    (warning,) = logged(caplog, LIST_FAILED)
    assert "'pm list packages -U' failed (could not start its thread: " in warning


@pytest.mark.parametrize("mode", ["async"], indirect=True)
def test_leaving_async_with_by_an_exception_leaves_no_list_task(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    regular_soon(monkeypatch)
    server.add_sequence(PM, pm_list({A: APP_A}), ShellScript([Wait("hang")]))
    tasks_before = loop_tasks(mode)
    s = begin(server, mode, Package(A))
    assert server.wait_reached("hang", GUARD)
    inner = cast("AsyncLogStream", mode.unwrap(s))
    assert mode._loop is not None

    async def leave() -> set[str]:
        body = RuntimeError("body")
        await inner.__aexit__(RuntimeError, body, None)
        current = asyncio.current_task()
        return {t.get_name() for t in asyncio.all_tasks() if t is not current}

    assert mode._loop.call(leave()) == tasks_before  # right after, in the same task
    assert server.wait_done(records(server, PM)[1].index, GUARD)


def test_an_unexpected_failure_of_the_regular_list_ends_the_stream(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    regular_soon(monkeypatch)

    def broken(*_args: object) -> None:
        msg = "a bug in the list"
        raise RuntimeError(msg)

    async def abroken(*_args: object) -> None:
        broken()

    monkeypatch.setattr(_stream, "_run_list_commands", broken)
    monkeypatch.setattr(_astream, "_run_listing", abroken)
    s = begin(server, mode, Package(A), uids={A: APP_A})
    with kill_if_hung(s), pytest.raises(LogprobeError, match="a bug in the list"):
        list(s.items())
    with pytest.raises(LogprobeError, match="a bug in the list"):
        s.join(GUARD)


def test_a_failure_of_the_regular_list_after_its_reader_ended_is_logged(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    regular_soon(monkeypatch)
    started = threading.Event()
    pause = threading.Event()

    def late_bug(_core: object, _unit: object, listing: Any) -> None:  # noqa: ANN401
        started.set()
        while not listing.abandoned:
            pause.wait(0.005)
        msg = "a late bug"
        raise RuntimeError(msg)

    async def alate_bug(*_args: object) -> None:
        started.set()
        try:
            await asyncio.sleep(GUARD)
        except asyncio.CancelledError:
            msg = "a late bug"
            raise RuntimeError(msg) from None

    monkeypatch.setattr(_stream, "_run_list_commands", late_bug)
    monkeypatch.setattr(_astream, "_run_listing", alate_bug)
    s = begin(server, mode, Package(A), uids={A: APP_A})
    assert started.wait(GUARD)
    assert finish(s) == []
    (record,) = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert record.getMessage() == (
        "a: the regular package list failed after the reader had ended"
    )
    assert isinstance(record.exc_info, tuple)
    assert str(record.exc_info[1]) == "a late bug"
    assert s.summary.devices[0].error is None


def test_a_regular_list_that_fails_makes_the_device_blind_and_warns_once(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    regular_soon(monkeypatch)
    failing = ShellScript([Wait("regular"), ("stderr", b"boom\n")], exit_status=1)
    server.add_sequence(PM, pm_list({A: APP_A}), failing)
    s = begin(server, mode, ~Package(A))
    assert server.wait_reached("regular", GUARD)
    no_more_regular(monkeypatch)
    assert not attributor_of(s).blind  # not until its outcome arrives
    server.release("regular")
    wait_until(lambda: attributor_of(s).blind)
    items = s.items()
    with kill_if_hung(s):
        server.inject(uat(1, "n1", NEW))
        got = [next(items)]
        server.inject(uat(2, "n2", NEW2))
        got.append(next(items))
    assert finish(s, items) == []
    assert shape(got) == ["n1", "n2"]
    assert len(records(server, PM)) == 2  # blind for 30 s: no list for a read
    assert s.summary.devices[0].unattributed == 2
    (warning,) = logged(caplog, LIST_FAILED)
    assert warning.startswith(
        "could not list the packages of a (the command 'pm list packages -U' "
    )
    assert warning.endswith("until the next list in 30 s")
    assert logged(caplog, UNATTRIBUTED) == [
        "a: lines whose app could not be determined are counted as unattributed "
        "(first: the last package list failed)"
    ]


def test_a_flush_marker_in_the_read_that_waits_for_the_pacing_is_done(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The marker comes in the same read as a line whose list would have to
    wait longer than the budget: the line is delivered at once, unattributed,
    and the flush is done well within its budget."""
    monkeypatch.setattr(_attribution, "LIST_INTERVAL", 0.9)
    server.add_sequence(PM, pm_list({}), pm_list({B: NEW}))
    server.echo_logged = lambda tag, message: (
        uat(4, "before", NEW) + uat(5, message, 1000, tag)
    )
    s = begin(server, mode, ~Package(C))
    assert server.wait_reached("live", GUARD)
    s.stop(flush=0.3)
    items = list(s.items())
    summary = s.join(GUARD).devices[0]
    assert shape(items) == ["before"]
    assert len(records(server, PM)) == 1
    assert (summary.flush, summary.unattributed) == ("done", 1)


def test_lines_of_a_watched_app_removed_before_a_lagging_reader_reads_them_count(
    server: FakeAdbServer, mode: Mode, caplog: pytest.LogCaptureFixture
) -> None:
    """A was installed and removed while the reader was behind the device, so
    no list names it: its lines are left out and counted as unattributed."""
    server.add_sequence(PM, pm_list({}), pm_list({}))  # A at neither list
    s = begin(server, mode, Package(A) | Tag("keep"))
    assert server.wait_reached("live", GUARD)
    items = s.items()
    with kill_if_hung(s):
        lines = uat(1, "a1", NEW) + uat(2, "a2", NEW) + uat(3, "k", 1000, "keep")
        wait_until(lambda: server.inject(lines) == 1)
        got = [next(items)]
    assert finish(s, items) == []
    assert shape(got) == ["k"]
    assert len(records(server, PM)) == 2
    summary = s.summary.devices[0]
    assert (summary.unattributed, summary.complete) == (2, False)
    assert logged(caplog, UNATTRIBUTED) == [
        "a: lines whose app could not be determined are counted as unattributed "
        "(first: the app of its uid could not be checked: the package list taken "
        "after the line was read did not name the uid)"
    ]


def test_a_stop_while_the_flush_marker_is_written_delivers_the_rest_of_the_read(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A flush is pending when the first part of one network read waits for
    its list; after it, the reader writes the marker, and a stop comes then.
    The asyncio reader still has the second batch of that read (the first
    packet, three long lines, fills a batch), and delivers it."""
    big = b"".join(
        uat(1 + n / 10, f"x{n}", NEW if n == 2 else 1000, "T" * 2800) for n in range(3)
    )
    rest = uat(1.5, "s", 1000)
    one_read = len(packet(1, big)) + len(packet(1, rest))
    sizes = received_sizes(mode, monkeypatch)
    server.add_sequence(PM, pm_list({A: APP_A}), pm_list({A: APP_A}, Wait("slow")))
    server.add_sequence("log", ShellScript([Wait("marker")]))
    steps: list = [Wait("go"), ("stdout", big), ("stdout", rest)]
    # coalesce: both packets go out in one write
    logcat = ShellScript(steps=[*steps, Wait("blocked", live=True)], coalesce=True)
    s = begin(server, mode, ~Package(A), logcat=logcat)
    server.release("go")
    assert server.wait_reached("slow", GUARD)
    s.stop(flush=GUARD)
    server.release("slow")
    assert server.wait_reached("marker", GUARD)
    s.stop()
    items = list(s.items())
    summary = s.join(GUARD).devices[0]
    assert one_read in sizes  # the two packets came in one network read
    assert shape(items) == ["x0", "x1", "x2", "s"]
    # x2: the list for its read does not name its app id, so it is counted.
    assert (summary.flush, summary.unattributed, summary.gaps) == ("cancelled", 1, 0)


def test_no_thread_is_started_by_an_astream_with_an_app_condition(
    server: FakeAdbServer,
) -> None:
    (device,) = attach(server, "a")
    server.answer("date +%s", CLOCK)
    server.add_sequence(PM, pm_list({}), pm_list({A: NEW}))
    server.add_sequence("logcat", staying(("stdout", uat(1, "new", NEW))))

    def own_threads() -> set[str]:
        # The fake server's handler threads come and go with its connections.
        return {
            t.name for t in threading.enumerate() if "process_request" not in t.name
        }

    before = own_threads()
    seen: set[str] = set()

    async def sample() -> None:
        while True:
            seen.update(own_threads())
            await asyncio.sleep(0.001)

    async def scenario() -> list[str]:
        watcher = asyncio.create_task(sample())
        try:
            async with device.astream(Package(A)) as s:
                got = []
                async for entry in s:
                    got.append(entry.package or "")
                    s.stop()
                return got
        finally:
            watcher.cancel()

    assert asyncio.run(scenario()) == [A]
    assert seen <= before


# -- Timing of the lists, and what a read may use ------------------------------


def taken(s: StreamLike) -> bool:
    """Whether no regular list of device ``a`` is left for the reader to take."""
    unit = s._core.units[0]
    return unit.listing is None and getattr(unit, "alisting", None) is None


def slow_list_cleanup(monkeypatch: pytest.MonkeyPatch, seconds: float) -> None:
    """Make the asyncio list task hang, and take ``seconds`` to end once cancelled."""

    async def hanging(*_args: object) -> None:
        try:
            await asyncio.sleep(GUARD)
        except asyncio.CancelledError:
            await asyncio.sleep(seconds)
            raise

    monkeypatch.setattr(_astream, "_run_listing", hanging)


def test_the_pacing_counts_from_the_first_command_of_a_regular_list(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The regular list's runner starts its command 0.3 s after the list
    began; a read's own list right after it keeps 0.4 s from that command,
    as the fake sees the commands."""
    monkeypatch.setattr(_attribution, "LIST_INTERVAL", 0.4)
    regular_soon(monkeypatch)
    run_commands = _stream._run_list_commands
    run_listing = _astream._run_listing

    def late(*args: Any) -> None:  # noqa: ANN401
        time.sleep(0.3)
        run_commands(*args)

    async def alate(*args: Any) -> None:  # noqa: ANN401
        await asyncio.sleep(0.3)
        await run_listing(*args)

    monkeypatch.setattr(_stream, "_run_list_commands", late)
    monkeypatch.setattr(_astream, "_run_listing", alate)
    server.add_sequence(
        PM, pm_list({A: APP_A}), pm_list({A: APP_A}), pm_list({A: APP_A, B: NEW})
    )
    s = begin(server, mode, Package(A, B))
    wait_until(lambda: len(records(server, PM)) == 2)
    no_more_regular(monkeypatch)
    assert server.wait_done(records(server, PM)[1].index, GUARD)
    items = s.items()
    with kill_if_hung(s):
        wait_until(lambda: taken(s))
        server.inject(uat(1, "n", NEW))
        first = next(items)
    assert isinstance(first, LogEntry)
    assert (first.message, first.package) == ("n", B)
    assert finish(s, items) == []
    starts = command_starts(server, PM)
    assert len(starts) == 3
    assert starts[2] - starts[1] >= 0.4 - COMMAND_JITTER


def test_a_read_waits_for_the_recovery_list_while_the_device_is_blind(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The start list failed; the line of a new app arrives while the next
    list runs, and waits for it (no list of its own: the device is blind)."""
    regular_soon(monkeypatch)
    waiting = waiting_for_regular(monkeypatch)
    server.add_sequence(
        PM, ShellScript([], exit_status=1), pm_list({A: NEW}, Wait("recovery"))
    )
    s = begin(server, mode, Package(A))
    assert attributor_of(s).blind
    assert server.wait_reached("recovery", GUARD)
    no_more_regular(monkeypatch)
    server.inject(uat(1, "new", NEW))
    assert waiting.wait(GUARD)
    assert s._core.outbox.pending_lines == 0
    server.release("recovery")
    items = s.items()
    with kill_if_hung(s):
        first = next(items)
    assert isinstance(first, LogEntry)
    assert (first.message, first.package) == ("new", A)
    assert finish(s, items) == []
    assert len(records(server, PM)) == 2
    assert s.summary.devices[0].unattributed == 0


def test_a_blind_device_starts_no_list_for_a_read_after_the_recovery_list_fails(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    regular_soon(monkeypatch)
    waiting = waiting_for_regular(monkeypatch)
    failing = ShellScript([Wait("recovery")], exit_status=1)
    server.add_sequence(PM, ShellScript([], exit_status=1), failing)
    s = begin(server, mode, Package(A) | Tag("keep"))
    assert server.wait_reached("recovery", GUARD)
    no_more_regular(monkeypatch)
    server.inject(uat(1, "new", NEW) + uat(1.5, "k", NEW, "keep"))
    assert waiting.wait(GUARD)
    server.release("recovery")
    items = s.items()
    with kill_if_hung(s):
        first = next(items)
    assert shape([first]) == ["k"]
    assert finish(s, items) == []
    assert len(records(server, PM)) == 2  # no list of the read's own
    assert s.summary.devices[0].unattributed == 1  # new


def test_a_list_for_a_read_whose_answer_is_ready_after_the_flush_deadline_fails(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The read's list answers within the flush budget, but its output is
    ready only after it (a slow parse): the list is not used for the read
    and counts as failed."""
    server.add_sequence(PM, pm_list({}), pm_list({A: NEW}, Wait("slow")))
    s = begin(server, mode, Package(A))
    assert server.wait_reached("live", GUARD)
    server.inject(uat(1, "new", NEW))
    assert server.wait_reached("slow", GUARD)
    take = _attribution.ListJob.take

    def slow_take(job: _attribution.ListJob, *args: Any) -> None:  # noqa: ANN401
        time.sleep(0.5)  # past the flush deadline
        take(job, *args)

    monkeypatch.setattr(_attribution.ListJob, "take", slow_take)
    s.stop(flush=0.2)
    server.release("slow")
    with kill_if_hung(s):
        items = list(s.items())
    summary = s.join(GUARD).devices[0]
    assert items == []  # judged without a list: not A's
    assert (summary.unattributed, summary.flush) == (1, "timed_out")
    assert attributor_of(s).blind
    (warning,) = logged(caplog, LIST_FAILED)
    assert "'pm list packages -U' was cut at a time limit of the stream" in warning


def test_a_regular_list_ready_after_the_reads_deadline_waits_for_the_next_read(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The regular list ends while the reader is held after a read arrived,
    until that read's time for a list has passed: the read is judged without
    it, and the list applies from the next network read."""
    monkeypatch.setattr(_attribution, "LIST_WAIT", 0.3)  # below LIST_MIN_TIME
    regular_soon(monkeypatch)
    server.add_sequence(PM, pm_list({}), pm_list({A: NEW}, Wait("regular")))
    held: list[bool] = []
    decode = _stream._decode
    queue_read = _astream._queue_read

    def held_decode(*args: Any) -> Any:  # noqa: ANN401
        _core, _run, unit, _data, received = args
        if not held:  # wait for the list's thread, then for the read's time
            held.append(True)
            unit.listing.thread.join(GUARD)
            time.sleep(max(received + 0.3 - time.perf_counter(), 0) + 0.05)
        return decode(*args)

    async def held_queue(*args: Any) -> None:  # noqa: ANN401
        _core, unit, run, _chunks, batch = args
        if batch is not None and not held:
            held.append(True)
            await asyncio.wait((unit.alisting.task,), timeout=GUARD)
            late = run.stream.received_at + 0.3 - time.perf_counter()
            await asyncio.sleep(max(late, 0) + 0.05)
        await queue_read(*args)

    s = begin(server, mode, Package(A))
    assert server.wait_reached("regular", GUARD)
    no_more_regular(monkeypatch)
    monkeypatch.setattr(_stream, "_decode", held_decode)
    monkeypatch.setattr(_astream, "_queue_read", held_queue)
    server.inject(uat(1, "first", NEW))
    server.release("regular")
    wait_until(lambda: held)
    items = s.items()
    with kill_if_hung(s):
        wait_until(lambda: taken(s))
        server.inject(uat(2, "second", NEW))
        got = next(items)
    assert isinstance(got, LogEntry)
    assert (got.message, got.package) == ("second", A)
    assert finish(s, items) == []
    assert len(records(server, PM)) == 2
    assert s.summary.devices[0].unattributed == 1  # first


def test_a_regular_list_that_ends_during_a_network_read_waits_for_the_next_one(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The regular list (A reinstalled, its old uid given to B) ends while the
    first packet of one network read is queued; the second packet of that
    read is still judged with the list before it, in both readers."""
    if mode.is_async and sys.platform == "win32":
        pytest.skip("a proactor loop may split the one write into several reads")
    regular_soon(monkeypatch)
    filler = b"".join(uat(1 + n / 10, f"x{n}", 1000, "T" * 2800) for n in range(3))
    late = uat(1.5, "late")
    one_read = len(packet(1, filler)) + len(packet(1, late))
    sizes = received_sizes(mode, monkeypatch)
    server.add_sequence(
        PM, pm_list({A: APP_A}), pm_list({A: NEW, B: APP_A}, Wait("regular"))
    )
    steps: list = [Wait("go"), ("stdout", filler), ("stdout", late)]
    logcat = ShellScript(steps=[*steps, Wait("blocked", live=True)], coalesce=True)
    held: list[bool] = []
    decode = _stream._decode
    queue_read = _astream._queue_read

    def held_decode(*args: Any) -> Any:  # noqa: ANN401
        unit = args[2]
        if not held and unit.listing is not None:
            held.append(True)
            unit.listing.thread.join(GUARD)  # the list ended during the receive
        return decode(*args)

    async def held_queue(*args: Any) -> None:  # noqa: ANN401
        await queue_read(*args)
        _core, unit, _run, _chunks, batch = args
        if batch is not None and not held and unit.alisting is not None:
            held.append(True)  # the list ends between the read's two batches
            await asyncio.wait((unit.alisting.task,), timeout=GUARD)

    monkeypatch.setattr(_stream, "_decode", held_decode)
    monkeypatch.setattr(_astream, "_queue_read", held_queue)
    s = begin(server, mode, Package(A), logcat=logcat)
    assert server.wait_reached("regular", GUARD)
    no_more_regular(monkeypatch)
    server.release("go")
    server.release("regular")
    items = s.items()
    with kill_if_hung(s):
        got = next(items)
    assert held
    assert one_read in sizes  # the two packets came in one network read
    assert isinstance(got, LogEntry)
    assert (got.message, got.package) == ("late", A)
    with kill_if_hung(s):
        wait_until(lambda: taken(s))
    assert finish(s, items) == []
    assert s.summary.devices[0].unattributed == 1  # late, by the reinstall


@pytest.mark.parametrize(
    ("first", "second", "blocking", "asyncio_"),
    [
        ({A: APP_A}, {A: NEW}, (["new"], 3), (["old0", "old1", "old2", "new"], 3)),
        (
            {C: APP_A},
            {A: APP_A, B: NEW},
            (["old0", "old1", "old2", "new"], 0),
            (["new"], 3),
        ),
    ],
    ids=["reinstall", "uid-given-again"],
)
def test_a_read_that_waits_for_the_regular_list_may_be_judged_with_two_lists(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    first: dict[str, int],
    second: dict[str, int],
    blocking: tuple[list[str], int],
    asyncio_: tuple[list[str], int],
) -> None:
    """One network read: three lines of APP_A that fill an asyncio batch, then
    a line of an app id the first list does not name, which waits for the
    regular list that runs. The blocking reader judges the whole receive with
    the new list; the asyncio reader judges the first batch at once with the
    old one. Either way every line judged with a list that the new one shows
    was outdated is counted."""
    regular_soon(monkeypatch)
    waiting = waiting_for_regular(monkeypatch)
    old = b"".join(uat(1 + n / 10, f"old{n}", APP_A, "T" * 2800) for n in range(3))
    new = uat(1.5, "new", NEW)
    one_read = len(packet(1, old)) + len(packet(1, new))
    sizes = received_sizes(mode, monkeypatch)
    server.add_sequence(PM, pm_list(first), pm_list(second, Wait("regular")))
    steps: list = [Wait("go"), ("stdout", old), ("stdout", new)]
    logcat = ShellScript(steps=[*steps, Wait("blocked", live=True)], coalesce=True)
    s = begin(server, mode, Package(A, B), logcat=logcat)
    assert server.wait_reached("regular", GUARD)
    no_more_regular(monkeypatch)
    server.release("go")
    assert waiting.wait(GUARD)
    server.release("regular")
    items = s.items()
    got: list[LogEntry | Gap] = []
    with kill_if_hung(s):
        while not got or shape(got)[-1] != "new":
            got.append(next(items))
    assert finish(s, items) == []
    assert one_read in sizes  # the two packets came in one network read
    delivered, counted = asyncio_ if mode.is_async else blocking
    assert shape(got) == delivered
    assert s.summary.devices[0].unattributed == counted
    assert len(records(server, PM)) == 2


def test_a_flush_that_times_out_during_a_list_still_delivers_the_rest_of_the_read(
    server: FakeAdbServer, mode: Mode
) -> None:
    """One network read: the first packet fills an asyncio batch and its line
    of a new app waits for a list until the flush budget runs out. The second
    packet (a line and a notice that makes a gap) is still delivered."""
    big = b"".join(
        uat(1 + n / 10, f"x{n}", NEW if n == 1 else 1000, "T" * 2800) for n in range(3)
    )
    notice = "uid=10077(com.example.x) expire 3 lines"
    rest = uat(1.5, "s", 1000) + uat(1.6, notice, 1000, "chatty")
    server.add_sequence(PM, pm_list({A: APP_A}), pm_list({A: APP_A}, Wait("slow")))
    steps: list = [Wait("go"), ("stdout", big), ("stdout", rest)]
    logcat = ShellScript(steps=[*steps, Wait("blocked", live=True)], coalesce=True)
    s = begin(server, mode, ~Package(A), logcat=logcat)
    server.release("go")
    assert server.wait_reached("slow", GUARD)
    s.stop(flush=0.3)
    with kill_if_hung(s):
        items = list(s.items())
    summary = s.join(GUARD).devices[0]
    assert shape(items) == [
        "x0",
        "x1",
        "x2",
        "s",
        "device_reported/notice",
        notice,
    ]
    assert (summary.flush, summary.unattributed, summary.gaps) == ("timed_out", 1, 1)


def held_tending(monkeypatch: pytest.MonkeyPatch) -> threading.Event:
    """An event that, once set, keeps either reader from looking at the
    regular list while it reads, as if the list ended after its last look."""
    hold = threading.Event()
    for module in (_stream, _astream):
        original = module._tend_listing

        def tend(core: Any, unit: Any, original: Any = original) -> None:  # noqa: ANN401
            if not hold.is_set():
                original(core, unit)

        monkeypatch.setattr(module, "_tend_listing", tend)
    return hold


def list_ended(s: StreamLike) -> bool:
    """Whether the regular list of device ``a`` ended and is not taken yet."""
    unit = s._core.units[0]
    listing = getattr(unit, "alisting", None)
    if listing is not None:
        return listing.task.done()
    return unit.listing is not None and not unit.listing.thread.is_alive()


@pytest.mark.parametrize("ending", ["flush", "stop"])
def test_a_regular_list_that_ended_by_the_readers_end_still_counts(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    ending: str,
) -> None:
    """A moved to uid NEW, which C had. A's line is judged with the old list
    while the regular list, which shows the move, runs; that list ends after
    the reader's last look, and then the flush marker comes back (or the
    stream is stopped). The reader hands the list over as it ends, so the
    line is counted."""
    regular_soon(monkeypatch)
    hold = held_tending(monkeypatch)
    server.add_sequence(PM, pm_list({C: NEW}), pm_list({A: NEW}, Wait("regular")))
    s = begin(server, mode, Package(A))
    assert server.wait_reached("regular", GUARD)
    no_more_regular(monkeypatch)
    hold.set()
    # logcat registers its live point apart from the package command
    wait_until(lambda: server.inject(uat(1, "a", NEW)) == 1)
    wait_until(lambda: attributor_of(s)._counts.others.get(NEW) == 1)
    server.release("regular")
    wait_until(lambda: list_ended(s))
    if ending == "flush":
        s.stop(flush=GUARD)
        wait_until(lambda: bool(server.logged))
        ((tag, message),) = server.logged
        server.inject(uat(5, message, 1000, tag))
    else:
        s.stop()
    with kill_if_hung(s):
        assert list(s.items()) == []
    summary = s.join(GUARD).devices[0]
    assert summary.flush == ("done" if ending == "flush" else "not_requested")
    assert summary.unattributed == 1
    assert logged(caplog, f"{A} appeared under uid {NEW}: 1 lines") != []


def test_a_failing_handover_of_the_list_at_the_readers_end_ends_the_stream(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The regular list ends after the reader's last look, and handing it over
    as the reader ends fails (a bug): the stream ends with that failure
    instead of leaving the consumer waiting for the device's end."""
    regular_soon(monkeypatch)
    hold = held_tending(monkeypatch)
    server.add_sequence(PM, pm_list({A: APP_A}), pm_list({A: APP_A}, Wait("regular")))
    s = begin(server, mode, Package(A))
    assert server.wait_reached("regular", GUARD)
    no_more_regular(monkeypatch)
    hold.set()

    def broken(*_args: object) -> None:
        msg = "a bug in list_done"
        raise RuntimeError(msg)

    monkeypatch.setattr(PackageAttributor, "list_done", broken)
    server.release("regular")
    wait_until(lambda: list_ended(s))
    s.stop()
    with (
        kill_if_hung(s),
        pytest.raises(LogprobeError, match="a bug in list_done") as caught,
    ):
        list(s.items())
    assert caught.value.code == "internal_error"
    with pytest.raises(LogprobeError, match="a bug in list_done"):
        s.join(GUARD)


def test_a_failing_handover_after_the_readers_own_error_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    unit = cast("Any", SimpleNamespace(serial="a"))
    own = LogprobeError("device_disconnected", "the device went away")
    assert _stream._settle_failed(unit, own, RuntimeError("a bug")) is own
    (record,) = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert record.getMessage() == (
        "a: handing over the regular package list failed as the reader ended"
    )
    assert isinstance(record.exc_info, tuple)
    assert str(record.exc_info[1]) == "a bug"


class FailingHandler(logging.Handler):
    """A log handler that fails on every WARNING or worse, as a broken one may."""

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.failed = 0

    def emit(self, record: logging.LogRecord) -> None:
        self.failed += 1
        msg = f"the log handler failed on {record.getMessage()!r}"
        raise OSError(msg)


def test_a_failing_log_handler_at_the_readers_end_keeps_the_readers_error(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A moved to uid NEW, which C had, and the regular list that shows it
    ends after the reader's last look; then the connection drops, so the
    reader ends with its own error. Handing the list over logs a WARNING that
    the log handler fails on, and logging that failure fails as well: the
    consumer still gets the reader's error instead of waiting for the
    device's end."""
    regular_soon(monkeypatch)
    hold = held_tending(monkeypatch)
    server.add_sequence(PM, pm_list({C: NEW}), pm_list({A: NEW}, Wait("regular")))
    dropping = ShellScript(steps=[Wait("live", live=True)], exit_status=None)
    s = begin(server, mode, Package(A), logcat=dropping, reconnect=0.0)
    assert server.wait_reached("regular", GUARD)
    no_more_regular(monkeypatch)
    hold.set()
    wait_until(lambda: server.inject(uat(1, "a", NEW)) == 1)
    wait_until(lambda: attributor_of(s)._counts.others.get(NEW) == 1)
    server.release("regular")
    wait_until(lambda: list_ended(s))
    handler = FailingHandler()
    logger = logging.getLogger("logprobe")
    logger.addHandler(handler)
    try:
        server.release("live")  # the connection drops
        with kill_if_hung(s), pytest.raises(LogprobeError) as caught:
            list(s.items())
        with pytest.raises(LogprobeError) as joined:
            s.join(GUARD)
    finally:
        logger.removeHandler(handler)
    assert caught.value.code == "device_lost"
    assert joined.value is caught.value
    assert handler.failed == 2  # the list's WARNING, then the handover's ERROR


def test_a_regular_list_that_failed_by_the_readers_stop_is_not_taken(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A failed list would only make the device blind as the reader stops."""
    regular_soon(monkeypatch)
    hold = held_tending(monkeypatch)
    failing = ShellScript([Wait("regular"), ("stderr", b"boom\n")], exit_status=1)
    server.add_sequence(PM, pm_list({A: APP_A}), failing)
    s = begin(server, mode, Package(A))
    assert server.wait_reached("regular", GUARD)
    no_more_regular(monkeypatch)
    hold.set()
    server.release("regular")
    wait_until(lambda: list_ended(s))
    s.stop()
    with kill_if_hung(s):
        assert list(s.items()) == []
    s.join(GUARD)
    assert not attributor_of(s).blind
    assert logged(caplog, LIST_FAILED) == []


def test_a_regular_list_that_ended_by_a_kill_is_not_taken(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """As in the test of a list that ended by the reader's end, but the stream
    is killed: nothing is judged or counted after a kill."""
    regular_soon(monkeypatch)
    hold = held_tending(monkeypatch)
    server.add_sequence(PM, pm_list({C: NEW}), pm_list({A: NEW}, Wait("regular")))
    s = begin(server, mode, Package(A))
    assert server.wait_reached("regular", GUARD)
    no_more_regular(monkeypatch)
    hold.set()
    # logcat registers its live point apart from the package command
    wait_until(lambda: server.inject(uat(1, "a", NEW)) == 1)
    wait_until(lambda: attributor_of(s)._counts.others.get(NEW) == 1)
    server.release("regular")
    wait_until(lambda: list_ended(s))
    s.kill()
    with kill_if_hung(s):
        assert list(s.items()) == []
    assert s.join(GUARD).devices[0].unattributed == 0
    assert logged(caplog, "appeared under uid") == []


def test_a_regular_list_that_failed_unexpectedly_by_the_readers_end_is_logged(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The helper of the regular list failed (a bug) after the reader's last
    look: the reader leaves it to be logged as it ends, not handed over."""
    regular_soon(monkeypatch)
    hold = held_tending(monkeypatch)
    started = threading.Event()
    go = threading.Event()
    ago = asyncio.Event()  # set on the stream's loop

    def bug(*_args: object) -> None:
        started.set()
        go.wait(GUARD)
        msg = "a bug in the list"
        raise RuntimeError(msg)

    async def abug(*_args: object) -> None:
        started.set()
        await ago.wait()
        msg = "a bug in the list"
        raise RuntimeError(msg)

    async def let_abug_go() -> None:
        ago.set()

    monkeypatch.setattr(_stream, "_run_list_commands", bug)
    monkeypatch.setattr(_astream, "_run_listing", abug)
    s = begin(server, mode, Package(A), uids={A: APP_A})
    assert started.wait(GUARD)
    no_more_regular(monkeypatch)
    hold.set()
    go.set()
    if mode._loop is not None:
        mode._loop.call(let_abug_go())
    wait_until(lambda: list_ended(s))
    assert finish(s) == []
    (record,) = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert record.getMessage() == (
        "a: the regular package list failed after the reader had ended"
    )
    assert isinstance(record.exc_info, tuple)
    assert str(record.exc_info[1]) == "a bug in the list"
    assert s.summary.devices[0].error is None


def test_a_failing_log_handler_on_a_failed_list_at_the_readers_end_ends_it(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """As in the test of a list helper that failed unexpectedly, but the log
    handler fails on the ERROR that reports it: the reader still ends, so the
    iteration ends instead of waiting for the device's end, and the failure
    does not reach the event loop either."""
    regular_soon(monkeypatch)
    hold = held_tending(monkeypatch)
    started = threading.Event()
    go = threading.Event()
    ago = asyncio.Event()  # set on the stream's loop

    def bug(*_args: object) -> None:
        started.set()
        go.wait(GUARD)
        msg = "a bug in the list"
        raise RuntimeError(msg)

    async def abug(*_args: object) -> None:
        started.set()
        await ago.wait()
        msg = "a bug in the list"
        raise RuntimeError(msg)

    async def let_abug_go() -> None:
        ago.set()

    monkeypatch.setattr(_stream, "_run_list_commands", bug)
    monkeypatch.setattr(_astream, "_run_listing", abug)
    s = begin(server, mode, Package(A), uids={A: APP_A})
    assert started.wait(GUARD)
    no_more_regular(monkeypatch)
    hold.set()
    go.set()
    if mode._loop is not None:
        mode._loop.call(let_abug_go())
    wait_until(lambda: list_ended(s))
    handler = FailingHandler()
    logger = logging.getLogger("logprobe")
    logger.addHandler(handler)
    try:
        s.stop()
        with kill_if_hung(s):
            assert list(s.items()) == []
        s.join(GUARD)
    finally:
        logger.removeHandler(handler)
    assert handler.failed == 1
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []
    assert s.summary.devices[0].error is None


@pytest.mark.parametrize("mode", ["async"], indirect=True)
def test_an_asyncio_reader_awaits_its_dropped_list_before_it_ends(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    regular_soon(monkeypatch)
    slow_list_cleanup(monkeypatch, 0.1)
    tasks_before = loop_tasks(mode)
    s = begin(server, mode, Package(A), uids={A: APP_A})
    wait_until(lambda: "logprobe-list-a" in loop_tasks(mode))
    inner = cast("AsyncLogStream", mode.unwrap(s))
    assert mode._loop is not None
    s.stop()

    async def joined() -> set[str]:
        await inner.join(GUARD)
        current = asyncio.current_task()
        return {t.get_name() for t in asyncio.all_tasks() if t is not current}

    assert mode._loop.call(joined()) == tasks_before  # right after, same task


@pytest.mark.parametrize("mode", ["async"], indirect=True)
def test_a_cancelled_exit_from_async_with_still_ends_the_list_tasks(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The task that leaves ``async with`` is cancelled while it joins a
    killed stream: the list task, whose cleanup takes a while, is done when
    the cancellation reaches the caller."""
    regular_soon(monkeypatch)
    slow_list_cleanup(monkeypatch, 0.1)
    s = begin(server, mode, Package(A), uids={A: APP_A})
    wait_until(lambda: "logprobe-list-a" in loop_tasks(mode))
    inner = cast("AsyncLogStream", mode.unwrap(s))
    assert mode._loop is not None
    s.kill()

    async def leave() -> set[str]:
        exiting = asyncio.create_task(inner.__aexit__(None, None, None))
        await asyncio.sleep(0)  # it waits for the readers now
        exiting.cancel()
        await asyncio.wait((exiting,))
        assert exiting.cancelled()
        current = asyncio.current_task()
        return {t.get_name() for t in asyncio.all_tasks() if t is not current}

    assert "logprobe-list-a" not in mode._loop.call(leave())


def slow_pm_cleanup(
    monkeypatch: pytest.MonkeyPatch, seconds: float
) -> tuple[list[str], asyncio.Event]:
    """Make a cancelled ``pm`` command of the asyncio stream take ``seconds``
    to end. The list returned gets the command once its cleanup starts, and
    the event is set then."""
    cleaning: list[str] = []
    started = asyncio.Event()
    real = _astream.arun_shell

    async def run(
        address: Any,  # noqa: ANN401
        serial: str,
        args: Any,  # noqa: ANN401
        timeout: float | None = 30.0,
    ) -> Any:  # noqa: ANN401
        try:
            return await real(address, serial, args, timeout)
        except asyncio.CancelledError:
            if args[0] == "pm":
                cleaning.append(" ".join(args))
                started.set()
                await asyncio.sleep(seconds)
            raise

    monkeypatch.setattr(_astream, "arun_shell", run)
    return cleaning, started


def leave_cancelled(inner: AsyncLogStream, started: asyncio.Event) -> Any:  # noqa: ANN401
    """Leave ``async with`` of a stream that is not drained, and cancel that
    exit once a ``pm`` command started its cleanup (``started``). Returns the
    names of the tasks left on the loop right when the cancellation reached
    the caller."""

    async def leave() -> set[str]:
        exiting = asyncio.create_task(inner.__aexit__(None, None, None))
        await started.wait()
        exiting.cancel()
        await asyncio.wait((exiting,))
        assert exiting.cancelled()
        current = asyncio.current_task()
        return {t.get_name() for t in asyncio.all_tasks() if t is not current}

    return leave()


@pytest.mark.parametrize("mode", ["async"], indirect=True)
def test_a_cancelled_exit_from_async_with_ends_a_readers_own_list_command(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A read of a new app waits for its own list, whose command hangs. The
    exit cancels the reader, and is itself cancelled while the command's
    cleanup runs: the command is done when the cancellation reaches the
    caller (the reader is cancelled once, and awaited)."""
    cleaning, started = slow_pm_cleanup(monkeypatch, 0.3)
    server.add_sequence(PM, pm_list({}), ShellScript([Wait("hang")]))
    tasks_before = loop_tasks(mode)
    s = begin(server, mode, Package(A))
    # Until the logcat connection waits at its live point, nothing gets a line.
    wait_until(lambda: server.inject(uat(1, "n", NEW)) == 1)
    assert server.wait_reached("hang", GUARD)
    assert "logprobe-list-a" not in loop_tasks(mode)  # the reader's own list
    inner = cast("AsyncLogStream", mode.unwrap(s))
    assert mode._loop is not None
    assert mode._loop.call(leave_cancelled(inner, started)) == tasks_before
    assert cleaning == [PM]


@pytest.mark.parametrize("mode", ["async"], indirect=True)
def test_a_cancelled_exit_from_async_with_lets_a_list_task_finish_its_cleanup(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exit cancels the regular list's task, and is itself cancelled
    while that task awaits its command's cleanup: the task is not cancelled
    a second time, so the command is done when the cancellation reaches the
    caller."""
    regular_soon(monkeypatch)
    cleaning, started = slow_pm_cleanup(monkeypatch, 0.3)
    server.add_sequence(PM, pm_list({A: APP_A}), ShellScript([Wait("hang")]))
    tasks_before = loop_tasks(mode)
    s = begin(server, mode, Package(A))
    assert server.wait_reached("hang", GUARD)
    no_more_regular(monkeypatch)
    assert "logprobe-list-a" in loop_tasks(mode)
    inner = cast("AsyncLogStream", mode.unwrap(s))
    assert mode._loop is not None
    assert mode._loop.call(leave_cancelled(inner, started)) == tasks_before
    assert cleaning == [PM]


@pytest.mark.parametrize("mode", ["async"], indirect=True)
def test_leaving_async_with_while_a_reader_awaits_its_dropped_list_ends_it(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The logcat ended (no reconnect) and the reader awaits the list task it
    dropped, whose cleanup takes a while; leaving ``async with`` then cancels
    that reader, and still waits for the list task."""
    regular_soon(monkeypatch)
    slow_list_cleanup(monkeypatch, 0.3)
    logcat = ShellScript([Wait("go"), ("stdout", uat(1, "x"))])
    s = begin(server, mode, Package(A), logcat=logcat, uids={A: APP_A}, reconnect=0)
    wait_until(lambda: "logprobe-list-a" in loop_tasks(mode))
    inner = cast("AsyncLogStream", mode.unwrap(s))
    unit = cast("Any", inner)._units[0]
    listing = unit.alisting.task
    assert mode._loop is not None
    server.release("go")
    wait_until(lambda: unit.alisting is None)  # the reader dropped it

    async def leave() -> set[str]:
        assert not unit.task.done()
        assert not listing.done()  # the reader awaits it
        await inner.__aexit__(RuntimeError, RuntimeError("body"), None)
        current = asyncio.current_task()
        return {t.get_name() for t in asyncio.all_tasks() if t is not current}

    assert "logprobe-list-a" not in mode._loop.call(leave())
    assert listing.done()


@pytest.mark.parametrize("mode", ["blocking"], indirect=True)
def test_a_ctrl_c_while_leaving_the_with_block_waits_for_the_list_thread(
    server: FakeAdbServer, mode: Mode, monkeypatch: pytest.MonkeyPatch
) -> None:
    regular_soon(monkeypatch)
    server.add_sequence(PM, pm_list({A: APP_A}), ShellScript([Wait("hang")]))
    s = begin(server, mode, Package(A))
    assert server.wait_reached("hang", GUARD)
    reader = s._core.units[0].thread
    assert reader is not None
    real_join = reader.join

    def interrupted_join(timeout: float | None = None) -> None:
        del timeout
        reader.join = real_join
        raise KeyboardInterrupt

    reader.join = interrupted_join
    with pytest.raises(KeyboardInterrupt):
        s.__exit__(None, None, None)
    assert not reader.is_alive()
    assert "logprobe-list-a" not in {t.name for t in threading.enumerate()}
    assert server.wait_done(records(server, PM)[1].index, GUARD)


# -- The start: the clock and the time of the list ---------------------------------


def test_an_adb_error_while_reading_the_clock_fails_the_start(
    server: FakeAdbServer, mode: Mode
) -> None:
    (device,) = attach(server, "a")
    server.fail['shell,v2,raw:export ANDROID_LOG_TAGS=""; exec date +%s'] = (
        "device offline"
    )
    server.oneoff[PM] = pm_list({A: APP_A})
    s = mode.device_stream(device, package=A)
    with pytest.raises(LogprobeError) as info:
        s.start()
    assert info.value.code == "device_offline"
    assert info.value.details["serial"] == "a"
    assert "pm" not in programs(server)
    assert "logcat" not in programs(server)


def test_a_clock_that_does_not_answer_leaves_the_boundary_unset(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="logprobe")
    monkeypatch.setattr(_marks, "COMMAND_LIMIT", 0.3)
    (device,) = attach(server, "a")
    server.oneoff["date +%s"] = ShellScript([Wait("never")])
    server.oneoff[PM] = pm_list({A: APP_A})
    server.add_sequence("logcat", staying(("stdout", uat(1, "a"))))
    s = mode.device_stream(device, package=A).start()
    assert attributor_of(s).boundary is None
    items, error = run(s, 1)
    assert error is None
    assert shape(items) == ["a"]
    assert logged(caplog, "could not read the clock") == [
        "could not read the clock of a (it did not finish within 0.3 seconds); "
        "app lines of removed packages in the backlog are checked against a new "
        "list"
    ]


def test_the_start_list_has_one_limit_for_pm_and_dumpsys(
    server: FakeAdbServer,
    mode: Mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``pm`` takes most of the limit before it asks for ``dumpsys``, which
    gets only what is left, not a limit of its own."""
    monkeypatch.setattr(_marks, "COMMAND_LIMIT", 0.6)
    limits: dict[str, float] = {}
    run_command = Device._run_command
    arun_command = _astream._run_command

    def recording(device: Device, *args: Any) -> Any:  # noqa: ANN401
        argv, limit = args[:2]
        limits[argv[0]] = limit
        return run_command(device, *args)

    async def arecording(*args: Any) -> Any:  # noqa: ANN401
        argv, limit = args[2:4]
        limits[argv[0]] = limit
        return await arun_command(*args)

    monkeypatch.setattr(Device, "_run_command", recording)
    monkeypatch.setattr(_astream, "_run_command", arecording)
    (device,) = attach(server, "a")
    server.answer("date +%s", CLOCK)
    unknown: list[Step] = [("stdout", b"Error: Unknown option: -U\n")]
    server.oneoff[PM] = ShellScript(unknown, fragment=True, byte_delay=0.012)
    server.oneoff[DUMPSYS] = ShellScript([Wait("hang")])
    server.add_sequence("logcat", live())
    s = mode.device_stream(device, ~Package(A)).start()
    (pm,) = records(server, PM)
    (dumpsys,) = records(server, DUMPSYS)
    assert dumpsys.started_at - pm.started_at >= 0.3  # pm answered slowly
    assert limits["dumpsys"] <= 0.6 - 0.3
    assert attributor_of(s).blind
    finish(s)
    (warning,) = logged(caplog, LIST_FAILED)
    assert "'dumpsys package packages' did not finish within the 0.6 seconds" in (
        warning
    )
