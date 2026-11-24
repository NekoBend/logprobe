"""Package attribution: verdicts against the package list, lists and accounting."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from logprobe import Crash, Gap, LogEntry, Package, Tag, parse_lines
from logprobe._attribution import (
    DUMPSYS_PACKAGES_ARGV,
    PM_LIST_ARGV,
    Failed,
    Listed,
    ListJob,
    PackageAttributor,
    Segment,
    dump_judge,
)
from logprobe._attribution import attributor as attributor_module
from tests.device_facts import level_dir, load, step

if TYPE_CHECKING:
    from logprobe import Condition

A = "com.example.a"
B = "com.example.b"
OTHER = "com.example.other"
APP_A = 10053
APP_B = 10054
APP_OTHER = 10070
NEW = 19999  # an app id the lists below (and the recorded one) do not name
BASE = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)
CLOCK = BASE.timestamp()  # the boundary of the tests that set one


def entry(
    uid: int | None, text: str = "x", tag: str = "T", at: float = 0.0
) -> LogEntry:
    """A line logged ``at`` seconds after BASE."""
    return LogEntry(
        logged_at=BASE + timedelta(seconds=at),
        pid=1,
        tid=1,
        level="I",
        tag=tag,
        message=text,
        raw=text,
        uid=uid,
    )


def gap() -> Gap:
    return Gap("s", "continuity_unknown", "disconnected", BASE, None)


def texts(segments: list[Any]) -> list[str]:
    """Messages of the entries, with ``"GAP"`` for a gap, in order."""
    result = []
    for segment in segments:
        if isinstance(segment, Gap):
            result.append("GAP")
        else:
            result.extend(e.message for e in segment)
    return result


def entries_of(segment: Segment) -> list[LogEntry]:
    assert isinstance(segment, list)
    return segment


def pm_text(uids: dict[str, int]) -> bytes:
    """What ``pm list packages -U`` prints for ``uids``, plus an unrelated app."""
    listed = {"com.example.unrelated": 10500, **uids}
    return "".join(f"package:{n} uid:{u}\n" for n, u in listed.items()).encode()


def give_list(
    attributor: PackageAttributor, uids: dict[str, int], now: float = 0.0
) -> None:
    """Take a list that ``pm list packages -U`` answers with ``uids``."""
    job = attributor.list_started(now)
    assert job.argv == PM_LIST_ARGV
    job.take(0, pm_text(uids), b"")
    assert isinstance(job.outcome, Listed)
    attributor.list_done(job, now)


def fail_list(attributor: PackageAttributor, now: float = 0.0) -> None:
    job = attributor.list_started(now)
    job.take(1, b"", b"Error: boom\n")
    assert isinstance(job.outcome, Failed)
    attributor.list_done(job, now)


def make(condition: Condition, uids: dict[str, int] | None = None) -> PackageAttributor:
    attributor = PackageAttributor(condition, serial="emu")
    if uids is not None:
        give_list(attributor, uids)
    return attributor


def warnings(attributor: PackageAttributor) -> list[str]:
    return [t for level, t in attributor.take_messages() if level == logging.WARNING]


# -- Deciding lines --------------------------------------------------------------


def test_a_watched_owner_decides_without_a_list() -> None:
    attributor = make(Package(A), {A: APP_A, B: APP_B})
    read = [[entry(APP_A, "a"), entry(APP_B, "b"), entry(1000, "s"), entry(None)]]
    assert not attributor.needs_list(read)
    out = attributor.judge(read)
    assert texts(out) == ["a"]
    assert entries_of(out[0])[0].package == A
    assert attributor.unattributed == 0


def test_lines_outside_the_app_range_never_need_a_list() -> None:
    # System uids, an isolated process (a WebView renderer of an app: 99001)
    # and a sandbox: no list names them, so they belong to no watched package.
    attributor = make(Package(A), {A: APP_A})
    read = [[entry(1000), entry(0), entry(99001), entry(APP_A + 89_000), entry(25000)]]
    assert not attributor.needs_list(read)
    assert attributor.judge(read) == []
    kept = make(~Package(A), {A: APP_A})
    assert len(texts(kept.judge(read))) == 5


def test_a_secondary_user_matches_by_app_id() -> None:
    attributor = make(Package(A), {A: APP_A})
    read = [[entry(APP_A + 100_000, "u1"), entry(1_000_000 + APP_A, "u10")]]
    assert not attributor.needs_list(read)
    out = attributor.judge(read)
    assert texts(out) == ["u1", "u10"]
    assert entries_of(out[0])[1].package == A


def test_a_shared_uid_matches_every_owner_and_shows_the_first_by_name() -> None:
    uids = {B: APP_A, A: APP_A}
    for condition, shown in [
        (Package(A), A),
        (Package(B), B),  # only watched names are owners
        (Package(B) & Package(A), A),
        (Package(A, B), A),
    ]:
        out = make(condition, uids).judge([[entry(APP_A, "x")]])
        assert texts(out) == ["x"]
        assert entries_of(out[0])[0].package == shown
    assert make(~Package(A), uids).judge([[entry(APP_A, "x")]]) == []


def test_an_installed_app_that_is_not_watched_is_decided_by_the_list() -> None:
    attributor = make(Package(A), {A: APP_A, OTHER: APP_OTHER})
    read = [[entry(APP_OTHER, "o")]]
    assert not attributor.needs_list(read)
    assert attributor.judge(read) == []
    assert texts(make(~Package(A), {A: APP_A, OTHER: APP_OTHER}).judge(read)) == ["o"]


def test_a_verdict_that_a_term_without_packages_settles_needs_no_list() -> None:
    attributor = make(Package(A) | Tag("keep"), {A: APP_A})
    assert not attributor.needs_list([[entry(NEW, "k", tag="keep")]])
    assert attributor.needs_list([[entry(NEW, "z")]])


def test_only_the_names_of_package_terms_are_watched() -> None:
    attributor = make(Package(A) | Crash(package="com.example.crash"), {})
    infos = [t for level, t in attributor.take_messages() if level == logging.INFO]
    assert infos == [
        f"{A} is not installed on emu; its lines are matched once a later list shows it"
    ]


def test_an_unlisted_app_id_needs_a_list_without_a_boundary() -> None:
    attributor = make(Package(A), {A: APP_A})
    assert attributor.needs_list([[entry(NEW, at=-3600)]])


def test_the_boundary_decides_lines_logged_before_the_list() -> None:
    attributor = PackageAttributor(Package(A), serial="emu")
    attributor.boundary = CLOCK
    give_list(attributor, {A: APP_A})
    before = entry(NEW, "before", at=-0.000001)
    at_boundary = entry(NEW, "at", at=0.0)
    assert not attributor.needs_list([[before]])
    assert attributor.needs_list([[at_boundary]])
    assert make(~Package(A), {A: APP_A}).needs_list([[before]])  # no boundary
    kept = PackageAttributor(~Package(A), serial="emu")
    kept.boundary = CLOCK
    give_list(kept, {A: APP_A})
    assert texts(kept.judge([[before]])) == ["before"]
    assert kept.unattributed == 0


def test_a_boundary_without_a_list_decides_nothing() -> None:
    attributor = PackageAttributor(Package(A), serial="emu")
    attributor.boundary = CLOCK
    assert attributor.needs_list([[entry(NEW, at=-60)]])


def test_gaps_keep_their_place_and_empty_lists_are_left_out() -> None:
    attributor = make(Package(A), {A: APP_A})
    out = attributor.judge(
        [[entry(APP_A, "a")], gap(), [entry(1000)], [entry(APP_A, "b")]]
    )
    assert texts(out) == ["a", "GAP", "b"]
    assert len(out) == 3


# -- Lines that wait for a list --------------------------------------------------


def test_a_new_app_id_is_answered_by_one_list() -> None:
    attributor = make(Package(A), {A: APP_A})
    read = [[entry(NEW, "n1"), entry(NEW + 1, "n2"), entry(APP_A, "a")]]
    assert attributor.needs_list(read)
    give_list(attributor, {A: APP_A, B: NEW}, now=1.0)
    assert not attributor.needs_list(read)
    assert texts(attributor.judge(read)) == ["a"]
    assert attributor.unattributed == 0


def test_an_app_installed_while_reading_is_attributed_after_its_list() -> None:
    attributor = make(Package(A), {})
    read = [[entry(APP_A, "first")]]
    assert attributor.needs_list(read)
    give_list(attributor, {A: APP_A}, now=1.0)
    out = attributor.judge(read)
    assert texts(out) == ["first"]
    assert entries_of(out[0])[0].package == A
    assert attributor.unattributed == 0


def test_an_app_id_the_next_list_lacks_is_absent_until_a_list_names_it() -> None:
    attributor = make(~Package(A), {A: APP_A})
    assert attributor.needs_list([[entry(NEW)]])
    give_list(attributor, {A: APP_A}, now=1.0)  # still not named: absent
    assert not attributor.needs_list([[entry(NEW)]])
    assert texts(attributor.judge([[entry(NEW, "n")]])) == ["n"]
    assert attributor.unattributed == 1  # its app could not be checked
    give_list(attributor, {A: APP_A, OTHER: NEW}, now=2.0)  # named: not absent
    give_list(attributor, {A: APP_A}, now=3.0)  # removed again
    assert attributor.needs_list([[entry(NEW)]])
    assert attributor.unattributed == 1


def test_needs_list_counts_nothing() -> None:
    attributor = make(Package(A), {A: APP_A})
    read = [[entry(APP_A), entry(APP_A), entry(NEW)]]
    for _ in range(3):
        assert attributor.needs_list(read)
    attributor.judge(read)  # counts the two lines of APP_A once each (and NEW)
    give_list(attributor, {A: APP_B}, now=1.0)
    assert attributor.unattributed == 3  # 2 judged with the old uid + 1 undecided


def test_lines_that_got_no_list_are_counted_with_the_cause_once() -> None:
    attributor = make(~Package(A), {A: APP_A})
    read = [[entry(NEW, "n1"), entry(NEW, "n2")]]
    assert attributor.needs_list(read)
    out = attributor.judge(read, "the stream stopped")
    assert texts(out) == ["n1", "n2"]  # judged as if no package owned them
    assert attributor.unattributed == 2
    assert attributor.judge([[entry(NEW + 1)]], "again") != []
    assert warnings(attributor) == [
        "emu: lines whose app could not be determined are counted as "
        "unattributed (first: the stream stopped)"
    ]


def test_settled_lines_of_an_absent_app_id_count_when_it_turns_out_watched() -> None:
    attributor = make(~Package(A) | Tag("keep"), {A: APP_A})
    attributor.needs_list([[entry(NEW)]])
    give_list(attributor, {A: APP_A}, now=1.0)
    read = [[entry(NEW, str(i), tag="keep") for i in range(4)]]
    assert not attributor.needs_list(read)  # absent: asking counts nothing
    out = attributor.judge(read)  # the tag settles them: not counted yet
    assert len(texts(out)) == 4
    assert attributor.unattributed == 0
    attributor.take_messages()
    give_list(attributor, {A: NEW}, now=31.0)  # the app id was given to A
    assert attributor.unattributed == 4 + 0  # the reinstall of A counts nothing
    assert (
        "emu: com.example.a appeared under uid 19999: 4 lines judged before it "
        "was known are counted as unattributed"
    ) in warnings(attributor)


def test_lines_older_than_the_boundary_are_counted_when_a_watched_app_appears() -> None:
    # After a clock step back, the lines of an app installed while reading
    # look older than the boundary: they are judged at once, and counted when
    # a list shows a watched package under their app id.
    attributor = PackageAttributor(~Package(A), serial="emu")
    attributor.boundary = CLOCK
    give_list(attributor, {})
    read = [[entry(NEW, str(i), at=-5) for i in range(3)]]
    assert not attributor.needs_list(read)
    assert len(texts(attributor.judge(read))) == 3
    assert attributor.unattributed == 0
    attributor.take_messages()
    give_list(attributor, {A: NEW}, now=31.0)
    assert attributor.unattributed == 3
    assert warnings(attributor) == [
        "emu: com.example.a appeared under uid 19999: 3 lines judged before it "
        "was known are counted as unattributed"
    ]


def test_lines_older_than_the_boundary_count_only_until_the_next_list() -> None:
    attributor = PackageAttributor(~Package(A), serial="emu")
    attributor.boundary = CLOCK
    give_list(attributor, {})
    attributor.judge([[entry(NEW, at=-5) for _ in range(3)]])
    give_list(attributor, {}, now=31.0)  # a removed app: nothing to count
    attributor.judge([[entry(NEW, at=-4)]])
    give_list(attributor, {A: NEW}, now=61.0)
    assert attributor.unattributed == 1


def test_an_absent_app_id_counts_its_settled_lines_since_the_latest_list() -> None:
    attributor = make(~Package(A) | Tag("keep"), {A: APP_A})
    attributor.needs_list([[entry(NEW)]])
    give_list(attributor, {A: APP_A}, now=1.0)
    attributor.judge([[entry(NEW, tag="keep") for _ in range(4)]])
    give_list(attributor, {A: APP_A}, now=31.0)  # still absent
    read = [[entry(NEW, "n", tag="keep")]]
    assert not attributor.needs_list(read)  # no new list for an absent app id
    assert texts(attributor.judge(read)) == ["n"]
    give_list(attributor, {A: NEW}, now=61.0)
    assert attributor.unattributed == 1


def test_a_watched_package_joining_a_watched_shared_uid_counts_its_lines() -> None:
    attributor = make(Package(A) & Package(B), {A: APP_A})
    read = [[entry(APP_A, str(i)) for i in range(3)]]
    assert not attributor.needs_list(read)
    assert attributor.judge(read) == []  # B has none of A's uid yet
    attributor.take_messages()
    give_list(attributor, {A: APP_A, B: APP_A}, now=30.0)
    assert attributor.unattributed == 3
    assert warnings(attributor) == [
        "emu: com.example.b appeared under uid 10053: 3 lines judged before it "
        "was known are counted as unattributed"
    ]
    give_list(attributor, {A: APP_A, B: APP_A}, now=60.0)
    assert attributor.unattributed == 3


def test_a_shared_uid_whose_owners_change_at_once_counts_its_lines_once() -> None:
    attributor = make(Package(A) | Package(B), {A: APP_A})
    attributor.judge([[entry(APP_A) for _ in range(2)]])
    attributor.take_messages()
    give_list(attributor, {A: APP_B, B: APP_A}, now=30.0)  # A left, B joined
    assert attributor.unattributed == 2
    assert warnings(attributor) == [
        "emu: com.example.a has a new uid: 2 lines judged with the old uid since "
        "the last list are counted as unattributed"
    ]


@pytest.mark.parametrize(
    "condition",
    [Tag("keep") | Package(A), Package(A) | Tag("keep")],
    ids=["tag-first", "package-first"],
)
def test_the_reinstall_count_does_not_depend_on_the_order_of_the_terms(
    condition: Condition,
) -> None:
    attributor = make(condition, {A: APP_A})
    out = attributor.judge([[entry(APP_A, "k", tag="keep")]])
    assert entries_of(out[0])[0].package == A
    give_list(attributor, {A: APP_B}, now=30.0)
    assert attributor.unattributed == 1


@pytest.mark.parametrize(
    "condition",
    [Tag("keep") | Package(A), Package(A) | Tag("keep")],
    ids=["tag-first", "package-first"],
)
def test_a_line_settled_without_its_package_counts_when_a_watched_app_appears(
    condition: Condition,
) -> None:
    attributor = make(condition, {B: APP_B})
    line = entry(NEW, "k", tag="keep", at=5.0)
    assert not attributor.needs_list([[line]])  # the tag settles it
    out = attributor.judge([[line]])
    assert [(e.message, e.package) for e in entries_of(out[0])] == [("k", None)]
    assert attributor.unattributed == 0
    attributor.take_messages()
    give_list(attributor, {A: NEW, B: APP_B}, now=30.0)
    assert attributor.unattributed == 1
    assert warnings(attributor) == [
        f"emu: {A} appeared under uid {NEW}: 1 lines judged before it was known "
        "are counted as unattributed"
    ]


def test_two_owners_that_leave_one_uid_together_report_the_count_once() -> None:
    attributor = make(Package(A, B), {A: APP_A, B: APP_A})
    attributor.judge([[entry(APP_A) for _ in range(3)]])
    attributor.take_messages()
    give_list(attributor, {A: APP_B, B: APP_OTHER}, now=30.0)
    assert attributor.unattributed == 3
    assert warnings(attributor) == [
        "emu: com.example.a has a new uid: 3 lines judged with the old uid since "
        "the last list are counted as unattributed",
        "emu: com.example.b has a new uid: the lines judged with the old uid are "
        "counted with those of com.example.a",
    ]


def test_a_list_that_started_before_a_line_asked_does_not_make_its_app_absent() -> None:
    attributor = make(~Package(A), {})
    job = attributor.list_started(30.0)  # the regular list starts
    line = entry(NEW, "n", at=31.0)
    assert attributor.needs_list([[line]])  # asked while that list runs
    job.take(0, pm_text({}), b"")
    attributor.list_done(job, 30.1)
    assert attributor.needs_list([[line]])  # it may be newer than that list
    give_list(attributor, {}, now=31.0)  # a list taken after the line was read
    assert not attributor.needs_list([[line]])  # absent now
    assert texts(attributor.judge([[line]])) == ["n"]
    assert attributor.unattributed == 1  # its app could not be checked


def test_an_app_id_asked_about_again_during_a_list_is_not_made_absent_by_it() -> None:
    """A failed list hands NEW back to the next one; A is installed under NEW
    while that list runs and its line asks again. The list was taken before
    the install, so it does not make NEW absent: the read takes its own."""
    attributor = make(Package(A), {})
    assert attributor.needs_list([[entry(NEW, "n", at=1.0)]])
    fail_list(attributor, now=1.0)  # NEW waits for the recovery list
    job = run_list(attributor, 30.0)  # the recovery list asks about NEW
    line = entry(NEW, "a", at=31.0)  # A's, installed meanwhile
    assert attributor.needs_list([[line]], running=True)
    end_list(attributor, job, {}, 30.1)  # taken before the install
    assert attributor.needs_list([[line]])
    give_list(attributor, {A: NEW}, now=31.0)  # the read's own list
    out = attributor.judge([[line]])
    assert [(e.message, e.package) for e in entries_of(out[0])] == [("a", A)]
    assert attributor.unattributed == 0


def test_the_app_ids_of_a_failed_list_wait_for_the_next_one() -> None:
    attributor = make(~Package(A), {})
    line = entry(NEW, "n", at=1.0)
    assert attributor.needs_list([[line]])
    fail_list(attributor, now=2.0)
    give_list(attributor, {}, now=40.0)
    assert not attributor.needs_list([[line]])


def test_an_app_id_given_again_to_a_watched_package_counts_the_lines_of_others() -> (
    None
):
    # Two Package terms ask about each line twice; it is counted once.
    attributor = make(Package(A) | Package(B), {A: APP_A, OTHER: APP_OTHER})
    attributor.judge([[entry(APP_OTHER, str(i)) for i in range(2)]])
    give_list(attributor, {A: APP_A, OTHER: APP_OTHER}, now=30.0)  # no change
    assert attributor.unattributed == 0
    read = [[entry(APP_OTHER, str(i)) for i in range(3)]]
    assert not attributor.needs_list(read)
    assert texts(attributor.judge(read)) == []
    attributor.take_messages()
    # OTHER was removed and B got its app id before the next list.
    give_list(attributor, {A: APP_A, B: APP_OTHER}, now=60.0)
    assert attributor.unattributed == 3  # the lines since the list before only
    assert warnings(attributor) == [
        "emu: com.example.b appeared under uid 10070: 3 lines judged before it "
        "was known are counted as unattributed"
    ]
    give_list(attributor, {A: APP_A, B: APP_OTHER}, now=90.0)
    assert attributor.unattributed == 3


# -- Lists: failures, pacing, schedule -------------------------------------------


def test_a_failed_first_list_makes_the_device_blind_until_a_list_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(attributor_module, "RECHECK_INTERVAL", 30.0)
    attributor = PackageAttributor(~Package(A), serial="emu")
    fail_list(attributor, now=5.0)
    assert attributor.blind
    read = [[entry(APP_A, "a"), entry(NEW, "n"), entry(1000, "s")]]
    assert not attributor.needs_list(read)
    assert texts(attributor.judge(read)) == ["a", "n", "s"]
    assert attributor.unattributed == 2
    assert warnings(attributor) == [
        "could not list the packages of emu (the command 'pm list packages -U' "
        "did not succeed (exit status 1)); lines whose app is not known are "
        "counted as unattributed until the next list in 30 s",
        "emu: lines whose app could not be determined are counted as "
        "unattributed (first: the last package list failed)",
    ]
    assert not attributor.list_due(34.9)
    assert attributor.list_due(35.0)
    fail_list(attributor, now=35.0)
    assert warnings(attributor) == []  # one WARNING per device
    give_list(attributor, {A: APP_A}, now=65.0)
    assert not attributor.blind
    assert attributor.needs_list(read)  # the list does not name NEW
    give_list(attributor, {A: APP_A}, now=66.0)
    assert texts(attributor.judge(read)) == ["n", "s"]
    assert attributor.unattributed == 3  # and NEW, absent now


def test_a_failed_list_after_a_good_one_keeps_the_old_list() -> None:
    attributor = make(Package(A), {A: APP_A, OTHER: APP_OTHER})
    fail_list(attributor, now=1.0)
    read = [[entry(APP_A, "a"), entry(APP_OTHER, "o"), entry(NEW, "n")]]
    assert not attributor.needs_list(read)
    assert texts(attributor.judge(read)) == ["a"]
    assert attributor.unattributed == 1  # only the line the old list cannot tell


def test_a_cut_list_fails_and_still_learns_about_dash_u(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(attributor_module, "RECHECK_INTERVAL", 30.0)
    attributor = make(~Package(A), {A: APP_A})
    attributor.take_messages()
    job = attributor.list_started(10.0)
    job.take(0, b"Error: Unknown option: -U\n", b"")
    assert job.argv == DUMPSYS_PACKAGES_ARGV
    job.fail("was cut")
    attributor.list_done(job, 10.5)
    assert attributor.blind
    assert attributor.list_due(40.5)
    assert len(warnings(attributor)) == 1
    assert attributor.list_started(41.0).argv == DUMPSYS_PACKAGES_ARGV


def test_lists_are_paced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(attributor_module, "LIST_INTERVAL", 0.5)
    attributor = PackageAttributor(Package(A), serial="emu")
    assert attributor.ready_at() == float("-inf")
    give_list(attributor, {A: APP_A}, now=10.0)
    assert attributor.ready_at() == 10.5
    fail_list(attributor, now=20.0)
    assert attributor.ready_at() == 20.5


def test_the_list_is_due_again_after_the_interval_from_its_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(attributor_module, "RECHECK_INTERVAL", 30.0)
    attributor = PackageAttributor(Package(A), serial="emu")
    assert not attributor.list_due(1e9)  # no list yet: the start takes one
    job = attributor.list_started(10.0)
    job.take(0, pm_text({A: APP_A}), b"")
    attributor.list_done(job, 10.4)
    assert not attributor.list_due(39.9)
    assert attributor.list_due(40.0)


def test_a_reinstall_counts_the_lines_judged_with_the_old_uid() -> None:
    attributor = make(Package(A), {A: APP_A})
    attributor.judge([[entry(APP_A) for _ in range(5)]])
    give_list(attributor, {A: APP_A}, now=30.0)  # unchanged: the count restarts
    attributor.judge([[entry(APP_A) for _ in range(3)]])
    attributor.take_messages()
    give_list(attributor, {A: APP_B}, now=60.0)
    assert attributor.unattributed == 3
    assert warnings(attributor) == [
        "emu: com.example.a has a new uid: 3 lines judged with the old uid since "
        "the last list are counted as unattributed"
    ]
    attributor.judge([[entry(APP_B)]])
    give_list(attributor, {}, now=90.0)
    assert attributor.unattributed == 4
    assert warnings(attributor) == [
        "emu: com.example.a is no longer installed: 1 lines judged with the old "
        "uid since the last list are counted as unattributed"
    ]


def test_a_shared_uid_that_moves_counts_every_line_once() -> None:
    attributor = make(Package(A) | Package(B), {A: APP_A, B: APP_A})
    attributor.judge([[entry(APP_A) for _ in range(4)]])
    give_list(attributor, {A: APP_B, B: APP_A}, now=30.0)
    assert attributor.unattributed == 4
    attributor.judge([[entry(APP_A) for _ in range(2)]])
    give_list(attributor, {A: APP_B, B: APP_B}, now=60.0)
    assert attributor.unattributed == 6


def test_a_system_uid_package_warns_once_and_matches_its_uid() -> None:
    settings = "com.android.settings"
    attributor = make(Package(settings), {settings: 1000})
    give_list(attributor, {settings: 1000}, now=30.0)
    assert warnings(attributor) == [
        "emu: com.android.settings runs under the system uid 1000: every process "
        "of that uid is taken as belonging to it"
    ]
    out = attributor.judge([[entry(1000, "s"), entry(101000, "s10")]])
    assert texts(out) == ["s", "s10"]
    assert entries_of(out[0])[0].package == settings


def test_a_missing_package_is_told_once_on_the_first_list() -> None:
    attributor = make(Package(A, B), {B: APP_B})
    give_list(attributor, {B: APP_B}, now=30.0)
    messages = attributor.take_messages()
    assert messages == [
        (
            logging.INFO,
            f"{A} is not installed on emu; its lines are matched once a later "
            "list shows it",
        )
    ]


def test_a_list_job_falls_back_by_the_output_and_remembers_it() -> None:
    attributor = PackageAttributor(Package(A), serial="emu")
    job = attributor.list_started(0.0)
    job.take(0, b"Error: Unknown option: -U\n", b"")
    assert not job.finished
    assert job.argv == DUMPSYS_PACKAGES_ARGV
    job.take(0, b"  Package [com.example.a] (1f):\n    userId=10053\n", b"")
    assert job.outcome == Listed({A: APP_A})
    attributor.list_done(job, 0.0)
    assert attributor.list_started(1.0).argv == DUMPSYS_PACKAGES_ARGV


def test_a_list_job_that_got_bare_names_tries_pm_again_next_time() -> None:
    attributor = PackageAttributor(Package(A), serial="emu")
    job = attributor.list_started(0.0)
    job.take(0, b"package:com.example.a\n", b"")
    assert job.argv == DUMPSYS_PACKAGES_ARGV
    job.take(0, b"Error: Could not access the Package Manager\n", b"")
    assert job.outcome == Failed("printed no package list", 0)
    attributor.list_done(job, 0.0)
    assert attributor.blind
    assert attributor.list_started(1.0).argv == PM_LIST_ARGV


def test_a_list_job_that_could_not_run_fails_with_the_reason() -> None:
    job = ListJob()
    job.fail("did not finish within 5 seconds")
    assert job.outcome == Failed("did not finish within 5 seconds", None)
    assert job.stderr == b""
    job = ListJob()
    job.fail("did not finish within 5 seconds", b"Error: slow\n")
    assert job.stderr == b"Error: slow\n"


# -- A list that runs while the reader judges lines --------------------------------


def run_list(attributor: PackageAttributor, now: float) -> ListJob:
    """Start a list that runs elsewhere; finish it with `end_list`."""
    return attributor.list_started(now)


def end_list(
    attributor: PackageAttributor, job: ListJob, uids: dict[str, int], now: float
) -> None:
    job.take(0, pm_text(uids), b"")
    assert isinstance(job.outcome, Listed)
    attributor.list_done(job, now)


@pytest.mark.parametrize(
    ("first", "line", "boundary"),
    [
        ({OTHER: APP_OTHER}, entry(APP_OTHER, "o", at=31.0), None),
        ({}, entry(NEW, "absent", tag="keep", at=31.0), None),
        ({}, entry(NEW, "early", at=-5.0), CLOCK),
        ({}, entry(NEW, "k", tag="keep", at=31.0), None),
    ],
    ids=["listed-for-another", "absent", "older-than-the-boundary", "settled-by-tag"],
)
def test_lines_judged_while_a_list_runs_count_when_a_later_list_shows_the_app(
    first: dict[str, int], line: LogEntry, boundary: float | None
) -> None:
    """The list that runs may have been taken before the lines judged
    meanwhile; when it does not settle them, the next one does."""
    attributor = PackageAttributor(~Package(A) | Tag("keep"), serial="emu")
    attributor.boundary = boundary
    give_list(attributor, first)
    app_id = line.uid
    assert app_id is not None
    if line.message == "absent":
        attributor.needs_list([[entry(NEW, at=31.0)]])
        give_list(attributor, first, now=1.0)  # NEW is absent from now on
    job = run_list(attributor, 30.0)
    assert not attributor.needs_list([[line]])
    assert texts(attributor.judge([[line]])) == [line.message]
    end_list(attributor, job, first, 30.1)  # taken before the line: no change
    assert attributor.unattributed == 0
    attributor.take_messages()
    give_list(attributor, {A: app_id}, now=60.0)
    assert attributor.unattributed == 1
    assert warnings(attributor) == [
        f"emu: {A} appeared under uid {app_id}: 1 lines judged before it was "
        "known are counted as unattributed"
    ]


def test_lines_judged_while_a_list_runs_are_counted_once() -> None:
    attributor = make(Package(A, B), {A: APP_A})
    attributor.judge([[entry(APP_A, "before")]])
    job = run_list(attributor, 30.0)
    attributor.judge([[entry(APP_A, "during")]])
    end_list(attributor, job, {A: APP_B, B: APP_A}, 30.1)  # it saw the change
    assert attributor.unattributed == 2
    give_list(attributor, {A: APP_B, B: APP_OTHER}, now=60.0)  # B leaves APP_A
    assert attributor.unattributed == 2  # not again for the next list


def test_lines_judged_while_a_list_runs_go_to_the_next_one_only() -> None:
    attributor = make(~Package(A), {OTHER: APP_OTHER})
    job = run_list(attributor, 30.0)
    attributor.judge([[entry(APP_OTHER)]])
    end_list(attributor, job, {OTHER: APP_OTHER}, 30.1)
    give_list(attributor, {OTHER: APP_OTHER}, now=60.0)  # it settles that line
    give_list(attributor, {A: APP_OTHER}, now=90.0)
    assert attributor.unattributed == 0


def test_the_counts_of_a_list_that_fails_wait_for_the_next_list() -> None:
    attributor = make(~Package(A), {OTHER: APP_OTHER})
    attributor.judge([[entry(APP_OTHER, "before")]])
    job = run_list(attributor, 30.0)
    attributor.judge([[entry(APP_OTHER, "during")]])
    job.take(1, b"", b"")
    attributor.list_done(job, 30.1)
    give_list(attributor, {A: APP_OTHER}, now=60.0)
    assert attributor.unattributed == 2


def test_an_app_id_a_joined_list_named_is_not_asked_about_again() -> None:
    """A read joined a running list that named its app id: the next list does
    not take that app id as asked about, so a removal does not make it absent."""
    attributor = make(~Package(A), {})
    job = run_list(attributor, 30.0)
    line = entry(NEW, "n", at=31.0)
    assert attributor.needs_list([[line]])
    end_list(attributor, job, {B: NEW}, 30.1)
    assert not attributor.needs_list([[line]])  # B's
    give_list(attributor, {}, now=60.0)  # B was removed
    assert attributor.needs_list([[entry(NEW, "fresh", at=61.0)]])  # not absent


def test_a_listed_system_uid_counts_when_a_watched_package_joins_it() -> None:
    settings = "com.android.settings"
    attributor = make(Package(settings), {"android": 1000})
    assert attributor.judge([[entry(1000, str(n)) for n in range(3)]]) == []
    attributor.judge([[entry(1001, "not listed")]])
    attributor.take_messages()
    give_list(attributor, {"android": 1000, settings: 1000}, now=30.0)
    assert attributor.unattributed == 3
    assert (
        f"emu: {settings} appeared under uid 1000: 3 lines judged before it was "
        "known are counted as unattributed"
    ) in warnings(attributor)


def test_system_uid_lines_judged_before_any_list_count_for_a_later_owner() -> None:
    """The start list failed, so rule 3 decides the lines of uid 1000; the
    recovery list shows the watched package under that uid."""
    settings = "com.android.settings"
    attributor = PackageAttributor(Package(settings), serial="emu")
    fail_list(attributor, 0.0)
    read = [[entry(1000, str(n)) for n in range(3)] + [entry(90001, "isolated")]]
    assert not attributor.needs_list(read)
    assert attributor.judge(read) == []
    assert attributor.unattributed == 0
    attributor.take_messages()
    give_list(attributor, {"android": 1000, settings: 1000}, now=30.0)
    assert attributor.unattributed == 3
    assert (
        f"emu: {settings} appeared under uid 1000: 3 lines judged before it was "
        "known are counted as unattributed"
    ) in warnings(attributor)


def test_system_uid_lines_the_first_list_settles_are_not_counted_later() -> None:
    settings = "com.android.settings"
    attributor = PackageAttributor(Package(settings), serial="emu")
    attributor.judge([[entry(1000, "s")]])
    give_list(attributor, {"android": 1000}, now=0.0)
    give_list(attributor, {"android": 1000, settings: 1000}, now=30.0)
    assert attributor.unattributed == 0  # the first list settled that line


def test_unlisted_system_uid_lines_count_when_a_watched_package_appears_there() -> None:
    """No list named uid 1001 when its lines were judged; the next list shows
    the watched package under it."""
    settings = "com.android.settings"
    attributor = make(Package(settings), {"android": 1000})
    read = [[entry(1001, str(n)) for n in range(2)]]
    assert not attributor.needs_list(read)
    assert attributor.judge(read) == []
    attributor.take_messages()
    give_list(attributor, {"android": 1000, settings: 1001}, now=30.0)
    assert attributor.unattributed == 2
    assert (
        f"emu: {settings} appeared under uid 1001: 2 lines judged before it was "
        "known are counted as unattributed"
    ) in warnings(attributor)


def test_unlisted_system_uid_lines_count_only_until_the_next_list() -> None:
    settings = "com.android.settings"
    attributor = make(Package(settings), {"android": 1000})
    attributor.judge([[entry(1001, "s")]])
    give_list(attributor, {"android": 1000}, now=30.0)
    give_list(attributor, {"android": 1000, settings: 1001}, now=60.0)
    assert attributor.unattributed == 0


# -- The app ids that watched packages left -----------------------------------------


@pytest.mark.parametrize(
    "condition",
    [Package(A) | Tag("keep"), Tag("keep") | Package(A)],
    ids=["package-first", "tag-first"],
)
def test_every_line_of_an_app_id_a_watched_package_left_is_counted_once(
    condition: Condition,
) -> None:
    """A tag that settles the verdict does not keep a late line of A's old
    uid from being counted: it is counted at once, judged without an owner,
    and not again by a later list."""
    attributor = make(condition, {A: APP_A})
    give_list(attributor, {A: APP_B}, now=30.0)
    late = [[entry(APP_A, "k", tag="keep", at=29.0), entry(APP_A, "d", at=29.0)]]
    assert not attributor.needs_list(late)
    out = attributor.judge(late)
    assert [(e.message, e.package) for e in entries_of(out[0])] == [("k", None)]
    assert attributor.unattributed == 2
    give_list(attributor, {A: APP_A}, now=31.0)  # A is back under its old uid
    assert attributor.unattributed == 2


@pytest.mark.parametrize(
    ("condition", "delivered"), [(Package(A), []), (~Package(A), ["s"])]
)
def test_lines_of_a_system_uid_a_watched_package_left_are_counted(
    condition: Condition, delivered: list[str]
) -> None:
    attributor = make(condition, {A: 1000})
    give_list(attributor, {A: APP_A}, now=30.0)
    late = [[entry(1000, "s", at=29.0)]]
    assert not attributor.needs_list(late)
    assert texts(attributor.judge(late)) == delivered
    assert attributor.unattributed == 1
    give_list(attributor, {A: APP_A}, now=60.0)
    assert texts(attributor.judge([[entry(1000, "s2", at=59.0)]])) == [
        f"{d}2" for d in delivered
    ]
    assert attributor.unattributed == 1  # rule 4 is over: rule 3 again


@pytest.mark.parametrize(
    "after", [{A: APP_B, OTHER: APP_A}, {A: APP_B}, {}], ids=["given", "freed", "gone"]
)
def test_lines_of_an_app_id_a_watched_package_left_are_counted_until_the_regular_list(
    after: dict[str, int],
) -> None:
    """They may be late lines of the package (the reader is behind)."""
    attributor = make(~Package(A), {A: APP_A})
    give_list(attributor, after, now=30.0)
    attributor.take_messages()
    late = [[entry(APP_A, "late", at=29.0)]]
    assert not attributor.needs_list(late)  # no list for it
    out = attributor.judge(late)
    assert [(e.message, e.package) for e in entries_of(out[0])] == [("late", None)]
    assert attributor.unattributed == 1
    assert warnings(attributor) == [
        "emu: lines whose app could not be determined are counted as "
        "unattributed (first: its uid belonged to a watched package until a "
        "recent package list)"
    ]
    give_list(attributor, after, now=60.0)
    later = [[entry(APP_A, "later", at=59.0)]]  # judged as usual again
    assert attributor.needs_list(later) == (APP_A not in after.values())


@pytest.mark.parametrize("gap", [29.9, 30.0])
def test_a_list_for_a_read_does_not_end_the_count_of_an_app_id_a_package_left(
    gap: float,
) -> None:
    """A read of another new app takes its own list soon after the list that
    showed A's reinstall: A's late lines under its old uid are still counted.
    Only a list that started ``RECHECK_INTERVAL`` after the move ends that."""
    attributor = make(~Package(A), {A: APP_A})
    give_list(attributor, {A: APP_B}, now=30.0)  # A was reinstalled
    unknown = [[entry(NEW, "u", at=30.5)]]
    assert attributor.needs_list(unknown)
    give_list(attributor, {A: APP_B}, now=30.6)  # the read's own list
    assert texts(attributor.judge(unknown)) == ["u"]  # absent: not A's
    assert attributor.unattributed == 1  # u: its app could not be checked
    attributor.take_messages()
    late = [[entry(APP_A, "late", at=29.0)]]
    assert not attributor.needs_list(late)
    out = attributor.judge(late)
    assert [(e.message, e.package) for e in entries_of(out[0])] == [("late", None)]
    assert attributor.unattributed == 2  # and late
    give_list(attributor, {A: APP_B}, now=30.0 + gap)
    later = [[entry(APP_A, "later", at=59.0)]]
    assert attributor.needs_list(later) == (gap >= 30.0)


def test_a_left_app_id_is_no_longer_counted_once_a_watched_package_has_it() -> None:
    attributor = make(Package(A, B), {A: APP_A})
    give_list(attributor, {A: APP_B}, now=30.0)
    give_list(attributor, {A: APP_B, B: APP_A}, now=31.0)  # B got the old uid
    out = attributor.judge([[entry(APP_A, "b", at=31.5)]])
    assert [(e.message, e.package) for e in entries_of(out[0])] == [("b", B)]
    assert attributor.unattributed == 0


def test_a_reinstall_without_lines_is_an_info() -> None:
    attributor = make(Package(A, B), {A: APP_A, B: APP_A})
    give_list(attributor, {A: APP_B, B: APP_OTHER}, now=30.0)
    assert attributor.take_messages() == [
        (logging.INFO, "emu: com.example.a has a new uid"),
        (logging.INFO, "emu: com.example.b has a new uid"),
    ]
    give_list(attributor, {B: APP_OTHER}, now=60.0)
    assert attributor.take_messages() == [
        (logging.INFO, "emu: com.example.a is no longer installed"),
    ]
    assert attributor.unattributed == 0


def test_a_line_a_new_list_no_longer_explains_names_that_cause() -> None:
    attributor = make(~Package(A), {OTHER: APP_OTHER})
    read = [[entry(APP_OTHER, "o", at=1.0), entry(NEW, "n", at=1.0)]]
    assert attributor.needs_list(read)  # for NEW only
    give_list(attributor, {}, now=1.0)  # OTHER was removed meanwhile
    assert texts(attributor.judge(read)) == ["o", "n"]
    assert attributor.unattributed == 2  # and n, whose app is absent
    assert warnings(attributor) == [
        "emu: lines whose app could not be determined are counted as "
        "unattributed (first: the package list taken for its read no longer "
        "names its uid)"
    ]


# -- Lines whose app no list could check -----------------------------------------

UNCHECKED = (
    "emu: lines whose app could not be determined are counted as unattributed "
    "(first: the app of its uid could not be checked: the package list taken "
    "after the line was read did not name the uid)"
)


def absent_after_list(condition: Condition) -> PackageAttributor:
    """An attributor with a boundary, whose list for a read did not name NEW."""
    attributor = PackageAttributor(condition, serial="emu")
    attributor.boundary = CLOCK
    give_list(attributor, {})
    assert attributor.needs_list([[entry(NEW, at=1.0)]])
    give_list(attributor, {}, now=1.0)  # NEW is absent from now on
    attributor.take_messages()
    return attributor


def test_lines_of_an_absent_app_id_after_the_boundary_are_counted() -> None:
    """A watched app may have been installed and removed while the reader was
    behind the device: no list could check the app of these lines."""
    attributor = absent_after_list(Package(A))
    read = [[entry(NEW, "at", at=0.0), entry(NEW, "later", at=2.0)]]
    assert not attributor.needs_list(read)  # no list is taken for them
    assert attributor.judge(read, "the stream stopped") == []
    assert attributor.unattributed == 2
    assert warnings(attributor) == [UNCHECKED]


def test_lines_of_an_absent_app_id_before_the_boundary_are_not_counted() -> None:
    attributor = absent_after_list(~Package(A))
    read = [[entry(NEW, "before", at=-0.000001)]]
    assert not attributor.needs_list(read)
    assert texts(attributor.judge(read)) == ["before"]
    assert attributor.unattributed == 0
    assert warnings(attributor) == []
    give_list(attributor, {A: NEW}, now=31.0)  # counted once a list shows A
    assert attributor.unattributed == 1


def test_each_line_of_an_absent_app_id_after_the_boundary_is_counted_once() -> None:
    attributor = absent_after_list(~Package(A))
    attributor.judge([[entry(NEW, "before the list", at=1.0)]])
    job = run_list(attributor, 30.0)
    attributor.judge([[entry(NEW, "while it runs", at=30.5)]])
    end_list(attributor, job, {}, 30.1)
    assert attributor.unattributed == 2
    give_list(attributor, {A: NEW}, now=60.0)  # A is under that app id now
    assert attributor.unattributed == 2
    assert warnings(attributor) == [UNCHECKED]


# -- The dump's judge ------------------------------------------------------------


def test_the_dump_judge_is_two_valued() -> None:
    keep, _ = dump_judge(Package(A), {A: APP_A})
    out = keep([entry(APP_A, "a"), entry(NEW, "n"), entry(None, "u")])
    assert [e.message for e in out] == ["a"]
    assert out[0].package == A
    keep_not, _ = dump_judge(~Package(A), {A: APP_A})
    assert [e.message for e in keep_not([entry(APP_A), entry(NEW, "n")])] == ["n"]


def test_the_dump_judge_messages_and_shared_uids() -> None:
    settings = "com.android.settings"
    keep, messages = dump_judge(
        Package(A, B, settings), {B: APP_A, A: APP_A, settings: 1000}, "emu"
    )
    assert keep([entry(APP_A)])[0].package == A
    assert messages == [
        (
            logging.WARNING,
            "emu: com.android.settings runs under the system uid 1000: every "
            "process of that uid is taken as belonging to it",
        )
    ]
    _, missing = dump_judge(Package(A), {}, "emu")
    assert missing == [
        (logging.INFO, f"{A} is not installed on emu; the dump has no lines of it")
    ]


# -- The recordings --------------------------------------------------------------


def recorded_pm_list(level: int) -> dict[str, int]:
    rec = step(load(level_dir(level), "C03"), "pm_list_packages_U")
    job = ListJob()
    job.take(0, "\n".join(rec["stdout"]).encode(), b"")
    assert isinstance(job.outcome, Listed)
    return job.outcome.uids


def recorded_dump(level: int) -> list[LogEntry]:
    rec = step(load(level_dir(level), "C03"), "dump")
    return list(parse_lines(rec["stdout"]))


def test_the_recorded_api36_backlog_needs_no_second_list() -> None:
    gms = "com.google.android.gms"
    attributor = make(Package(gms), recorded_pm_list(36))
    lines = recorded_dump(36)
    assert not attributor.needs_list([lines])
    out = attributor.judge([lines])
    assert [(e.uid, e.package) for e in entries_of(out[0])] == [(10146, gms)]
    assert attributor.unattributed == 0


# The recorded API 36 backlog: 214,301 lines, of which about a fifth carry one of
# the recorded app uids (all in the recorded list). The pure form runs the whole
# size with a fake clock at the recorded read speed.
BACKLOG_LINES = 214_301
READ_LINES = 1_200
LINES_PER_SECOND = 378_000
APP_UIDS = (10097, 10135, 10146, 10147, 10153, 10182, 10183)
SYSTEM_UIDS = (1000, 0, 1041, 1021, 2000)
GMS = "com.google.android.gms"


def backlog(removed: int | None, at: float) -> list[LogEntry]:
    """The synthetic backlog; every 100th line of the app id ``removed`` (not in
    the list) logged ``at`` seconds from the boundary, when given."""
    out = []
    for i in range(BACKLOG_LINES):
        if removed is not None and i % 100 == 50:
            uid, when = removed, at
        elif i % 1000 < 198:
            uid, when = APP_UIDS[i % len(APP_UIDS)], -60.0
        else:
            uid, when = SYSTEM_UIDS[i % len(SYSTEM_UIDS)], -60.0
        out.append(entry(uid, "m", at=when))
    return out


def run_backlog(lines: list[LogEntry]) -> tuple[PackageAttributor, int, int]:
    """Read ``lines`` as a stream would; return the attributor, lists, delivered."""
    attributor = PackageAttributor(Package(GMS), serial="emu")
    attributor.boundary = CLOCK
    uids = recorded_pm_list(36)
    lists = 0

    def take(now: float) -> None:
        nonlocal lists
        lists += 1
        job = attributor.list_started(now)
        job.take(0, pm_text(uids), b"")
        attributor.list_done(job, now + 0.1)

    take(0.0)
    delivered = 0
    for start in range(0, len(lines), READ_LINES):
        now = 0.1 + start / LINES_PER_SECOND
        read: list[Segment] = [lines[start : start + READ_LINES]]
        if attributor.list_due(now):
            take(now)
        if attributor.needs_list(read):
            take(max(now, attributor.ready_at()))
        delivered += sum(len(entries_of(s)) for s in attributor.judge(read))
    return attributor, lists, delivered


@pytest.mark.parametrize(
    ("removed", "at", "lists", "counted"),
    [(None, 0.0, 1, False), (NEW, -1.0, 1, False), (NEW, 0.0, 2, True)],
    ids=["as-recorded", "removed-app-before-the-boundary", "new-app-after-it"],
)
def test_the_recorded_backlog_size_at_full_speed(
    removed: int | None, at: float, lists: int, *, counted: bool
) -> None:
    """The lines of an app that no list names count when they are not older
    than the boundary (the app may have been a watched one)."""
    lines = backlog(removed, at)
    attributor, taken, delivered = run_backlog(lines)
    new_lines = sum(1 for e in lines if e.uid == NEW)
    assert attributor.unattributed == (new_lines if counted else 0)
    assert taken == lists
    assert delivered == sum(1 for e in lines if e.uid == 10146)
