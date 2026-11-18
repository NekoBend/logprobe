"""Package attribution: holding, lookups, accounting and the dumpsys reader."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from logprobe import Gap, LogEntry, Package, Tag
from logprobe._attribution import (
    CHUNK_ENTRIES,
    HOLD_SECONDS,
    LOOKUP_INTERVAL,
    NEGATIVE_LIFETIME,
    RECHECK_INTERVAL,
    PackageAttributor,
    Segment,
    parse_package_uid,
)
from logprobe._outbox import MARKER_BYTES
from tests.device_facts import LEVELS, level_dir, load, step

A = "com.example.a"
B = "com.example.b"
APP_A = 10053
APP_B = 10054
UNKNOWN = 10099


def entry(uid: int | None, text: str = "x", tag: str = "T") -> LogEntry:
    return LogEntry(
        logged_at=datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC),
        pid=1,
        tid=1,
        level="I",
        tag=tag,
        message=text,
        raw=text,
        uid=uid,
    )


def gap(serial: str = "s") -> Gap:
    now = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)
    return Gap(serial, "continuity_unknown", "disconnected", now, None)


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


def learn(attributor: PackageAttributor, uids: dict[str, int], now: float) -> None:
    """Answer the initial lookups from ``uids``; a missing package is not found."""
    while (lookup := attributor.next_lookup(now)) is not None:
        attributor.lookup_done(lookup, uids.get(lookup.package), now)


def make(
    *names: str, hold_lines: int = 10_000, hold_charge: int = 4 << 20
) -> PackageAttributor:
    return PackageAttributor(
        Package(*names), hold_lines=hold_lines, hold_charge=hold_charge
    )


# -- Deciding lines --------------------------------------------------------------


def test_known_owner_decides_at_once() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A, B: APP_B}, 0)
    out = attributor.admit([[entry(APP_A, "a"), entry(1000, "b"), entry(None, "n")]], 1)
    assert texts(out) == ["a"]
    assert attributor.held_lines == 0
    assert attributor.unattributed == 0
    assert entries_of(out[0])[0].package == A


def test_no_watched_package_decides_at_once() -> None:
    kept = PackageAttributor(~Package(A), packages=[])
    out = kept.admit([[entry(APP_A, "a"), entry(APP_B, "b")]], 1)
    assert texts(out) == ["a", "b"]
    dropped = PackageAttributor(Package(A), packages=[])
    assert dropped.admit([[entry(APP_A, "a")]], 1) == []
    for attributor in (kept, dropped):
        assert attributor.held_lines == 0
        assert attributor.next_lookup(1) is None


def test_system_uids_and_other_ranges_do_not_match_or_hold() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    out = attributor.admit([[entry(1000), entry(0), entry(99001), entry(25000)]], 1)
    assert out == []
    assert attributor.held_lines == 0
    assert attributor.next_lookup(1) is None


def test_secondary_user_matches_by_app_id() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    out = attributor.admit(
        [[entry(APP_A + 100_000, "u1"), entry(APP_A + 200_000, "u2")]], 1
    )
    assert texts(out) == ["u1", "u2"]
    assert entries_of(out[0])[0].package == A


def test_display_package_is_first_by_name_and_both_match_a_shared_uid() -> None:
    both = PackageAttributor(Package(A) & Package(B))
    learn(both, {A: APP_A, B: APP_A}, 0)
    assert texts(both.admit([[entry(APP_A, "x")]], 1)) == ["x"]
    only_b = PackageAttributor(Package(B), packages=[A, B])
    learn(only_b, {A: APP_A, B: APP_A}, 0)
    out = only_b.admit([[entry(APP_A, "x")]], 1)
    assert texts(out) == ["x"]
    assert entries_of(out[0])[0].package == A
    negated = PackageAttributor(~Package(A), packages=[A, B])
    learn(negated, {A: APP_A, B: APP_A}, 0)
    assert negated.admit([[entry(APP_A, "x")]], 1) == []


def test_decisive_verdict_needs_no_owner() -> None:
    attributor = PackageAttributor(Package(A) | Tag("keep"))
    out = attributor.admit([[entry(UNKNOWN, "k", tag="keep"), entry(UNKNOWN, "z")]], 0)
    assert texts(out) == ["k"]
    assert attributor.held_lines == 1


def test_condition_without_package_term_never_looks_up() -> None:
    attributor = PackageAttributor(Tag("t"))
    assert attributor.next_lookup(0) is None
    assert texts(attributor.admit([[entry(UNKNOWN, "a", tag="t")]], 0)) == ["a"]
    assert attributor.next_deadline() is None


# -- Order, holding and gaps -----------------------------------------------------


def test_unknown_uid_holds_and_a_gap_keeps_its_place() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    out = attributor.admit(
        [
            [entry(APP_A, "1"), entry(UNKNOWN, "2"), entry(APP_A, "3")],
            gap(),
            [entry(APP_A, "4")],
        ],
        1,
    )
    assert texts(out) == ["1"]
    assert attributor.held_lines == 4  # "2", "3", the gap and "4"
    lookup = attributor.next_lookup(1)
    assert lookup is not None
    assert lookup.package == A
    out = attributor.lookup_done(lookup, APP_A, 1.1)
    # UNKNOWN is still without an owner, so the round ends and the app id is negative.
    assert texts(out) == ["3", "GAP", "4"]
    assert attributor.held_lines == 0
    assert attributor.unattributed == 0


def test_gap_waits_behind_an_undecided_entry() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    assert attributor.admit([[entry(UNKNOWN, "u")], gap()], 1) == []
    assert attributor.held_lines == 2
    assert attributor.held_charge > MARKER_BYTES
    out = attributor.expire(1 + HOLD_SECONDS)
    assert texts(out) == ["GAP"]  # "u" is judged without owners: Package(A) is False
    assert attributor.unattributed == 1


def test_entry_found_to_belong_is_released_with_package_name() -> None:
    attributor = make(A)
    learn(attributor, {}, 0)
    assert attributor.admit([[entry(APP_A, "late")]], 1) == []
    lookup = attributor.next_lookup(1)
    assert lookup is not None
    out = attributor.lookup_done(lookup, APP_A, 1.05)
    assert texts(out) == ["late"]
    assert entries_of(out[0])[0].package == A
    assert attributor.unattributed == 0


def test_order_of_released_entries_is_the_arrival_order() -> None:
    attributor = make(A)
    learn(attributor, {}, 0)
    attributor.admit([[entry(APP_A, "1")], gap(), [entry(APP_A, "2")]], 1)
    attributor.admit([[entry(APP_A, "3")]], 1.5)
    lookup = attributor.next_lookup(1.5)
    assert lookup is not None
    out = attributor.lookup_done(lookup, APP_A, 1.6)
    assert texts(out) == ["1", "GAP", "2", "3"]


# -- Hold limits -----------------------------------------------------------------


def test_hold_time_limit_is_per_line() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    attributor.admit([[entry(UNKNOWN, "old")]], 1.0)
    attributor.admit([[entry(UNKNOWN, "new")]], 2.5)
    assert attributor.expire(2.9) == []
    assert attributor.unattributed == 0
    attributor.expire(3.0)
    assert attributor.unattributed == 1  # only the old line
    assert attributor.held_lines == 1
    attributor.expire(4.5)
    assert attributor.unattributed == 2
    assert attributor.held_lines == 0


def test_deadline_is_the_oldest_held_line() -> None:
    attributor = make(A)
    assert attributor.next_lookup(0) is not None  # outstanding: no lookup terms
    attributor.admit([[entry(UNKNOWN, "old")]], 5.0)
    attributor.admit([[entry(UNKNOWN, "new")]], 6.0)
    assert attributor.next_deadline() == 5.0 + HOLD_SECONDS
    attributor.expire(5.0 + HOLD_SECONDS)
    assert attributor.next_deadline() == 6.0 + HOLD_SECONDS


def test_line_limit_flushes_the_oldest_without_owners() -> None:
    attributor = make(A, hold_lines=5)
    learn(attributor, {A: APP_A}, 0)
    out = attributor.admit([[entry(UNKNOWN, str(i)) for i in range(8)]], 1)
    assert out == []
    assert attributor.held_lines == 5
    assert attributor.unattributed == 3


def test_a_gap_counts_as_one_line_in_the_limit() -> None:
    attributor = make(A, hold_lines=3)
    learn(attributor, {A: APP_A}, 0)
    out = attributor.admit(
        [[entry(UNKNOWN, "1")], gap(), [entry(UNKNOWN, "2"), entry(UNKNOWN, "3")]], 1
    )
    # 4 lines held with room for 3: the oldest is judged; the gap is now at the head.
    assert texts(out) == ["GAP"]
    assert attributor.held_lines == 2
    assert attributor.unattributed == 1


def test_charge_limit_uses_the_average_charge_of_the_read() -> None:
    attributor = make(A, hold_charge=1000)
    learn(attributor, {A: APP_A}, 0)
    attributor.admit([[entry(UNKNOWN, str(i)) for i in range(10)]], 1, charge=2000)
    # 200 per line, room for 5 lines.
    assert attributor.held_lines == 5
    assert attributor.held_charge == 1000
    assert attributor.unattributed == 5
    attributor.admit([[entry(UNKNOWN, "x")]], 1.1, charge=10)
    assert attributor.held_charge == 810
    assert attributor.held_lines == 5
    assert attributor.unattributed == 6


def test_charge_is_estimated_without_a_given_charge() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    attributor.admit([[entry(UNKNOWN, "abc")]], 1)
    assert attributor.held_charge == 4


def test_estimated_charge_counts_utf8_bytes() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    text = "\U0001f600" * 4
    attributor.admit([[entry(UNKNOWN, text)]], 1)
    assert attributor.held_charge == len(text.encode()) + 1


# -- Lookups ---------------------------------------------------------------------


def test_lookups_run_one_at_a_time() -> None:
    attributor = make(A, B)
    first = attributor.next_lookup(0)
    assert first is not None
    assert attributor.next_lookup(0) is None
    assert attributor.lookup_done(first, APP_A, 0.01) == []
    second = attributor.next_lookup(0.01)
    assert second is not None
    assert {first.package, second.package} == {A, B}
    assert first.command == f"dumpsys package {first.package}"


def test_answer_to_another_request_is_ignored() -> None:
    attributor = PackageAttributor(Package(A) | Package(B))
    first = attributor.next_lookup(0)
    assert first is not None
    attributor.lookup_done(first, APP_A, 0.1)
    second = attributor.next_lookup(0.1)
    assert second is not None
    # The answer to the first request arrives again while the second is out.
    assert attributor.lookup_done(first, APP_B, 0.2) == []
    assert attributor.warnings == []
    assert attributor.next_lookup(0.2) is None  # the second is still awaited
    attributor.lookup_done(second, APP_B, 0.3)
    assert texts(attributor.admit([[entry(APP_B, "b")]], 0.4)) == ["b"]


def test_lookup_of_a_package_is_paced() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    attributor.admit([[entry(UNKNOWN, "1")]], 0.1)
    assert attributor.next_lookup(0.1) is None  # tried at 0.0
    deadline = attributor.next_deadline()
    assert deadline is not None
    assert deadline == pytest.approx(LOOKUP_INTERVAL)
    assert attributor.next_lookup(LOOKUP_INTERVAL - 0.01) is None
    lookup = attributor.next_lookup(LOOKUP_INTERVAL)
    assert lookup is not None
    assert lookup.in_round


def test_the_clock_can_be_driven_by_next_deadline_alone() -> None:
    tried = 4095.6097767602464  # tried + 0.5 - tried != 0.5 in floating point
    attributor = make(A)
    learn(attributor, {A: APP_A}, tried)
    attributor.admit([[entry(UNKNOWN, "1")]], tried + 0.1)
    now = tried + 0.1
    for _ in range(3):
        deadline = attributor.next_deadline()
        assert deadline is not None
        now = max(now, deadline)
        lookup = attributor.next_lookup(now)
        if lookup is not None:
            break
    assert lookup is not None
    assert lookup.in_round


def test_unknown_uids_share_one_round() -> None:
    attributor = make(A, B)
    learn(attributor, {A: APP_A, B: APP_B}, 0)
    attributor.admit([[entry(UNKNOWN), entry(UNKNOWN + 1), entry(UNKNOWN)]], 1)
    done = []
    while (lookup := attributor.next_lookup(1)) is not None:
        done.append(lookup.package)
        attributor.lookup_done(lookup, {A: APP_A, B: APP_B}[lookup.package], 1)
    assert sorted(done) == [A, B]
    assert attributor.held_lines == 0
    assert attributor.next_lookup(1.5) is None


def test_startup_backlog_of_many_apps_needs_one_round() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    lines = [entry(UNKNOWN + n, f"u{n}") for n in range(8) for _ in range(3)]
    lines.insert(5, entry(APP_A, "mine"))
    assert attributor.admit([lines], 1.0) == []
    lookups = 0
    out: list[Segment] = []
    while (lookup := attributor.next_lookup(1.0)) is not None:
        lookups += 1
        out += attributor.lookup_done(lookup, APP_A, 1.0)
    assert lookups == 1
    assert texts(out) == ["mine"]
    assert attributor.held_lines == 0
    assert attributor.unattributed == 0
    assert attributor.next_lookup(1.5) is None
    assert attributor.next_deadline() == 1.0 + RECHECK_INTERVAL


def test_backlog_behind_a_stalled_line_is_registered_once_per_line() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    attributor.admit([[entry(UNKNOWN, "a"), entry(UNKNOWN + 1, "b")]], 1.0)
    attributor.admit([[entry(UNKNOWN + 2, "c")]], 1.0)
    lookup = attributor.next_lookup(1.0)
    assert lookup is not None
    out = attributor.lookup_done(lookup, APP_A, 1.0)
    assert out == []
    assert attributor.held_lines == 0
    assert attributor.unattributed == 0


def test_shared_uid_found_during_a_round_is_judged_with_all_owners() -> None:
    both = PackageAttributor(Package(A) & Package(B))
    assert both.admit([[entry(UNKNOWN, "x")]], 0) == []
    first = both.next_lookup(0)
    assert first is not None
    assert both.lookup_done(first, UNKNOWN, 0.1) == []
    assert both.held_lines == 1  # the other owner is not known yet
    second = both.next_lookup(0.1)
    assert second is not None
    out = both.lookup_done(second, UNKNOWN, 0.2)
    assert texts(out) == ["x"]
    assert both.unattributed == 0

    negated = PackageAttributor(~Package(B), packages=[A, B])
    assert negated.admit([[entry(UNKNOWN, "x")]], 0) == []
    first = negated.next_lookup(0)
    assert first is not None
    assert negated.lookup_done(first, UNKNOWN, 0.1) == []
    assert negated.held_lines == 1
    second = negated.next_lookup(0.1)
    assert second is not None
    assert negated.lookup_done(second, UNKNOWN, 0.2) == []  # B owns it: excluded
    assert negated.held_lines == 0
    assert negated.unattributed == 0


def test_unknown_uid_during_a_round_starts_another_round() -> None:
    attributor = make(A, B)
    learn(attributor, {A: APP_A, B: APP_B}, 0)
    attributor.admit([[entry(UNKNOWN)]], 1)
    lookup = attributor.next_lookup(1)
    assert lookup is not None
    attributor.admit([[entry(UNKNOWN + 1, "second")]], 1.01)
    attributor.lookup_done(lookup, {A: APP_A, B: APP_B}[lookup.package], 1.02)
    lookup = attributor.next_lookup(1.02)
    assert lookup is not None
    out = attributor.lookup_done(lookup, {A: APP_A, B: APP_B}[lookup.package], 1.03)
    assert out == []  # UNKNOWN is negative now; UNKNOWN + 1 still needs a round
    assert attributor.held_lines == 1
    assert attributor.next_lookup(1.04) is None  # paced: both looked up at 1.0-1.02
    assert attributor.next_lookup(1.6) is not None


def test_a_failed_lookup_judges_the_unresolved_lines_without_owners() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    attributor.admit([[entry(UNKNOWN, "1")]], 1)
    lookup = attributor.next_lookup(1)
    assert lookup is not None
    out = attributor.lookup_done(lookup, None, 1.1, failed=True)
    assert out == []  # judged without owners: Package(A) is False
    assert attributor.unattributed == 1
    assert attributor.held_lines == 0
    # The failure is not remembered as "belongs to nobody": lines count again.
    attributor.admit([[entry(UNKNOWN, "2")]], 1.2)
    assert attributor.held_lines == 0
    assert attributor.unattributed == 2


def test_package_that_is_not_installed_does_not_make_lines_unattributed() -> None:
    attributor = make(A, B)
    learn(attributor, {A: APP_A}, 0)  # B is not installed
    attributor.admit([[entry(UNKNOWN, "1")]], 1)
    while (lookup := attributor.next_lookup(1)) is not None:
        attributor.lookup_done(lookup, APP_A if lookup.package == A else None, 1)
    assert attributor.held_lines == 0
    assert attributor.unattributed == 0


def test_close_during_unanswered_lookup_ignores_the_answer() -> None:
    attributor = make(A)
    lookup = attributor.next_lookup(0)
    list(attributor.close())
    assert lookup is not None
    assert attributor.lookup_done(lookup, APP_A, 1) == []
    assert attributor.unattributed == 0
    assert attributor.warnings == []


def test_close_ignores_the_answer_of_a_recheck() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    attributor.admit([[entry(APP_A) for _ in range(4)]], 1)
    lookup = attributor.next_lookup(RECHECK_INTERVAL)
    assert lookup is not None
    list(attributor.close())
    assert attributor.lookup_done(lookup, UNKNOWN, RECHECK_INTERVAL + 0.1) == []
    assert attributor.unattributed == 0
    assert attributor.warnings == []


# -- The negative set ------------------------------------------------------------


def test_negative_set_stops_holding_until_it_is_cleared() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    attributor.admit([[entry(UNKNOWN, "1")]], 1)
    lookup = attributor.next_lookup(1)
    assert lookup is not None
    attributor.lookup_done(lookup, APP_A, 1.1)
    assert attributor.held_lines == 0
    # Known not to belong: decided at once, no lookup, nothing unattributed.
    assert attributor.admit([[entry(UNKNOWN, "2")]], 2) == []
    assert attributor.held_lines == 0
    assert attributor.next_lookup(2) is None
    assert attributor.unattributed == 0


def test_negative_set_expires_and_a_new_package_is_found() -> None:
    attributor = make(A)
    learn(attributor, {}, 0)  # A is not installed yet
    attributor.admit([[entry(UNKNOWN, "1")]], 1)
    lookup = attributor.next_lookup(1)
    assert lookup is not None
    attributor.lookup_done(lookup, None, 1.1)
    assert attributor.held_lines == 0
    # The app is installed later and writes lines: still judged "not ours".
    assert attributor.admit([[entry(UNKNOWN, "2")]], 10) == []
    assert attributor.next_lookup(10) is None
    # The memory is cleared NEGATIVE_LIFETIME after the first call (time 0).
    assert attributor.admit([[entry(UNKNOWN, "3")]], NEGATIVE_LIFETIME) == []
    assert attributor.held_lines == 1
    lookup = attributor.next_lookup(NEGATIVE_LIFETIME)
    assert lookup is not None
    out = attributor.lookup_done(lookup, UNKNOWN, NEGATIVE_LIFETIME + 0.05)
    assert texts(out) == ["3"]


# -- Re-assignment ---------------------------------------------------------------


def test_known_uid_is_rechecked_on_schedule() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    assert attributor.next_lookup(RECHECK_INTERVAL - 0.1) is None
    assert attributor.next_deadline() == pytest.approx(RECHECK_INTERVAL)
    lookup = attributor.next_lookup(RECHECK_INTERVAL)
    assert lookup is not None
    assert not lookup.in_round
    attributor.lookup_done(lookup, APP_A, RECHECK_INTERVAL)
    assert attributor.next_deadline() == pytest.approx(2 * RECHECK_INTERVAL)
    assert attributor.unattributed == 0
    assert attributor.warnings == []


def test_reassignment_counts_lines_judged_since_the_last_check() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    attributor.admit([[entry(APP_A, str(i)) for i in range(5)]], 1)
    attributor.admit([[entry(1000, "other")]], 2)  # decided without the owner map
    lookup = attributor.next_lookup(RECHECK_INTERVAL)
    assert lookup is not None
    out = attributor.lookup_done(lookup, UNKNOWN, RECHECK_INTERVAL)
    assert out == []
    # Only the 5 lines the old mapping judged; "other" did not use the map.
    assert attributor.unattributed == 5
    assert len(attributor.warnings) == 1
    assert A in attributor.warnings[0]
    assert "5" in attributor.warnings[0]
    # The new uid is decided with the new mapping; the old uid is unknown again.
    assert texts(attributor.admit([[entry(UNKNOWN, "new")]], RECHECK_INTERVAL + 1)) == [
        "new"
    ]
    assert attributor.admit([[entry(APP_A, "old")]], RECHECK_INTERVAL + 1) == []
    assert attributor.held_lines == 1


def test_shared_uid_reassignment_counts_every_line_once() -> None:
    attributor = PackageAttributor(Package(A) | Package(B))
    learn(attributor, {A: UNKNOWN, B: UNKNOWN}, 0)
    attributor.admit([[entry(UNKNOWN) for _ in range(5)]], 1)
    first = attributor.next_lookup(RECHECK_INTERVAL)
    assert first is not None
    attributor.lookup_done(first, UNKNOWN, RECHECK_INTERVAL)  # unchanged
    second = attributor.next_lookup(RECHECK_INTERVAL)
    assert second is not None
    attributor.lookup_done(second, None, RECHECK_INTERVAL, failed=True)
    attributor.admit([[entry(UNKNOWN) for _ in range(2)]], 31)
    changed = []
    while (lookup := attributor.next_lookup(2 * RECHECK_INTERVAL)) is not None:
        changed.append(lookup.package)
        attributor.lookup_done(lookup, UNKNOWN + 100, 2 * RECHECK_INTERVAL)
    assert len(changed) == 2
    # The first owner was checked after 5 lines, the second never since the start:
    # 7 distinct lines were judged with the old mapping, none of them twice.
    assert attributor.unattributed == 7
    assert len(attributor.warnings) == 2
    assert "2 lines" in attributor.warnings[0]
    assert "7 lines" in attributor.warnings[1]


def test_unchanged_recheck_resets_the_count() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    attributor.admit([[entry(APP_A) for _ in range(3)]], 1)
    lookup = attributor.next_lookup(RECHECK_INTERVAL)
    assert lookup is not None
    attributor.lookup_done(lookup, APP_A, RECHECK_INTERVAL)
    attributor.admit([[entry(APP_A) for _ in range(2)]], RECHECK_INTERVAL + 1)
    lookup = attributor.next_lookup(2 * RECHECK_INTERVAL)
    assert lookup is not None
    attributor.lookup_done(lookup, UNKNOWN, 2 * RECHECK_INTERVAL)
    assert attributor.unattributed == 2


def test_uninstalled_package_is_reported() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    attributor.admit([[entry(APP_A) for _ in range(4)]], 1)
    lookup = attributor.next_lookup(RECHECK_INTERVAL)
    assert lookup is not None
    attributor.lookup_done(lookup, None, RECHECK_INTERVAL)
    assert attributor.unattributed == 4
    assert "no longer" in attributor.warnings[0]


def test_failed_recheck_keeps_the_mapping_and_tries_again_later() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    attributor.admit([[entry(APP_A) for _ in range(4)]], 1)
    lookup = attributor.next_lookup(RECHECK_INTERVAL)
    assert lookup is not None
    attributor.lookup_done(lookup, None, RECHECK_INTERVAL, failed=True)
    assert attributor.unattributed == 0
    assert texts(attributor.admit([[entry(APP_A, "still")]], RECHECK_INTERVAL + 1)) == [
        "still"
    ]
    assert attributor.next_lookup(RECHECK_INTERVAL + 1) is None
    assert attributor.next_lookup(2 * RECHECK_INTERVAL) is not None


def test_system_uid_warns_once() -> None:
    attributor = make(A)
    learn(attributor, {A: 1000}, 0)
    assert len(attributor.warnings) == 1
    assert "system uid 1000" in attributor.warnings[0]
    lookup = attributor.next_lookup(RECHECK_INTERVAL)
    assert lookup is not None
    attributor.lookup_done(lookup, 1000, RECHECK_INTERVAL)
    assert len(attributor.warnings) == 1
    assert attributor.take_warnings() != []
    assert attributor.warnings == []
    assert texts(
        attributor.admit([[entry(1000, "sys"), entry(1001, "other")]], 31)
    ) == ["sys"]


def test_lookup_result_of_a_secondary_user_is_reduced_to_the_app_id() -> None:
    attributor = make(A)
    learn(attributor, {A: 1_000_000 + APP_A}, 0)
    assert texts(attributor.admit([[entry(APP_A, "p")]], 1)) == ["p"]


# -- Close and chunks ------------------------------------------------------------


def test_close_flushes_everything_and_counts_it() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    attributor.admit(
        [[entry(UNKNOWN, "1"), entry(APP_A, "2")], gap(), [entry(UNKNOWN, "3")]], 1
    )
    assert attributor.held_lines == 4
    out = list(attributor.close())
    assert texts(out) == ["2", "GAP"]
    assert attributor.unattributed == 2  # "1" and "3" were undecided
    assert attributor.held_lines == 0
    assert attributor.held_charge == 0
    assert attributor.next_deadline() is None
    assert attributor.next_lookup(5) is None
    assert attributor.expire(9) == []
    assert list(attributor.close()) == []
    with pytest.raises(RuntimeError):
        attributor.admit([[entry(APP_A)]], 10)


def test_close_judges_without_package_names() -> None:
    attributor = PackageAttributor(~Package(A))
    attributor.admit([[entry(UNKNOWN, "1")]], 1)
    assert texts(list(attributor.close())) == [
        "1"
    ]  # nobody owns it, so ~Package is true
    assert attributor.unattributed == 1


def test_released_lines_are_split_into_chunks_of_2048() -> None:
    attributor = make(A)
    learn(attributor, {}, 0)
    count = 2 * CHUNK_ENTRIES + 5
    attributor.admit([[entry(APP_A, str(i)) for i in range(count)]], 1, charge=count)
    lookup = attributor.next_lookup(1)
    assert lookup is not None
    out = attributor.lookup_done(lookup, APP_A, 1.1)
    assert [len(entries_of(s)) for s in out] == [CHUNK_ENTRIES, CHUNK_ENTRIES, 5]
    assert sum(attributor.last_charges) == count


def test_a_full_read_of_matching_lines_is_one_chunk() -> None:
    attributor = make(A)
    learn(attributor, {}, 0)
    attributor.admit([[entry(APP_A, str(i)) for i in range(800)]], 1, charge=65_536)
    lookup = attributor.next_lookup(1)
    assert lookup is not None
    out = attributor.lookup_done(lookup, APP_A, 1.1)
    assert [len(entries_of(s)) for s in out] == [800]
    assert sum(attributor.last_charges) <= 65_536


def test_chunks_are_split_by_charge_and_a_gap_separates_them() -> None:
    attributor = make(A)
    learn(attributor, {}, 0)
    attributor.admit(
        [[entry(APP_A, "1"), entry(APP_A, "2")], gap(), [entry(APP_A, "3")]],
        1,
        charge=3 * 40_000,
    )
    lookup = attributor.next_lookup(1)
    assert lookup is not None
    out = attributor.lookup_done(lookup, APP_A, 1.1)
    assert [type(s) for s in out] == [list, list, Gap, list]
    assert attributor.last_charges == [40_000, 40_000, MARKER_BYTES, 40_000]


def test_decided_read_is_returned_as_one_list() -> None:
    attributor = make(A)
    learn(attributor, {A: APP_A}, 0)
    out = attributor.admit([[entry(APP_A, str(i)) for i in range(10)]], 1, charge=100)
    assert len(out) == 1
    assert type(out[0]) is list
    assert attributor.last_charges == [100]


# -- The dumpsys reader ----------------------------------------------------------

DUMP_24 = """\
Packages:
  Package [com.example.app] (1a2b3c4):
    userId=10053
    pkg=Package{5d6e com.example.app}
    sharedUser=null
    userId=10099
  Package [com.example.app.extra] (aaaaaaa):
    userId=10100
"""

DUMP_36 = """\
Packages:
  Package [com.example.app] (9f8e7d6):
    appId=10161
    pkg=Package{4c3b com.example.app}
"""


def test_parser_reads_the_first_user_id_or_app_id() -> None:
    assert parse_package_uid(DUMP_24, "com.example.app") == 10053
    assert parse_package_uid(DUMP_36, "com.example.app") == 10161


def test_parser_selects_the_exact_record() -> None:
    assert parse_package_uid(DUMP_24, "com.example.app.extra") == 10100
    assert parse_package_uid(DUMP_24, "com.example") is None
    assert parse_package_uid(DUMP_24, "com.example.app.ex") is None
    assert parse_package_uid(DUMP_24, "com.example.app.extra2") is None


def test_parser_ignores_other_records_and_mentions() -> None:
    dump = """\
Hidden system packages:
  Package [com.example.apple] (1):
    userId=10001
Activity Resolver Table:
  Package [com.example.app] is mentioned here without a record
    userId=10001
Packages:
  Package [com.example.app] (2):
    flags=[ HAS_CODE ]
    sharedUserId=7
    userId=10002 gids=[3003]
    User 0: ceDataInode=1
  Package [com.example.zzz] (3):
    userId=10003
"""
    assert parse_package_uid(dump, "com.example.app") == 10002
    assert parse_package_uid(dump, "com.example.zzz") == 10003


def test_parser_stops_at_the_end_of_a_record() -> None:
    dump = """\
  Package [com.example.a] (1):
    versionCode=1
Shared users:
  SharedUser [x]:
    userId=10008
"""
    assert parse_package_uid(dump, "com.example.a") is None


def test_parser_without_record_or_with_empty_input() -> None:
    assert parse_package_uid("", "com.example.a") is None
    assert (
        parse_package_uid("Unable to find package: com.example.a\n", "com.example.a")
        is None
    )
    assert (
        parse_package_uid(
            "Package [com.example.a] (1):\r\n    appId=12\r\n", "com.example.a"
        )
        == 12
    )


def _dump_lines(level: int, name: str) -> list[str]:
    recording = load(level_dir(level), "C03")
    return step(recording, name)["stdout"]


@pytest.mark.parametrize("level", LEVELS)
def test_parser_on_the_single_package_recordings(level: int) -> None:
    text = "\n".join(_dump_lines(level, "dumpsys_package"))
    assert parse_package_uid(text, "com.android.settings") == 1000
    assert parse_package_uid(text, "com.android.settings.intelligence") is None
    assert parse_package_uid(text, "com.android") is None


@pytest.mark.parametrize("level", LEVELS)
def test_parser_on_the_listing_of_all_packages(level: int) -> None:
    recording = load(level_dir(level), "C03")
    text = "\n".join(_dump_lines(level, "dumpsys_package_packages"))
    expected = recording["facts"]["app_uid_tokens_to_packages"]
    checked = 0
    for uid, names in expected.items():
        for name in names:
            assert parse_package_uid(text, name) == int(uid), name
            checked += 1
    assert checked >= 10
    # Every record in the listing is read, and equals the line under its header.
    pairs = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("  Package ["):
            pairs.append((line[len("  Package [") : line.index("]")], lines[index + 1]))
    assert len(pairs) >= 90
    for name, following in pairs:
        assert parse_package_uid(text, name) == int(following.split("=")[1]), name


@pytest.mark.parametrize("level", LEVELS)
def test_parser_rejects_prefixes_of_recorded_names(level: int) -> None:
    text = "\n".join(_dump_lines(level, "dumpsys_package_packages"))
    names = [
        line[len("  Package [") : line.index("]")]
        for line in text.splitlines()
        if line.startswith("  Package [")
    ]
    for name in names[:40]:
        assert parse_package_uid(text, name[:-1]) is None
        assert parse_package_uid(text, name + "x") is None
