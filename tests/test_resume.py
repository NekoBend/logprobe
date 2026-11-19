"""Tests for the reconnect decisions and the resume check of the stream readers."""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta, timezone

import pytest

from logprobe import Gap, LogprobeError
from logprobe import _feed as feed_module
from logprobe._feed import OVERLAP, Feeder
from logprobe._resume import (
    BACKOFF_CAP,
    QUICK_END,
    QUICK_LIMIT,
    RESUME_IDLE,
    STABLE_AFTER,
    STALL_AFTER,
    Decision,
    EndKind,
    ReconnectPolicy,
    ResumeCheck,
    ResumeFlags,
    attempt_error_code,
    backoff,
    cause_of,
    classify_end,
    end_error,
    parse_sdk,
    plan_resume,
    skips_silently,
    stall_limit,
    t_arg,
)

BASE = datetime(2026, 11, 4, 4, 21, 0, tzinfo=UTC)
NOW = datetime(2026, 11, 4, 5, 0, 0, tzinfo=UTC)
API24_EOF = "read: unexpected EOF!\n"
API36_EOF = (
    "logcat: Unexpected EOF!\n"
    "\n"
    "This means that either the device shut down, logd crashed, or this instance"
    " of logcat was unable to read log\n"
    "messages as quickly as they were being produced.\n"
    "\n"
    "If you have enabled significant logging, look into using the -G option to"
    " increase log buffer sizes.\n"
)


def stamp(seconds: float) -> datetime:
    return BASE + timedelta(seconds=seconds)


def line(seconds: float, msg: str = "hello") -> str:
    moment = stamp(seconds)
    clock = f"{moment:%Y-%m-%d %H:%M:%S}.{moment.microsecond:06d} +0000"
    return f"{clock}  1000   100   100 I tag     : {msg}"


def data(*lines: str) -> bytes:
    return "".join(f"{text}\n" for text in lines).encode()


def flat(chunks) -> list:
    return [segment for chunk in chunks for segment in chunk.segments]


def shape(chunks) -> list:
    """Sizes of entry lists, and the Gap objects themselves."""
    return [len(s) if type(s) is list else s for s in flat(chunks)]


def messages(chunks) -> list[str]:
    return [e.message for s in flat(chunks) if type(s) is list for e in s]


def kind(exit_status, stderr="", **overrides) -> EndKind:
    args = {
        "stop_requested": False,
        "stalled": False,
        "output_seen": True,
        "first_connection": False,
    }
    args.update(overrides)
    return classify_end(exit_status, stderr, **args)


# -- classify_end --------------------------------------------------------------------


class TestClassifyEnd:
    @pytest.mark.parametrize("stderr", [API24_EOF, API36_EOF, "UNEXPECTED EOF"])
    def test_exit_1_with_the_eof_message_is_released(self, stderr):
        assert kind(1, stderr) is EndKind.RELEASED

    def test_exit_1_without_the_message_is_failed(self):
        assert kind(1, "logcat: something else\n") is EndKind.FAILED
        assert kind(1) is EndKind.FAILED

    def test_the_eof_message_with_another_status_is_not_released(self):
        assert kind(2, API36_EOF) is EndKind.FAILED
        assert kind(0, API36_EOF) is EndKind.ENDED

    @pytest.mark.parametrize("status", [0, 128, 130, 137, 143, 255])
    def test_zero_and_signals_are_ended(self, status):
        assert kind(status) is EndKind.ENDED

    def test_no_exit_packet_is_lost(self):
        assert kind(None) is EndKind.LOST

    @pytest.mark.parametrize("status", [1, 2, 127])
    def test_nonzero_before_output_on_the_first_connection_is_failed_start(
        self, status
    ):
        assert (
            kind(status, output_seen=False, first_connection=True)
            is EndKind.FAILED_START
        )

    def test_nonzero_after_output_on_the_first_connection_is_failed(self):
        assert kind(2, first_connection=True) is EndKind.FAILED

    def test_nonzero_before_output_on_a_later_connection_is_failed(self):
        assert kind(2, output_seen=False) is EndKind.FAILED

    def test_zero_before_output_on_the_first_connection_is_ended(self):
        assert kind(0, output_seen=False, first_connection=True) is EndKind.ENDED

    def test_released_before_output_on_the_first_connection_is_released(self):
        assert (
            kind(1, API36_EOF, output_seen=False, first_connection=True)
            is EndKind.RELEASED
        )

    @pytest.mark.parametrize("status", [None, 0, 1, 143])
    def test_a_requested_stop_wins(self, status):
        assert (
            kind(status, API36_EOF, stop_requested=True, stalled=True)
            is EndKind.STOPPED
        )

    def test_a_close_by_the_reader_without_an_exit_status_is_stalled(self):
        assert kind(None, stalled=True) is EndKind.STALLED

    @pytest.mark.parametrize(
        ("status", "stderr", "expected"),
        [
            (2, "", EndKind.FAILED),
            (1, API24_EOF, EndKind.RELEASED),
            (0, "", EndKind.ENDED),
            (143, "", EndKind.ENDED),
        ],
    )
    def test_an_exit_status_that_came_before_the_reader_closed_wins(
        self, status, stderr, expected
    ):
        """logcat ended on its own in the read the reader gave up on."""
        assert kind(status, stderr, stalled=True) is expected
        early = {"output_seen": False, "first_connection": True}
        assert kind(status, stderr, stalled=True, **early) is kind(
            status, stderr, **early
        )

    def test_causes(self):
        assert cause_of(EndKind.RELEASED) == "released"
        assert cause_of(EndKind.STALLED) == "stalled"
        for end in (EndKind.LOST, EndKind.ENDED, EndKind.FAILED):
            assert cause_of(end) == "disconnected"
        for end in (EndKind.STOPPED, EndKind.FAILED_START):
            with pytest.raises(ValueError, match="not resumed"):
                cause_of(end)


# -- backoff and the policy ----------------------------------------------------------


class TestBackoff:
    def test_sequence(self):
        assert [backoff(n) for n in range(8)] == [1, 2, 4, 8, 16, 30, 30, 30]
        assert backoff(10_000) == BACKOFF_CAP

    def test_negative_is_rejected(self):
        with pytest.raises(ValueError, match="negative"):
            backoff(-1)


def ended(policy, end, at, *, length=5.0, output_for=None) -> Decision:
    """Report a connection that ended at ``at`` after ``length`` seconds."""
    since = None if output_for is None else at - output_for
    return policy.connection_ended(
        end, opened_at=at - length, ended_at=at, output_since=since
    )


class TestPolicy:
    def test_delays_double_up_to_the_cap(self):
        policy = ReconnectPolicy(10_000)
        delays = [ended(policy, EndKind.LOST, 100.0 * n).delay for n in range(8)]
        assert delays == [1, 2, 4, 8, 16, 30, 30, 30]

    def test_the_budget_counts_from_the_first_failure(self):
        policy = ReconnectPolicy(10)
        assert ended(policy, EndKind.LOST, 100.0) == Decision(retry=True, delay=1)
        assert ended(policy, EndKind.LOST, 101.0) == Decision(retry=True, delay=2)
        assert ended(policy, EndKind.LOST, 103.0) == Decision(retry=True, delay=4)
        # 8 s would overrun the budget: the last wait is cut to what is left.
        assert ended(policy, EndKind.LOST, 107.0) == Decision(retry=True, delay=3)
        assert ended(policy, EndKind.LOST, 110.0) == Decision(
            retry=False, error="device_lost"
        )

    def test_failed_attempts_use_the_same_budget(self):
        policy = ReconnectPolicy(5)
        assert ended(policy, EndKind.LOST, 0.0).delay == 1
        assert policy.attempt_failed(1.0) == Decision(retry=True, delay=2)
        assert policy.attempt_failed(3.0) == Decision(retry=True, delay=2)
        assert policy.attempt_failed(5.0) == Decision(retry=False, error="device_lost")

    def test_the_error_code_follows_the_last_failure(self):
        policy = ReconnectPolicy(1)
        assert ended(policy, EndKind.FAILED, 0.0).retry
        assert ended(policy, EndKind.FAILED, 2.0) == Decision(
            retry=False, error="logcat_failed"
        )
        policy = ReconnectPolicy(1)
        assert ended(policy, EndKind.ENDED, 0.0).retry  # the free retry
        assert ended(policy, EndKind.ENDED, 2.0) == Decision(
            retry=False, error="device_lost"
        )
        assert ReconnectPolicy(1).attempt_failed(0.0, error="logcat_failed").retry

    def test_a_stable_connection_resets_delay_and_budget(self):
        policy = ReconnectPolicy(10)
        for at, want in ((0.0, 1), (1.0, 2), (3.0, 4)):
            assert ended(policy, EndKind.LOST, at).delay == want
        # 10 s of output: stable. The next failure starts a new budget.
        assert ended(
            policy, EndKind.LOST, 500.0, length=60, output_for=STABLE_AFTER
        ) == (Decision(retry=True, delay=1))
        assert ended(policy, EndKind.LOST, 501.0).delay == 2
        assert ended(policy, EndKind.LOST, 509.0).delay == 1  # cut: budget ends at 510
        assert not ended(policy, EndKind.LOST, 511.0).retry

    def test_nine_seconds_of_output_is_not_stable(self):
        policy = ReconnectPolicy(1000)
        assert ended(policy, EndKind.LOST, 0.0).delay == 1
        assert ended(policy, EndKind.LOST, 100.0, output_for=9.99).delay == 2
        assert ended(policy, EndKind.LOST, 200.0, length=30).delay == 4

    def test_a_stable_connection_that_was_released_resets_too(self):
        policy = ReconnectPolicy(1000)
        ended(policy, EndKind.LOST, 0.0)
        ended(policy, EndKind.LOST, 10.0)
        assert ended(policy, EndKind.RELEASED, 99.0, output_for=20) == Decision(
            retry=True
        )
        assert ended(policy, EndKind.LOST, 100.0).delay == 1

    def test_a_logcat_that_ended_is_retried_at_once_only_once(self):
        policy = ReconnectPolicy(1000)
        assert ended(policy, EndKind.ENDED, 0.0) == Decision(retry=True, delay=0)
        assert ended(policy, EndKind.ENDED, 1.0).delay == 1
        assert ended(policy, EndKind.ENDED, 5.0).delay == 2
        # a stable connection gives the free retry back
        ended(policy, EndKind.ENDED, 900.0, output_for=STABLE_AFTER)
        assert ended(policy, EndKind.ENDED, 901.0).delay == 1

    def test_a_failed_start_ends_the_stream(self):
        policy = ReconnectPolicy(1000)
        assert ended(policy, EndKind.FAILED_START, 0.0) == Decision(
            retry=False, error="logcat_failed"
        )

    def test_a_stop_ends_without_an_error(self):
        policy = ReconnectPolicy(1000)
        assert ended(policy, EndKind.STOPPED, 0.0) == Decision(retry=False)

    @pytest.mark.parametrize("end", [EndKind.RELEASED, EndKind.STALLED])
    def test_released_and_stalled_resume_at_once_without_cost(self, end):
        policy = ReconnectPolicy(1000)
        for at in (10.0, 20.0, 30.0, 40.0):
            assert ended(policy, end, at, length=5) == Decision(retry=True)
        assert ended(policy, EndKind.LOST, 50.0).delay == 1  # budget untouched

    def test_three_quick_ends_in_a_row_become_failures(self):
        policy = ReconnectPolicy(1000)
        assert QUICK_LIMIT == 3
        assert ended(policy, EndKind.RELEASED, 10.0, length=0.2) == Decision(retry=True)
        assert ended(policy, EndKind.STALLED, 11.0, length=0.2) == Decision(retry=True)
        assert ended(policy, EndKind.RELEASED, 12.0, length=0.2) == Decision(
            retry=True, delay=1
        )
        assert ended(policy, EndKind.RELEASED, 13.0, length=0.2).delay == 2

    def test_quick_means_one_second_or_less(self):
        policy = ReconnectPolicy(0)
        assert QUICK_END == 1.0
        for at in (10.0, 20.0, 30.0, 40.0):
            assert ended(policy, EndKind.RELEASED, at, length=1.01).retry
        for at in (50.0, 60.0):
            assert ended(policy, EndKind.RELEASED, at, length=1.0).retry
        assert not ended(policy, EndKind.RELEASED, 70.0, length=1.0).retry

    def test_a_longer_connection_or_another_kind_breaks_the_run(self):
        policy = ReconnectPolicy(1000)
        ended(policy, EndKind.RELEASED, 1.0, length=0.1)
        ended(policy, EndKind.RELEASED, 2.0, length=0.1)
        ended(policy, EndKind.RELEASED, 3.0, length=2.0)  # long: count starts over
        assert ended(policy, EndKind.RELEASED, 4.0, length=0.1).delay == 0
        assert ended(policy, EndKind.RELEASED, 5.0, length=0.1).delay == 0
        ended(policy, EndKind.LOST, 6.0, length=0.1)  # another kind: count restarts
        assert ended(policy, EndKind.RELEASED, 7.0, length=0.1).delay == 0
        assert ended(policy, EndKind.RELEASED, 8.0, length=0.1).delay == 0
        assert ended(policy, EndKind.RELEASED, 9.0, length=0.1).delay == 2

    def test_a_stable_connection_ends_the_quick_run(self):
        policy = ReconnectPolicy(1000)
        ended(policy, EndKind.RELEASED, 1.0, length=0.1)
        ended(policy, EndKind.RELEASED, 2.0, length=0.1)
        # output for 10 s makes it stable, and its length is no longer quick
        ended(policy, EndKind.RELEASED, 30.0, length=20, output_for=15)
        assert ended(policy, EndKind.RELEASED, 31.0, length=0.1).delay == 0

    def test_quick_failures_use_up_the_budget(self):
        policy = ReconnectPolicy(2)
        decisions = [
            ended(policy, EndKind.STALLED, 0.1 * n, length=0.05) for n in range(3)
        ]
        assert decisions[2] == Decision(retry=True, delay=1)
        assert ended(policy, EndKind.STALLED, 3.0, length=0.05) == Decision(
            retry=False, error="logcat_failed"
        )

    def test_reconnect_zero_recovers_nothing_that_was_lost(self):
        for end, code in (
            (EndKind.LOST, "device_lost"),
            (EndKind.ENDED, "device_lost"),
            (EndKind.FAILED, "logcat_failed"),
        ):
            assert ended(ReconnectPolicy(0), end, 1.0) == Decision(
                retry=False, error=code
            )
        assert ReconnectPolicy(0).attempt_failed(1.0).retry is False

    def test_reconnect_zero_still_resumes_released_and_stalled(self):
        policy = ReconnectPolicy(0)
        for end in (EndKind.RELEASED, EndKind.STALLED, EndKind.RELEASED):
            assert ended(policy, end, 10.0, length=3) == Decision(retry=True)

    def test_reconnect_zero_fails_on_the_third_quick_end(self):
        policy = ReconnectPolicy(0)
        assert ended(policy, EndKind.RELEASED, 1.0, length=0.1).retry
        assert ended(policy, EndKind.STALLED, 2.0, length=0.1).retry
        assert ended(policy, EndKind.RELEASED, 3.0, length=0.1) == Decision(
            retry=False, error="logcat_failed"
        )

    @pytest.mark.parametrize("bad", [-1, math.nan])
    def test_a_bad_budget_is_rejected(self, bad):
        with pytest.raises(ValueError, match="reconnect"):
            ReconnectPolicy(bad)


# -- t_arg ---------------------------------------------------------------------------


class TestTArg:
    def test_microseconds_are_always_six_digits(self):
        assert (
            t_arg(datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)) == "1700000000.000000"
        )
        assert (
            t_arg(datetime(2023, 11, 14, 22, 13, 20, 5, tzinfo=UTC))
            == "1700000000.000005"
        )
        assert t_arg(datetime(2023, 11, 14, 22, 13, 20, 123456, tzinfo=UTC)) == (
            "1700000000.123456"
        )
        assert t_arg(datetime(2023, 11, 14, 22, 13, 20, 999999, tzinfo=UTC)) == (
            "1700000000.999999"
        )

    def test_the_value_always_has_a_dot(self):
        for second in range(60):
            assert "." in t_arg(datetime(2026, 1, 1, 0, 0, second, tzinfo=UTC))

    def test_the_zone_does_not_change_the_instant(self):
        zone = timezone(timedelta(hours=9))
        moment = datetime(2023, 11, 15, 7, 13, 20, 250000, tzinfo=zone)
        assert t_arg(moment) == "1700000000.250000"

    def test_the_epoch_and_before(self):
        assert t_arg(datetime(1970, 1, 1, tzinfo=UTC)) == "0.000000"
        assert t_arg(datetime(1970, 1, 1, 0, 0, 1, 1, tzinfo=UTC)) == "1.000001"
        assert (
            t_arg(datetime(1969, 12, 31, 23, 59, 59, 999999, tzinfo=UTC)) == "0.000000"
        )

    def test_a_naive_moment_is_rejected(self):
        with pytest.raises(ValueError, match="aware"):
            t_arg(datetime(2026, 1, 1))  # noqa: DTZ001


# -- the resume check against scripted histories -------------------------------------


def first_connection(*lines: str) -> Feeder:
    feeder = Feeder("s1")
    feeder.feed(data(*lines))
    return feeder


def reconnect(feeder: Feeder, cause="disconnected", **kwargs):
    plan = plan_resume(feeder, cause, NOW, **kwargs)
    feeder.begin_connection(plan.check)
    return plan


class TestPlan:
    def test_nothing_read_means_no_check(self):
        feeder = Feeder("s1")
        plan = plan_resume(feeder, "disconnected", NOW)
        assert (plan.start, plan.t_arg, plan.check) == (None, None, None)

    def test_only_untimed_lines_read_means_no_check(self):
        feeder = first_connection("--------- beginning of main", "no time here")
        assert plan_resume(feeder, "disconnected", NOW).check is None

    def test_start_is_the_cursor_minus_the_overlap(self):
        feeder = first_connection(line(0), line(5.25))
        plan = plan_resume(feeder, "released", NOW)
        assert plan.start == stamp(5.25) - OVERLAP
        assert plan.start is not None
        assert plan.t_arg == t_arg(plan.start)
        assert plan.t_arg.endswith(".250000")
        assert isinstance(plan.check, ResumeCheck)

    def test_the_check_is_not_finished_at_the_start(self):
        feeder = first_connection(line(0))
        check = plan_resume(feeder, "stalled", NOW).check
        assert check is not None
        assert not check.finished
        assert check.flags == ResumeFlags()
        with pytest.raises(RuntimeError, match="not finished"):
            check.gap()


class TestCheck:
    def test_a_full_replay_leaves_no_gap(self):
        feeder = first_connection(line(0), line(0.5), line(1.0), line(1.5))
        reconnect(feeder)
        out = feeder.feed(data(line(0.5), line(1.0), line(1.5)))
        assert out == []
        out = feeder.feed(data(line(2.0, "new")))
        assert shape(out) == [1]
        assert messages(out) == ["new"]
        assert feeder.duplicates == 3
        assert feeder.gaps == 0

    def test_a_partial_replay_is_ring_rotated(self):
        feeder = first_connection(line(0), line(0.5), line(1.0), line(1.5))
        reconnect(feeder, "released")
        out = feeder.feed(data(line(1.0), line(1.5), line(2.0, "new")))
        gap = flat(out)[0]
        assert gap == Gap("s1", "ring_rotated", "released", NOW, stamp(0.5))
        assert shape(out)[1:] == [1]
        assert feeder.gaps == 1

    def test_a_short_history_is_continuity_unknown(self, monkeypatch):
        monkeypatch.setattr(feed_module, "HISTORY_LINES", 3)
        feeder = Feeder("s1")
        for second in (0, 0.2, 0.4, 0.6):
            feeder.feed(data(line(second)))
        assert feeder.short_until is not None
        reconnect(feeder, "stalled")
        out = feeder.feed(data(line(0.2), line(0.4), line(0.6), line(1.0, "new")))
        assert shape(out) == [
            Gap("s1", "continuity_unknown", "stalled", NOW, stamp(-0.4)),
            1,
        ]

    def test_ring_rotated_wins_over_continuity_unknown(self, monkeypatch):
        monkeypatch.setattr(feed_module, "HISTORY_LINES", 3)
        feeder = Feeder("s1")
        for second in (0, 0.2, 0.4, 0.6):
            feeder.feed(data(line(second)))
        reconnect(feeder)
        out = feeder.feed(data(line(0.6), line(1.0, "new")))
        assert flat(out)[0].reason == "ring_rotated"

    def test_an_older_unread_line_is_continuity_unknown(self):
        feeder = first_connection(line(0), line(1.0))
        # T = 0; the replay is complete, then a never-read line from before T
        reconnect(feeder)
        out = feeder.feed(data(line(0), line(1.0), line(-0.5, "late")))
        gap, entries = flat(out)
        assert gap.reason == "continuity_unknown"
        assert [e.message for e in entries] == ["late"]

    def test_an_unread_line_inside_the_window_is_delivered_once_without_a_gap(self):
        # A is read at 1.0; B (86 ms earlier) reached logd after the disconnect.
        feeder = first_connection(line(0.2), line(1.0))
        reconnect(feeder)
        out = feeder.feed(data(line(0.914, "B"), line(0.2), line(1.0)))
        assert messages(out) == ["B"]
        out = feeder.feed(data(line(1.5, "new")))
        assert shape(out) == [1]
        assert feeder.gaps == 0
        assert feeder.duplicates == 2

    def test_a_replay_that_starts_before_t_is_matched_through_the_old_lines(self):
        feeder = first_connection(line(0), line(2.0))  # one read: T = 1.0
        reconnect(feeder)
        out = feeder.feed(data(line(0), line(2.0), line(3.0, "new")))
        assert shape(out) == [1]
        assert feeder.duplicates == 2
        assert feeder.gaps == 0

    def test_identical_lines_in_one_microsecond_match_by_occurrence(self):
        same = line(1.0, "same")
        feeder = first_connection(same, same, same)
        reconnect(feeder)
        out = feeder.feed(data(same, same, same))
        assert out == []
        out = feeder.feed(data(same))  # a fourth is new, and ends the check
        assert messages(out) == ["same"]
        assert feeder.duplicates == 3
        assert feeder.gaps == 0

    def test_a_partial_return_of_identical_lines_is_ring_rotated(self):
        same = line(1.0, "same")
        feeder = first_connection(same, same, same)
        reconnect(feeder)
        out = feeder.feed(data(same, same, line(2.0, "new")))
        assert flat(out)[0].reason == "ring_rotated"

    def test_untimed_lines_while_lines_are_expected_neither_end_nor_flag(self):
        feeder = first_connection(line(0), line(1.0))
        reconnect(feeder)
        out = feeder.feed(
            data("--------- beginning of main", "garbage", line(0), line(1.0))
        )
        assert messages(out) == ["garbage"]  # a divider is dropped by the feeder
        out = feeder.feed(data(line(2.0, "new")))
        assert shape(out) == [1]
        assert feeder.gaps == 0

    def test_a_newer_line_ends_the_check_while_expected_lines_are_missing(self):
        feeder = first_connection(line(0.5), line(1.0), line(1.5))
        reconnect(feeder)
        out = feeder.feed(data(line(1.0), line(1.6, "new"), line(1.5)))
        gap = flat(out)[0]
        assert gap.reason == "ring_rotated"
        # the check is over: the late replay of 1.5 is an ordinary line now
        assert messages(out) == ["new", "hello"]

    def test_the_first_new_line_after_the_expected_lines_ends_the_check(self):
        feeder = first_connection(line(0), line(5.0))
        # T = 4.0: only the line at 5.0 is expected; give it back, then the end
        check = reconnect(feeder).check
        assert check is not None
        feeder.feed(data(line(5.0)))
        assert not check.finished
        feeder.feed(data(line(5.0, "other")))
        assert check.finished

    def test_the_gap_sits_before_the_line_that_ended_the_check(self):
        feeder = first_connection(line(0.5), line(1.0))
        reconnect(feeder)
        out = feeder.feed(data(line(1.0), line(1.2, "a"), line(1.3, "b")))
        assert shape(out)[0].reason == "ring_rotated"
        assert shape(out)[1:] == [2]

    def test_an_interrupted_check_keeps_its_flags_and_restarts_from_the_same_t(self):
        feeder = first_connection(line(0), line(1.0))
        plan = reconnect(feeder)
        # the first replay brings an old unread line, then the connection ends
        out = feeder.feed(data(line(-0.5, "late"), line(0)))
        assert messages(out) == ["late"]
        assert plan.check is not None
        assert plan.check.flags == ResumeFlags(short=False, older_unread=True)
        assert not plan.check.finished

        again = reconnect(feeder, carried=plan.check.flags)
        assert again.start == plan.start
        out = feeder.feed(
            data(line(-0.5, "late"), line(0), line(1.0), line(2.0, "new"))
        )
        gap = flat(out)[0]
        assert gap.reason == "continuity_unknown"
        assert gap.start_at == plan.start
        assert messages(out) == ["new"]  # the late line came back as a replay

    def test_flags_are_not_carried_unless_handed_over(self):
        feeder = first_connection(line(0), line(1.0))
        reconnect(feeder)
        feeder.feed(data(line(-0.5, "late")))
        reconnect(feeder)  # the flags are dropped
        out = feeder.feed(
            data(line(-0.5, "late"), line(0), line(1.0), line(2.0, "new"))
        )
        assert shape(out) == [1]

    def test_the_short_flag_is_carried_too(self):
        feeder = first_connection(line(0), line(1.0))
        assert feeder.short_until is None  # only the carried flag can set it
        plan = reconnect(feeder, carried=ResumeFlags(short=True))
        assert plan.check is not None
        assert plan.check.flags == ResumeFlags(short=True, older_unread=False)
        out = feeder.feed(data(line(0), line(1.0), line(2.0, "new")))
        assert flat(out)[0].reason == "continuity_unknown"

    def test_a_history_that_fell_short_long_ago_is_no_longer_a_problem(
        self, monkeypatch
    ):
        monkeypatch.setattr(feed_module, "HISTORY_LINES", 3)
        feeder = Feeder("s1")
        for second in (0, 0.2, 0.4, 0.6):
            feeder.feed(data(line(second)))
        monkeypatch.undo()
        assert feeder.short_until is not None
        feeder.feed(data(line(10.0)))  # T is now 9.0, long after the cut
        reconnect(feeder)
        out = feeder.feed(data(line(10.0), line(11.0, "new")))
        assert shape(out) == [1]
        assert feeder.gaps == 0

    def test_a_history_cut_exactly_at_t_is_short(self, monkeypatch):
        monkeypatch.setattr(feed_module, "HISTORY_LINES", 3)
        feeder = Feeder("s1")
        for second in (0, 0.2, 0.4, 0.6):
            feeder.feed(data(line(second)))
        monkeypatch.undo()
        assert feeder.short_until == stamp(0)
        feeder.feed(data(line(1.0)))  # T = 0.0, the time of the cut
        reconnect(feeder)
        out = feeder.feed(data(line(0.2), line(0.4), line(0.6), line(1.0)))
        out += feeder.feed(data(line(2.0, "new")))
        assert flat(out)[0].reason == "continuity_unknown"

    def test_an_unread_line_exactly_at_t_is_not_older(self):
        feeder = first_connection(line(0), line(1.0))  # T = 0.0
        reconnect(feeder)
        out = feeder.feed(data(line(0, "x"), line(0), line(1.0)))
        out += feeder.feed(data(line(2.0, "new")))
        assert messages(out) == ["x", "new"]
        assert feeder.gaps == 0

    def test_a_new_line_at_the_cursor_time_does_not_end_the_check(self):
        feeder = first_connection(line(0.5), line(1.0))
        reconnect(feeder)
        out = feeder.feed(data(line(1.0, "twin"), line(0.5), line(1.0)))
        assert messages(out) == ["twin"]
        out = feeder.feed(data(line(2.0, "new")))
        assert shape(out) == [1]
        assert feeder.gaps == 0

    def test_old_lines_are_matched_by_occurrence_too(self):
        same = line(0, "same")
        feeder = first_connection(same, same, line(5.0))  # T = 4.0
        reconnect(feeder)
        # two replays of `same` are known; a third one was never read
        out = feeder.feed(data(same, same, same, line(5.0), line(6.0, "new")))
        gaps = [x for x in flat(out) if type(x) is Gap]
        assert [g.reason for g in gaps] == ["continuity_unknown"]
        assert messages(out) == ["same", "new"]

    def test_a_line_delivered_twice_can_make_the_next_reconnect_ring_rotated(self):
        feeder = first_connection(line(0.5), line(1.0))
        reconnect(feeder)
        out = feeder.end_check()  # idle: nothing came back
        assert flat(out)[0].reason == "ring_rotated"
        # the replay turns up late and is delivered a second time
        assert len(messages(feeder.feed(data(line(0.5), line(1.0))))) == 2
        assert feeder.history_lines == 4
        reconnect(feeder)
        out = feeder.feed(data(line(0.5), line(1.0), line(1.2, "new")))
        assert flat(out)[0].reason == "ring_rotated"  # documented: reports too much
        assert messages(out) == ["new"]

    def test_data_without_a_whole_line_keeps_the_idle_count_down(self):
        feeder = first_connection(line(0), line(1.0))
        check = reconnect(feeder).check
        assert check is not None
        assert not check.idle(0.6)
        part = line(0).encode()[:20]
        assert feeder.feed(part) == []  # no line is complete: admit is not called
        check.received()
        assert not check.idle(0.6)
        assert check.idle(0.6)

    def test_an_unparsed_line_after_the_expected_lines_ends_the_check(self):
        feeder = first_connection(line(0.5), line(1.0))
        plan = reconnect(feeder, carried=ResumeFlags(short=True))
        assert plan.check is not None
        out = feeder.feed(data(line(0.5), line(1.0), "garbage one", "garbage two"))
        assert plan.check.finished
        assert [type(s) for s in flat(out)] == [Gap, list]  # the gap comes first
        assert messages(out) == ["garbage one", "garbage two"]

    def test_a_divider_after_the_expected_lines_ends_the_check_too(self):
        feeder = first_connection(line(0.5), line(1.0))
        plan = reconnect(feeder, carried=ResumeFlags(short=True))
        assert plan.check is not None
        feeder.feed(data(line(0.5), line(1.0), "--------- beginning of main"))
        assert plan.check.finished

    def test_untimed_lines_before_the_expected_lines_are_back_do_not_end_it(self):
        feeder = first_connection(line(0.5), line(1.0))
        plan = reconnect(feeder)
        assert plan.check is not None
        feeder.feed(data("garbage", line(0.5)))
        assert not plan.check.finished

    def test_idle_waits_add_up_and_data_resets_them(self):
        feeder = first_connection(line(0), line(1.0))
        check = reconnect(feeder).check
        assert check is not None
        assert RESUME_IDLE == 1.0
        assert not check.idle(0.5)
        feeder.feed(data(line(0)))
        assert not check.idle(0.5)  # the line reset the count
        assert check.idle(0.5)

    def test_an_idle_end_reports_the_missing_lines(self):
        feeder = first_connection(line(0.5), line(1.0))
        reconnect(feeder, "stalled")
        feeder.feed(data(line(1.0)))
        chunks = feeder.end_check()
        assert chunks[0].charge == 0
        assert chunks[0].segments == [
            Gap("s1", "ring_rotated", "stalled", NOW, stamp(0.0))
        ]
        assert feeder.gaps == 1
        assert feeder.end_check() == []

    def test_an_idle_end_after_a_full_replay_is_silent(self):
        feeder = first_connection(line(0.5), line(1.0))
        reconnect(feeder)
        feeder.feed(data(line(0.5), line(1.0)))
        assert feeder.end_check() == []
        assert feeder.gaps == 0
        # the next lines are not looked at by the check any more
        assert messages(feeder.feed(data(line(0.5, "again")))) == ["again"]

    def test_the_hook_protocol_is_accepted_by_the_feeder(self):
        feeder = first_connection(line(0))
        plan = plan_resume(feeder, "disconnected", NOW)
        feeder.begin_connection(plan.check)  # not finished: no ValueError
        assert feeder.reconnects == 1


# -- end to end ----------------------------------------------------------------------


def test_a_disconnect_and_a_replayed_connection_through_the_feeder():
    feeder = Feeder("s1")
    policy = ReconnectPolicy(60)
    out = feeder.feed(data(line(0), line(0.8), line(1.5)))
    assert messages(out) == ["hello"] * 3
    # a partial line is in flight when the connection is lost; it is dropped
    assert feeder.feed(line(2.0, "cut").encode()[:30]) == []

    end = classify_end(
        None,
        "",
        stop_requested=False,
        stalled=False,
        output_seen=True,
        first_connection=True,
    )
    assert end is EndKind.LOST
    decision = policy.connection_ended(
        end, opened_at=0.0, ended_at=3.0, output_since=0.1
    )
    assert decision == Decision(retry=True, delay=1)

    plan = plan_resume(feeder, cause_of(end), NOW)
    assert plan.t_arg is not None
    assert plan.t_arg == t_arg(stamp(0.5))
    feeder.begin_connection(plan.check)

    # the replay arrives in pieces cut inside a line; the line at 0.0 is not
    # replayed at all (older than T), the one at 0.8 is, 1.5 comes back, and
    # lines the first connection never saw follow
    replay = data(line(0.8), line(1.5), line(2.0, "n1"), line(2.5, "n2"))
    pieces = [replay[:40], replay[40:200], replay[200:]]
    produced = [chunk for piece in pieces for chunk in feeder.feed(piece)]
    assert messages(produced) == ["n1", "n2"]
    assert [type(s) for s in flat(produced)] == [list]
    assert feeder.duplicates == 2
    assert feeder.gaps == 0
    assert feeder.reconnects == 1
    assert feeder.cursor == stamp(2.5)


def test_a_disconnect_that_loses_lines_reports_them_in_place():
    feeder = Feeder("s1")
    feeder.feed(data(line(0.2), line(1.0), line(1.2)))
    plan = plan_resume(feeder, "released", NOW)
    feeder.begin_connection(plan.check)
    chunks = feeder.feed(data(line(1.2), line(2.0, "n1"), line(2.1, "n2")))
    segments = flat(chunks)
    assert segments[0] == Gap("s1", "ring_rotated", "released", NOW, stamp(0.2))
    assert [len(s) for s in segments[1:]] == [2]
    assert feeder.lost == 0


# --- the error a stream ends with ---------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "code"),
    [
        (EndKind.STOPPED, None),
        (EndKind.LOST, "device_lost"),
        (EndKind.ENDED, "device_lost"),
        (EndKind.FAILED_START, "logcat_failed"),
        (EndKind.FAILED, "logcat_failed"),
        (EndKind.RELEASED, "logcat_failed"),
        (EndKind.STALLED, "logcat_failed"),
    ],
)
def test_each_end_kind_maps_to_an_error_code(kind, code):
    error = end_error(kind, "a", 7, ["tail"])
    if code is None:
        assert error is None
        return
    assert error is not None
    assert error.code == code
    assert error.details["serial"] == "a"
    assert error.details["exit_status"] == 7
    assert error.details.get("stderr") == (
        ["tail"] if code == "logcat_failed" else None
    )


@pytest.mark.parametrize("code", ["device_lost", "logcat_failed"])
def test_a_decision_code_builds_the_same_error_as_its_kind(code):
    kind = EndKind.LOST if code == "device_lost" else EndKind.FAILED
    from_kind = end_error(kind, "a", 3, ["x"])
    from_code = end_error(code, "a", 3, ["x"])
    assert from_kind is not None
    assert from_code is not None
    assert (from_code.code, from_code.message, from_code.details) == (
        from_kind.code,
        from_kind.message,
        from_kind.details,
    )


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (LogprobeError("device_not_found", "gone"), "device_lost"),
        (LogprobeError("device_offline", "off"), "device_lost"),
        (LogprobeError("device_unauthorized", "no"), "device_lost"),
        (LogprobeError("adb_server_unavailable", "down"), "adb_server_unavailable"),
        (LogprobeError("adb_error", "FAIL something"), "adb_error"),
        (TimeoutError("slow"), "adb_error"),
        (ConnectionResetError("reset"), "adb_error"),
    ],
)
def test_a_failed_attempt_stands_for_the_code_of_its_exception(error, code):
    assert attempt_error_code(error) == code


def test_the_last_attempt_becomes_the_cause_of_device_lost():
    attempt = LogprobeError("device_not_found", "device 'a' not found", {"serial": "a"})
    error = end_error("device_lost", "a", None, [], attempt=attempt)
    assert error is not None
    assert error.code == "device_lost"
    assert error.__cause__ is attempt
    assert error.details["serial"] == "a"


@pytest.mark.parametrize("code", ["adb_server_unavailable", "adb_error"])
def test_an_attempt_that_names_its_own_code_is_returned_as_it_is(code):
    attempt = LogprobeError(code, "the adb server said so")
    error = end_error(code, "a", None, [], attempt=attempt)
    assert error is attempt
    assert error.details["serial"] == "a"


def test_a_timeout_attempt_ends_as_adb_error_with_the_timeout_as_cause():
    attempt = TimeoutError("no answer")
    error = end_error("adb_error", "a", None, [], attempt=attempt)
    assert error is not None
    assert error.code == "adb_error"
    assert error.__cause__ is attempt


# --- older logd versions --------------------------------------------------------------


@pytest.mark.parametrize(
    ("sdk", "skips"),
    [
        (None, True),
        (23, True),
        (24, True),
        (25, True),
        (26, False),
        (27, False),
        (28, False),
        (29, False),
        (30, True),
        (31, False),
        (32, False),
        (33, False),
        (34, False),
        (35, False),
        (36, False),
        (37, False),
        (40, False),
    ],
)
def test_old_logd_rule_matches_the_measured_levels(sdk, skips):
    """24 and 30 were seen to skip lines and 26-29, 31, 32, 36 to cut a reader off;
    an unreadable level is treated as one that skips, and only those get a limit.
    """
    assert skips_silently(sdk) is skips
    assert stall_limit(sdk) == (STALL_AFTER if skips else None)


@pytest.mark.parametrize(
    ("stdout", "sdk"),
    [
        (b"24\n", 24),
        (b"30\r\n", 30),
        (b" 36 \n", 36),
        (b"", None),
        (b"\n", None),
        (b"abc\n", None),
        (b"24 25\n", None),
        (b"-1\n", None),
        (b"+24\n", None),
        (b"2.4\n", None),
        ("\uff12\uff14\n".encode(), None),  # full-width digits
        ("\u0662\u0664".encode(), None),  # Arabic-Indic digits
        (b"1234\n", 1234),
        (b"12345\n", None),  # more digits than an API level has
        (b"1" * 5000 + b"\n", None),  # more than int() converts
    ],
)
def test_api_level_text_is_parsed_or_unreadable(stdout, sdk):
    assert parse_sdk(stdout) == sdk


def test_the_stall_limit_is_read_when_asked(monkeypatch):
    """Tests and the reader both see a changed limit: it is looked up at call time."""
    from logprobe import _resume

    monkeypatch.setattr(_resume, "STALL_AFTER", 0.25)
    assert stall_limit(24) == 0.25


# --- times with and without a zone -------------------------------------------


def unzoned(seconds: float, msg: str = "hello") -> str:
    """A line like `line`, but without the zone (a producer that breaks -v zone)."""
    return line(seconds, msg).replace(" +0000", "", 1)


def test_a_line_without_a_zone_among_zoned_lines_does_not_break_the_plan() -> None:
    feeder = Feeder("s1")
    feeder.feed(data(line(10, "A"), unzoned(10.5, "B"), line(11, "C")))
    plan = plan_resume(feeder, "disconnected", NOW)
    assert plan.check is not None
    feeder.begin_connection(plan.check)
    # The zoned lines are replays; the line without a zone counts as a line
    # without a time, so it is never matched and is delivered again.
    out = feeder.feed(data(line(10, "A"), unzoned(10.5, "B"), line(11, "C")))
    assert messages(out) == ["B"]
    assert feeder.duplicates == 2
    assert feeder.end_check() == []  # no false gap for the line without a zone


def test_the_check_admits_a_line_of_the_other_kind_as_one_without_a_time() -> None:
    feeder = Feeder("s1")
    feeder.feed(data(line(10, "A")))
    plan = plan_resume(feeder, "disconnected", NOW)
    assert plan.check is not None
    feeder.begin_connection(plan.check)
    # Without a zone, and "older" than the start by its clock: no comparison
    # with the zoned cursor is made, so no TypeError and no older-unread flag.
    out = feeder.feed(data(unzoned(1, "X"), line(10, "A"), line(12, "D")))
    assert messages(out) == ["X", "D"]
    assert plan.check.flags.older_unread is False


def test_a_first_line_without_a_zone_does_not_stop_the_resume() -> None:
    feeder = Feeder("s1")
    feeder.feed(data(unzoned(9, "N")))
    assert feeder.cursor is None  # only a time with a zone moves the cursor
    feeder.feed(data(line(10, "A"), line(11, "B")))
    assert feeder.cursor == stamp(11)
    plan = plan_resume(feeder, "disconnected", NOW)
    assert plan.check is not None
    assert plan.t_arg is not None
    feeder.begin_connection(plan.check)
    out = feeder.feed(data(line(10, "A"), line(11, "B"), line(12, "C")))
    assert messages(out) == ["C"]


def test_a_line_without_a_zone_after_every_replay_ends_the_check() -> None:
    feeder = Feeder("s1")
    feeder.feed(data(line(10, "A")))
    plan = plan_resume(feeder, "disconnected", NOW)
    assert plan.check is not None
    feeder.begin_connection(plan.check)
    out = feeder.feed(data(line(10, "A"), unzoned(10, "X")))
    assert messages(out) == ["X"]
    assert plan.check.finished
    assert plan.check.gap() is None
