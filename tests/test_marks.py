"""The pure marker decisions: what a reader does about its markers and its flush."""

from __future__ import annotations

from typing import Any

import pytest

from logprobe._feed import MarkerArrived
from logprobe._marks import Act, FlushRequest, Marks, Phase, parse_clock, since_t_arg

START = "start-" + "0" * 32
FLUSH = "flush-" + "1" * 32


def test_the_since_time_is_one_second_before_the_device_clock() -> None:
    assert since_t_arg(1_700_000_000) == "1699999999.000000"
    assert since_t_arg(0) == "0.000000"


@pytest.mark.parametrize(
    ("output", "clock"),
    [(b"1700000000\n", 1_700_000_000), (b"", None), (b"soon\n", None), (b"-5\n", None)],
)
def test_the_device_clock_is_read_from_the_output_of_date(
    output: bytes, clock: int | None
) -> None:
    assert parse_clock(output) == clock


def test_only_time_waited_for_room_in_the_queue_is_given_back_to_a_flush() -> None:
    # Asked at 10.0 s, when "a" had already waited 2.0 s in total.
    request = FlushRequest(1.0, 10.0, {"a": 2.0, "b": 9.0})
    # 4 s later "a" waited 3.5 s more and "b" 1 s more: only "a"'s wait is its own.
    assert request.left("a", 14.0, 5.5) == pytest.approx(1.0 - (4.0 - 3.5))
    assert request.left("b", 14.0, 10.0) == pytest.approx(1.0 - (4.0 - 1.0))
    assert request.left("c", 14.0, 0.0) == pytest.approx(1.0 - 4.0)


def entries(*names: str) -> Any:  # noqa: ANN401  (stand-ins for log entries)
    return list(names)


def pending(budget: float = 1.0, serial: str = "a") -> Marks:
    marks = Marks(serial)
    marks.adopt(FlushRequest(budget, 0.0, {}))
    return marks


def test_a_flush_without_budget_times_out_and_nothing_is_written() -> None:
    marks = pending(1.0)
    assert marks.step(0.5, 0.0).act is Act.WRITE
    step = marks.step(1.5, 0.0)
    assert step.act is Act.END
    assert marks.state == "timed_out"
    assert marks.step(1.6, 0.0).act is Act.END  # and it stays over


def test_a_wait_for_room_keeps_the_budget_from_running_out() -> None:
    marks = pending(1.0)
    step = marks.step(5.0, 4.5)  # 5 s passed, 4.5 s of them waiting for room
    assert step.act is Act.WRITE
    assert step.limit == pytest.approx(0.5)


def test_the_flush_marker_is_written_once_and_again_only_after_a_resume() -> None:
    marks = pending(60.0)
    first = marks.step(0.0, 0.0)
    assert first.act is Act.WRITE
    assert first.token.startswith("flush-")
    assert first.limit == 5.0  # the command limit is shorter than the budget
    marks.command_done(None)  # the device was lost: no exit status
    assert marks.step(0.1, 0.0).act is Act.READ  # nothing is written meanwhile
    marks.resumed()
    again = marks.step(0.2, 0.0)
    assert (again.act, again.token) == (Act.WRITE, first.token)
    marks.command_done(0)
    assert marks.step(0.3, 0.0).act is Act.READ
    marks.resumed()  # a written marker is not written again
    assert marks.step(0.4, 0.0).act is Act.READ


def test_a_marker_command_that_exits_with_an_error_fails_the_flush() -> None:
    marks = pending()
    assert marks.step(0.0, 0.0).act is Act.WRITE
    marks.command_done(1)
    assert marks.step(0.1, 0.0).act is Act.END
    assert marks.state == "failed"


def test_the_flush_marker_waits_for_the_start_marker_which_may_be_late() -> None:
    marks = pending(60.0)
    marks.skip_until(START)
    marks.arm(10.0)
    step = marks.step(4.0, 0.0)
    assert step.act is Act.READ  # the one awaited marker is the start marker
    assert step.limit == pytest.approx(6.0)
    assert marks.step(10.0, 0.0).act is Act.LATE


def test_a_flush_that_is_not_requested_has_no_limit() -> None:
    marks = Marks("a")
    assert marks.step(1.0, 0.0) == (Act.READ, None, "")
    marks.end_unfinished(requested=False)
    assert marks.state == "not_requested"


def test_a_requested_flush_without_a_result_is_cancelled_when_the_reader_ends() -> None:
    marks = pending()
    marks.end_unfinished(requested=True)
    assert marks.state == "cancelled"
    done = pending()
    done.route([MarkerArrived(FLUSH)])
    done.end_unfinished(requested=True)
    assert done.state == "done"  # a result is not overwritten


def test_everything_before_the_start_marker_is_dropped_and_what_follows_is_kept() -> (
    None
):
    marks = Marks("a")
    marks.skip_until(START)
    assert marks.route([entries("old", "older")]) == []
    kept = marks.route([entries("before"), MarkerArrived(START), entries("after")])
    assert kept == [entries("after")]
    assert marks.phase is Phase.DELIVERING
    assert marks.dropped == 3
    rest = [entries("next")]
    assert marks.route(rest) is rest  # the common case costs nothing


def test_nothing_after_the_flush_marker_is_kept_and_the_flush_is_done() -> None:
    marks = pending()
    kept = marks.route([entries("a"), MarkerArrived(FLUSH), entries("b", "c")])
    assert kept == [entries("a")]
    assert marks.state == "done"
    assert marks.phase is Phase.CLOSED
    assert marks.route([entries("d")]) == []
    assert marks.dropped == 3
    assert marks.step(0.0, 0.0).act is Act.END
