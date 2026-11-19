"""Tests for the I/O-free feeder behind the live stream readers."""

from __future__ import annotations

import json
import logging
import statistics
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from logprobe import Anr, Crash, Gap, Level, Package, Tag
from logprobe._feed import (
    CHATTY_TAG,
    CHUNK_ENTRIES,
    HISTORY_BYTES,
    HISTORY_LINES,
    MARKER_TAG,
    OVERLAP,
    Feeder,
    MarkerArrived,
    chatty_loss,
    new_marker,
)
from tests.device_facts import level_dir, load

if TYPE_CHECKING:
    from logprobe._framing import FramedLine

BASE = datetime(2026, 11, 4, 4, 21, 0, tzinfo=UTC)


def stamp(seconds: float) -> datetime:
    """The moment ``seconds`` after the base time used by `line`."""
    return BASE + timedelta(seconds=seconds)


def line(
    seconds: float = 0.0,
    msg: str = "hello",
    tag: str = "tag",
    *,
    level: str = "I",
    uid: str = "10146",
    pid: int = 100,
) -> str:
    """One line in the live wire format, ``seconds`` after the base time."""
    moment = stamp(seconds)
    clock = f"{moment:%Y-%m-%d %H:%M:%S}.{moment.microsecond:06d} +0000"
    return f"{clock} {uid:>5} {pid:5d} {pid:5d} {level} {tag:<8}: {msg}"


def data(*lines: str) -> bytes:
    """The bytes of ``lines``, each ended by LF."""
    return "".join(f"{text}\n" for text in lines).encode()


def flat(chunks) -> list:
    """Every segment of ``chunks``, in order."""
    return [segment for chunk in chunks for segment in chunk.segments]


def entries_of(chunks) -> list:
    """Every entry of ``chunks``, in order."""
    return [e for s in flat(chunks) if type(s) is list for e in s]


def shape(chunks) -> list:
    """The segments as sizes of entry lists and the names of the others."""
    return [len(s) if type(s) is list else type(s).__name__ for s in flat(chunks)]


class FakeCheck:
    """A resume check that drops the lines whose data is in ``replays``.

    It finishes at the first line that is not a replay (or, with ``never``,
    only when told to end).
    """

    def __init__(self, replays=(), gap: Gap | None = None, *, never=False) -> None:
        self.replays: list[bytes] = list(replays)
        self._gap = gap
        self.never = never
        self.finished = False
        self.seen: list[tuple[bytes, datetime | None]] = []

    def admit(self, framed: FramedLine, logged_at) -> bool:
        assert not self.finished, "admit called after the check finished"
        self.seen.append((framed.data, logged_at))
        if framed.data in self.replays:
            self.replays.remove(framed.data)
            return False
        if not self.never:
            self.finished = True
        return True

    def gap(self):
        assert self.finished
        return self._gap

    def end(self) -> None:
        self.finished = True


def make_gap(lost: int | None = None) -> Gap:
    return Gap("s1", "continuity_unknown", "disconnected", stamp(0), None, lost)


class TestChunks:
    def test_one_read_is_one_list(self):
        feeder = Feeder("s1")
        out = feeder.feed(data(line(0), line(1), line(2)))
        assert shape(out) == [3]
        assert [e.serial for e in entries_of(out)] == ["s1"] * 3

    def test_a_read_without_a_complete_line_returns_nothing(self):
        feeder = Feeder("s1")
        assert feeder.feed(line(0).encode()) == []
        assert shape(feeder.feed(b"\n")) == [1]

    def test_long_runs_are_split_at_the_chunk_size(self):
        feeder = Feeder("s1")
        total = 2 * CHUNK_ENTRIES + 904
        out = feeder.feed(data(*(line(i / 1e4) for i in range(total))))
        assert shape(out) == [CHUNK_ENTRIES, CHUNK_ENTRIES, 904]
        assert len(entries_of(out)) == total
        times = [e.logged_at for e in entries_of(out)]
        assert times == sorted(times)

    def test_exactly_the_chunk_size_is_one_list(self):
        feeder = Feeder("s1")
        out = feeder.feed(data(*(line(i / 1e4) for i in range(CHUNK_ENTRIES))))
        assert shape(out) == [CHUNK_ENTRIES]

    def test_the_cut_of_the_input_does_not_change_the_result(self):
        text = data(
            line(0, "a"),
            "--------- beginning of main",
            "garbage",
            line(1, "b"),
            line(2, "é" * 10),
        )
        whole = entries_of(Feeder("s1").feed(text))
        for size in (1, 2, 7, 50):
            feeder = Feeder("s1")
            pieces: list = []
            for start in range(0, len(text), size):
                pieces.extend(feeder.feed(text[start : start + size]))
            got = entries_of(pieces)
            assert [(e.raw, e.message, e.parsed) for e in got] == [
                (e.raw, e.message, e.parsed) for e in whole
            ]

    def test_crlf_is_one_terminator(self):
        feeder = Feeder("s1")
        out = feeder.feed((line(0) + "\r\n").encode())
        assert entries_of(out)[0].raw == line(0)

    def test_finish_returns_the_last_unterminated_line(self):
        feeder = Feeder("s1")
        assert feeder.feed(line(0).encode()) == []
        out = feeder.finish()
        assert [e.raw for e in entries_of(out)] == [line(0)]
        assert feeder.lines == 1


class TestChunkCharges:
    def test_a_big_read_is_several_chunks_that_charge_its_bytes(self):
        feeder = Feeder("s1")
        out = feeder.feed(b"x\n" * 32_768)
        assert len(out) == 16
        assert all(len(entries_of([c])) == CHUNK_ENTRIES for c in out)
        assert sum(c.charge for c in out) == 2 * 32_768
        assert all(c.charge > 0 for c in out)

    def test_an_ordinary_read_is_one_chunk_charged_len_out(self):
        feeder = Feeder("s1")
        raw = data(line(0), line(1)) + line(2).encode()[:30]
        (chunk,) = feeder.feed(raw)
        assert chunk.charge == len(raw)

    def test_the_charges_add_up_for_an_uneven_split(self):
        feeder = Feeder("s1")
        raw = b"x\n" * 5000 + b"yy\n" * 3 + b"z"
        out = feeder.feed(raw)
        assert len(out) == 3
        assert sum(c.charge for c in out) == len(raw)

    def test_markers_and_gaps_keep_their_places_across_chunks(self):
        feeder = Feeder("s1")
        token = new_marker("flush")
        feeder.expect(token)
        feeder.begin_connection(FakeCheck(gap=make_gap()))
        text = data(
            *(line(i / 1e4) for i in range(CHUNK_ENTRIES + 10)),
            line(1, token, MARKER_TAG),
            *(line(2 + i / 1e4) for i in range(CHUNK_ENTRIES)),
        )
        out = feeder.feed(text)
        assert shape(out) == [
            "Gap",
            CHUNK_ENTRIES,
            10,
            "MarkerArrived",
            CHUNK_ENTRIES - 10,
            10,
        ]
        assert [len(entries_of([c])) for c in out] == [CHUNK_ENTRIES] * 2 + [10]
        assert sum(c.charge for c in out) == len(text)


class TestLinesAndEntries:
    def test_divider_is_skipped_and_counted_as_a_line(self):
        feeder = Feeder("s1")
        out = feeder.feed(data("--------- beginning of main", line(0)))
        assert len(entries_of(out)) == 1
        assert (feeder.lines, feeder.entries, feeder.unparsed) == (2, 1, 0)

    def test_unparsed_line_becomes_an_entry_with_the_serial(self):
        feeder = Feeder("s1")
        (entry,) = entries_of(feeder.feed(data("not a log line")))
        assert (entry.parsed, entry.message, entry.serial) == (
            False,
            "not a log line",
            "s1",
        )
        assert (feeder.lines, feeder.entries, feeder.unparsed) == (1, 1, 1)

    def test_a_long_line_is_cut_and_flagged(self):
        feeder = Feeder("s1", max_line_bytes=4096)
        out = feeder.feed(data(line(0, "x" * 5000), line(1)))
        first, second = entries_of(out)
        assert first.truncated
        assert len(first.raw.encode()) == 4096
        assert not second.truncated
        assert feeder.truncated == 1

    def test_undecodable_bytes_are_replaced(self):
        feeder = Feeder("s1")
        raw = line(0, "a\x00b").encode().replace(b"\x00", b"\xff")
        (entry,) = entries_of(feeder.feed(raw + b"\n"))
        assert entry.message == "a�b"


class TestCondition:
    def test_a_plain_condition_is_applied(self):
        feeder = Feeder("s1", condition=Level >= "W")
        out = feeder.feed(
            data(line(0, level="I"), line(1, level="W"), line(2, level="E"))
        )
        assert [e.level for e in entries_of(out)] == ["W", "E"]
        assert (feeder.lines, feeder.entries) == (3, 2)
        assert not feeder.deferred

    def test_a_condition_with_packages_is_deferred_and_entries_still_count(self):
        condition = Package("com.example.app") & (Level >= "W")
        feeder = Feeder("s1", condition=condition)
        out = feeder.feed(data(line(0, level="I"), line(1, level="W")))
        assert feeder.deferred
        assert [e.level for e in entries_of(out)] == ["I", "W"]
        assert (feeder.lines, feeder.entries) == (2, 2)

    def test_crash_and_anr_with_a_package_are_applied_not_deferred(self):
        crash = Crash(package="com.example.app")
        anr = Anr(package="com.example.app")
        for condition in (crash, anr, crash & (Level >= "W")):
            feeder = Feeder("s1", condition=condition)
            out = feeder.feed(data(line(0, level="I"), line(1, level="W")))
            assert not feeder.deferred
            assert entries_of(out) == []
            assert (feeder.lines, feeder.entries) == (2, 0)

    def test_a_condition_without_packages_in_a_junction_is_applied(self):
        feeder = Feeder("s1", condition=Tag("keep") | Tag("also"))
        out = feeder.feed(data(line(0, tag="keep"), line(1, tag="drop")))
        assert [e.tag for e in entries_of(out)] == ["keep"]
        assert not feeder.deferred

    def test_a_condition_applies_to_unparsed_entries_too(self):
        feeder = Feeder("s1", condition=Level >= "E")
        assert entries_of(feeder.feed(data("junk"))) == []
        assert (feeder.lines, feeder.unparsed, feeder.entries) == (1, 1, 0)


class TestCursor:
    def test_starts_empty_and_follows_the_newest_line(self):
        feeder = Feeder("s1")
        assert feeder.cursor is None
        feeder.feed(data(line(5), line(3)))
        assert feeder.cursor == stamp(5)
        feeder.feed(data(line(4)))
        assert feeder.cursor == stamp(5)

    def test_filtered_out_lines_move_the_cursor(self):
        feeder = Feeder("s1", condition=Level >= "E")
        out = feeder.feed(data(line(7, level="I")))
        assert entries_of(out) == []
        assert feeder.cursor == stamp(7)

    def test_marker_lines_move_the_cursor(self):
        feeder = Feeder("s1")
        feeder.feed(data(line(9, new_marker("start"), MARKER_TAG)))
        assert feeder.cursor == stamp(9)

    def test_lines_without_a_time_do_not(self):
        feeder = Feeder("s1")
        feeder.feed(data("junk", "--------- beginning of main"))
        assert feeder.cursor is None
        feeder.feed(data(line(1), "junk"))
        assert feeder.cursor == stamp(1)

    def test_the_cursor_survives_a_new_connection(self):
        feeder = Feeder("s1")
        feeder.feed(data(line(3)))
        feeder.begin_connection()
        assert feeder.cursor == stamp(3)


class TestHistory:
    def test_groups_older_than_the_overlap_are_dropped(self):
        feeder = Feeder("s1")
        feeder.feed(data(line(0), line(0.2)))
        feeder.feed(data(line(0.9)))
        assert feeder.history_lines == 3
        feeder.feed(data(line(1.5)))  # horizon 0.5: the first group (0.2) is old
        assert feeder.history_lines == 2
        feeder.feed(data(line(3)))  # horizon 2.0: everything before goes
        assert feeder.history_lines == 1
        assert feeder.short_until is None

    def test_a_group_exactly_at_the_horizon_stays(self):
        feeder = Feeder("s1")
        feeder.feed(data(line(0)))
        feeder.feed(data(line(OVERLAP.total_seconds())))
        assert feeder.history_lines == 2

    def test_history_since_returns_groups_by_their_cursor(self):
        feeder = Feeder("s1")
        feeder.feed(data(line(0, "a"), line(0.1, "b")))
        feeder.feed(data(line(0.6, "c")))
        got = feeder.history_since(stamp(0.5))
        assert [item.data for item in got] == [line(0.6, "c").encode()]
        got = feeder.history_since(stamp(0.05))
        assert len(got) == 3

    def test_the_history_holds_the_lines_of_the_read(self):
        feeder = Feeder("s1", condition=Level >= "E")
        feeder.feed(data(line(0), "junk", "--------- beginning of main"))
        assert feeder.history_lines == 3
        assert feeder.history_bytes > 0

    def test_the_line_cap_drops_the_oldest_groups_and_sets_short_until(self):
        feeder = Feeder("s1")
        per_read = 8000
        reads = 3
        for read in range(reads):
            feeder.feed(
                data(*(line((read * per_read + i) / 1e5, "x") for i in range(per_read)))
            )
        assert feeder.history_lines == per_read * 2  # 24000 > 20000: one group went
        assert feeder.history_lines <= HISTORY_LINES
        # The dropped group ended at 8000 / 1e5 s, inside the 1 s window.
        assert feeder.short_until == stamp((per_read - 1) / 1e5)

    def test_the_byte_cap_drops_the_oldest_groups_and_sets_short_until(self):
        feeder = Feeder("s1")
        big = "y" * 4000
        count = 300  # about 1.2 MB per read
        feeder.feed(data(*(line(i / 1e5, big) for i in range(count))))
        assert feeder.short_until is None
        first_end = stamp((count - 1) / 1e5)
        feeder.feed(data(*(line((count + i) / 1e5, big) for i in range(count))))
        assert feeder.history_bytes <= HISTORY_BYTES
        assert feeder.short_until == first_end
        assert feeder.history_lines == count

    def test_one_read_bigger_than_the_caps_empties_the_history(self):
        feeder = Feeder("s1")
        feeder.feed(data(*(line(i / 1e6, "z") for i in range(HISTORY_LINES + 5))))
        assert feeder.history_lines == 0
        assert feeder.history_bytes == 0
        assert feeder.short_until == stamp((HISTORY_LINES + 4) / 1e6)

    def test_groups_outside_the_window_do_not_set_short_until(self):
        feeder = Feeder("s1")
        feeder.feed(data(*(line(i / 1e5, "x") for i in range(15000))))
        feeder.feed(data(line(10)))  # the old group leaves by time first
        assert feeder.short_until is None
        assert feeder.history_lines == 1

    def test_short_until_only_moves_forward(self):
        feeder = Feeder("s1")
        for read in range(4):
            feeder.feed(
                data(*(line((read * 12000 + i) / 1e5, "x") for i in range(12000)))
            )
        assert feeder.short_until is not None
        first = feeder.short_until
        feeder.feed(data(*(line((60000 + i) / 1e5, "x") for i in range(12000))))
        assert feeder.short_until is not None
        assert feeder.short_until > first

    def test_the_line_cap_holds_without_any_timestamp(self):
        feeder = Feeder("s1")
        for _ in range(HISTORY_LINES // 1000 + 5):
            feeder.feed(b"junk\n" * 1000)
            assert feeder.history_lines <= HISTORY_LINES
        assert feeder.history_lines == HISTORY_LINES
        assert feeder.short_until is None

    def test_the_byte_cap_holds_without_any_timestamp(self):
        feeder = Feeder("s1")
        row = b"j" * 999 + b"\n"
        for _ in range(HISTORY_BYTES // 100_000 + 5):
            feeder.feed(row * 100)
            assert feeder.history_bytes <= HISTORY_BYTES
        assert feeder.history_bytes > HISTORY_BYTES // 2
        assert feeder.short_until is None

    def test_the_bytes_of_a_short_read_count_toward_the_line_it_completes(self):
        feeder = Feeder("s1")
        for index in range(50):
            text = line(index, "p" * 4000).encode()
            feeder.feed(text[:-10])
            feeder.feed(text[-10:] + b"\n")
        held = sum(len(item.data) for item in feeder.history_since(stamp(0)))
        assert feeder.history_bytes >= held

    def test_the_history_charge_is_the_bytes_of_the_reads(self):
        feeder = Feeder("s1")
        reads = [data(line(0), line(0.1))[:-20], b"x" * 20, data(line(0.2))]
        for raw in reads[:-1]:
            feeder.feed(raw)
        feeder.feed(reads[-1])
        assert feeder.history_bytes == sum(len(raw) for raw in reads)

    def test_a_group_without_a_time_leaves_when_a_time_is_known(self):
        feeder = Feeder("s1")
        feeder.feed(data("junk"))
        assert feeder.history_lines == 1
        feeder.feed(data(line(0)))
        assert feeder.history_lines == 1  # the timeless group is gone, not short
        assert feeder.short_until is None


class TestMarkers:
    @pytest.mark.parametrize("kind", ["start", "flush"])
    @pytest.mark.parametrize("suffix", ["", " ", "  \t"])
    def test_marker_lines_are_never_delivered(self, kind, suffix):
        feeder = Feeder("s1")
        marker = new_marker(kind)
        out = feeder.feed(data(line(0), line(1, marker + suffix, MARKER_TAG), line(2)))
        assert len(entries_of(out)) == 2
        assert (feeder.lines, feeder.markers) == (2, 1)
        assert not feeder.arrived

    def test_a_marker_of_an_earlier_run_is_dropped_and_not_awaited(self):
        feeder = Feeder("s1")
        awaited = new_marker("flush")
        feeder.expect(awaited)
        old = new_marker("flush")
        out = feeder.feed(data(line(0, old, MARKER_TAG), line(1)))
        assert len(entries_of(out)) == 1
        assert not feeder.arrived
        assert feeder.markers == 1

    def test_the_awaited_marker_arrives_at_its_place(self):
        feeder = Feeder("s1")
        token = new_marker("start")
        feeder.expect(token)
        out = feeder.feed(
            data(line(0, "a"), line(1, token + " ", MARKER_TAG), line(2, "b"))
        )
        assert shape(out) == [1, "MarkerArrived", 1]
        assert flat(out)[1] == MarkerArrived(token)
        assert feeder.arrived
        assert [e.message for e in entries_of(out)] == ["a", "b"]

    def test_a_second_copy_of_the_marker_is_dropped_quietly(self):
        feeder = Feeder("s1")
        token = new_marker("flush")
        feeder.expect(token)
        feeder.feed(data(line(0, token, MARKER_TAG)))
        out = feeder.feed(data(line(1, token, MARKER_TAG)))
        assert out == []
        assert feeder.markers == 2

    def test_expect_again_resets_arrived(self):
        feeder = Feeder("s1")
        first = new_marker("start")
        feeder.expect(first)
        feeder.feed(data(line(0, first, MARKER_TAG)))
        assert feeder.arrived
        feeder.expect(new_marker("flush"))
        assert not feeder.arrived

    def test_marker_shaped_text_under_another_tag_is_delivered(self):
        feeder = Feeder("s1")
        marker = new_marker("start")
        out = feeder.feed(data(line(0, marker, "other")))
        assert [e.message for e in entries_of(out)] == [marker]
        assert feeder.markers == 0

    @pytest.mark.parametrize(
        "message",
        [
            "hello",
            "start-1234",
            "start-" + "g" * 32,
            "start-" + "a" * 33,
            "begin-" + "a" * 32,
            "x start-" + "a" * 32,
        ],
    )
    def test_other_text_under_the_marker_tag_is_delivered(self, message):
        feeder = Feeder("s1")
        out = feeder.feed(data(line(0, message, MARKER_TAG)))
        assert len(entries_of(out)) == 1

    def test_a_marker_is_found_when_the_condition_would_drop_it(self):
        feeder = Feeder("s1", condition=Tag("nothing"))
        token = new_marker("flush")
        feeder.expect(token)
        out = feeder.feed(data(line(0, token, MARKER_TAG)))
        assert flat(out) == [MarkerArrived(token)]
        assert feeder.arrived

    def test_a_marker_that_continues_across_reads_is_found(self):
        feeder = Feeder("s1")
        token = new_marker("flush")
        feeder.expect(token)
        text = data(line(0, token + " ", MARKER_TAG))
        assert feeder.feed(text[:60]) == []
        assert flat(feeder.feed(text[60:])) == [MarkerArrived(token)]

    def test_marker_lines_are_kept_in_the_history(self):
        feeder = Feeder("s1")
        feeder.feed(data(line(0, new_marker("start"), MARKER_TAG)))
        assert feeder.history_lines == 1

    def test_expect_rejects_text_that_is_not_a_marker(self):
        with pytest.raises(ValueError, match="not a marker"):
            Feeder("s1").expect("flush-123")

    def test_markers_are_fresh_and_shaped(self):
        first, second = new_marker("start"), new_marker("flush")
        assert first.startswith("start-")
        assert second.startswith("flush-")
        assert len(first) == len("start-") + 32
        assert first != new_marker("start")


class TestConnections:
    def test_an_unfinished_line_is_not_joined_to_the_next_connection(self):
        feeder = Feeder("s1")
        text = line(1, "whole")
        feeder.feed(line(0, "partial").encode()[:40])
        feeder.begin_connection()
        out = feeder.feed(data(text))
        assert [e.raw for e in entries_of(out)] == [text]
        assert feeder.lines == 1

    def test_a_cut_line_of_the_old_connection_does_not_leak(self):
        feeder = Feeder("s1", max_line_bytes=4096)
        feeder.feed(b"x" * 5000)  # cut and discarded up to the next LF
        feeder.begin_connection()
        out = feeder.feed(data(line(0)))
        assert [e.raw for e in entries_of(out)] == [line(0)]

    def test_the_serial_is_kept_and_the_parse_session_is_fresh(self):
        feeder = Feeder("emulator-5554")
        feeder.feed(data(line(0)))
        feeder.begin_connection()
        (entry,) = entries_of(feeder.feed(data(line(1))))
        assert entry.serial == "emulator-5554"

    def test_the_parse_session_is_new_after_a_connection_begins(self):
        # A line without a year is placed next to the line before it in the same
        # session; a new session places it before the host's clock instead.
        now = datetime.now(UTC)
        ahead, behind = now + timedelta(days=5), now - timedelta(days=5)
        if 2 in {ahead.month, behind.month}:
            pytest.skip("too close to a leap day for this check")

        def yearless(moment: datetime, msg: str) -> str:
            clock = f"{moment:%m-%d %H:%M:%S}.000"
            return f"{clock}  1000  1000  1000 I tag     : {msg}"

        def year_of_second_line(*, reconnect: bool) -> int:
            feeder = Feeder("s1")
            feeder.feed(data(yearless(ahead, "first")))  # not yet happened: last year
            if reconnect:
                feeder.begin_connection()
            (entry,) = entries_of(feeder.feed(data(yearless(behind, "second"))))
            return entry.logged_at.year

        assert year_of_second_line(reconnect=True) == behind.year
        assert year_of_second_line(reconnect=False) == behind.year - 1

    def test_bytes_of_an_unfinished_line_are_not_charged_to_the_next_connection(self):
        feeder = Feeder("s1")
        feeder.feed(line(0).encode()[:40])
        feeder.begin_connection()
        raw = data(line(1))
        feeder.feed(raw)
        assert feeder.history_bytes == len(raw)

    def test_counters_persist_and_reconnects_count(self):
        feeder = Feeder("s1")
        feeder.feed(data(line(0), "junk"))
        feeder.begin_connection()
        feeder.begin_connection()
        feeder.feed(data(line(1)))
        assert (feeder.lines, feeder.entries, feeder.unparsed) == (3, 3, 1)
        assert feeder.reconnects == 2

    def test_the_awaited_marker_survives_a_new_connection(self):
        feeder = Feeder("s1")
        token = new_marker("flush")
        feeder.expect(token)
        feeder.begin_connection()
        assert flat(feeder.feed(data(line(0, token, MARKER_TAG)))) == [
            MarkerArrived(token)
        ]

    def test_the_history_survives_a_new_connection(self):
        feeder = Feeder("s1")
        feeder.feed(data(line(0), line(0.5)))
        feeder.begin_connection()
        assert feeder.history_lines == 2

    def test_feed_after_finish_needs_a_new_connection(self):
        feeder = Feeder("s1")
        feeder.finish()
        with pytest.raises(RuntimeError):
            feeder.feed(b"x\n")
        feeder.begin_connection()
        assert len(entries_of(feeder.feed(data(line(0))))) == 1


class TestResumeCheck:
    def test_replays_are_dropped_and_not_counted(self):
        old = line(0, "old")
        feeder = Feeder("s1")
        feeder.feed(data(old))
        check = FakeCheck([old.encode()])
        feeder.begin_connection(check)
        out = feeder.feed(data(old, line(0.5, "new")))
        assert [e.message for e in entries_of(out)] == ["new"]
        assert (feeder.lines, feeder.entries, feeder.duplicates) == (2, 2, 1)
        assert feeder.history_lines == 2  # the replay is not recorded twice

    def test_the_check_sees_every_line_with_its_time_before_anything_else(self):
        feeder = Feeder("s1", condition=Level >= "E")
        token = new_marker("start")
        feeder.expect(token)
        check = FakeCheck(never=True)
        feeder.begin_connection(check)
        feeder.feed(
            data(
                line(0, level="I"),
                "--------- beginning of main",
                "junk",
                line(1, token, MARKER_TAG),
            )
        )
        assert [moment for _, moment in check.seen] == [
            stamp(0),
            None,
            None,
            stamp(1),
        ]
        assert feeder.arrived

    def test_a_dropped_replay_does_not_move_the_cursor_or_count_as_a_marker(self):
        marker_line = line(5, new_marker("start"), MARKER_TAG)
        feeder = Feeder("s1")
        feeder.begin_connection(FakeCheck([marker_line.encode()], never=True))
        out = feeder.feed(data(marker_line))
        assert out == []
        assert feeder.cursor is None
        assert (feeder.markers, feeder.duplicates, feeder.lines) == (0, 1, 0)

    def test_the_gap_goes_before_the_line_that_ended_the_check(self):
        check = FakeCheck(gap=make_gap(lost=4))
        feeder = Feeder("s1")
        feeder.begin_connection(check)
        out = feeder.feed(data(line(0.5, "first"), line(2, "a")))
        assert check.finished
        assert shape(out) == ["Gap", 2]
        assert (feeder.gaps, feeder.lost) == (1, 4)
        assert len(check.seen) == 1  # not asked again once finished

    def test_entries_before_the_end_stay_before_the_gap(self):
        old = line(0, "old")
        gap = make_gap()
        check = FakeCheck([old.encode()], gap)
        feeder = Feeder("s1")
        feeder.begin_connection(check)
        out = feeder.feed(data(old, line(2, "a"), line(3, "b")))
        assert shape(out) == ["Gap", 2]
        assert flat(out)[0] is gap
        assert [e.message for e in entries_of(out)] == ["a", "b"]

    def test_entries_read_while_the_check_runs_come_before_the_gap(self):
        gap = make_gap()

        class Ending(FakeCheck):
            def admit(self, framed, logged_at):
                self.seen.append((framed.data, logged_at))
                self.finished = len(self.seen) == 3
                return True

        ending = Ending(gap=gap)
        feeder = Feeder("s1")
        feeder.begin_connection(ending)
        out = feeder.feed(data(line(0, "a"), line(1, "b"), line(2, "c"), line(3, "d")))
        assert shape(out) == [2, "Gap", 2]
        assert [e.message for e in entries_of(out)] == ["a", "b", "c", "d"]
        assert feeder.lines == 4

    def test_a_finished_check_is_not_called_again_and_the_tail_is_kept(self):
        class Counting(FakeCheck):
            calls = 0

            def admit(self, framed, logged_at):
                del framed, logged_at
                type(self).calls += 1
                self.finished = True
                return True

        feeder = Feeder("s1")
        feeder.begin_connection(Counting())
        feeder.feed(data(line(0), line(0.1), line(0.2)))
        feeder.feed(data(line(0.3)))
        assert Counting.calls == 1
        assert feeder.history_lines == 4

    def test_a_check_that_finishes_on_a_dropped_line_puts_the_gap_there(self):
        gap = make_gap()

        class LastReplay(FakeCheck):
            def admit(self, framed, logged_at):
                del framed, logged_at
                self.finished = True
                return False

        feeder = Feeder("s1")
        feeder.begin_connection(LastReplay(gap=gap))
        out = feeder.feed(data(line(0, "dup"), line(1, "new")))
        assert shape(out) == ["Gap", 1]
        assert feeder.duplicates == 1

    def test_a_finished_check_without_a_gap_adds_nothing(self):
        feeder = Feeder("s1")
        feeder.begin_connection(FakeCheck(gap=None))
        out = feeder.feed(data(line(0)))
        assert shape(out) == [1]
        assert feeder.gaps == 0

    def test_end_check_returns_the_gap_once(self):
        gap = make_gap(lost=2)
        feeder = Feeder("s1")
        feeder.begin_connection(FakeCheck(never=True, gap=gap))
        assert flat(feeder.end_check()) == [gap]
        assert (feeder.gaps, feeder.lost) == (1, 2)
        assert feeder.end_check() == []
        assert feeder.gaps == 1

    def test_end_check_without_a_check_or_a_gap(self):
        feeder = Feeder("s1")
        assert feeder.end_check() == []
        feeder.begin_connection(FakeCheck(never=True))
        assert feeder.end_check() == []

    def test_a_new_connection_replaces_a_pending_check(self):
        feeder = Feeder("s1")
        feeder.begin_connection(FakeCheck(never=True, gap=make_gap()))
        feeder.begin_connection()
        assert feeder.end_check() == []

    def test_a_check_that_is_finished_already_is_refused(self):
        check = FakeCheck()
        check.finished = True
        with pytest.raises(ValueError, match="finished"):
            Feeder("s1").begin_connection(check)

    def test_the_gap_counts_are_not_touched_for_a_gap_without_lost(self):
        feeder = Feeder("s1")
        feeder.begin_connection(FakeCheck(gap=make_gap(None)))
        feeder.feed(data(line(0)))
        assert (feeder.gaps, feeder.lost) == (1, 0)


def _cost_per_line(
    reads: int, lines_per_read: int, *, deep_history: bool, step: float
) -> float:
    """Seconds per line to feed ``reads`` reads of ``lines_per_read`` lines.

    With ``deep_history`` about 2,000 small groups are in the history (near
    its line cap) while the measured reads run; the measured reads then stay
    inside the overlap window. ``step`` is the time between reads: more than
    `OVERLAP` keeps the history at one group.
    """
    feeder = Feeder("s1")
    if deep_history:
        for r in range(HISTORY_LINES // 10 - 1):
            feeder.feed(data(*(line((r * 10 + i) / 1e6, "w") for i in range(10))))
    first = 1.0 if deep_history else 0.0
    payload = [
        data(
            *(
                line(first + r * step + i / 1e7, "m", pid=100 + i % 7)
                for i in range(lines_per_read)
            )
        )
        for r in range(reads)
    ]
    start = time.perf_counter()
    for chunk in payload:
        feeder.feed(chunk)
    elapsed = (time.perf_counter() - start) / (reads * lines_per_read)
    if deep_history:
        assert feeder.history_lines > HISTORY_LINES // 2  # the history stayed deep
    else:
        assert feeder.history_lines <= lines_per_read  # it stayed at one group
    return elapsed


def _median_cost(reads: int, lines_per_read: int, *, deep_history: bool) -> float:
    step = 0.0001 if deep_history else 2.0
    return statistics.median(
        _cost_per_line(reads, lines_per_read, deep_history=deep_history, step=step)
        for _ in range(5)
    )


def test_per_line_cost_does_not_grow_with_the_history_or_the_read(capsys):
    """Loose bounds: they catch a per-line step that walks the history or the read."""
    small_history = _median_cost(100, 100, deep_history=False)
    deep_history = _median_cost(100, 100, deep_history=True)
    small_read = _median_cost(800, 50, deep_history=False)
    big_read = _median_cost(2, 20_000, deep_history=False)
    with capsys.disabled():
        print(  # noqa: T201
            f"\nfeed: {small_history * 1e6:.3f} us/line, "
            f"{deep_history * 1e6:.3f} us/line with a deep history; "
            f"{small_read * 1e6:.3f} us/line in 50-line reads, "
            f"{big_read * 1e6:.3f} us/line in 20,000-line reads"
        )
    assert small_history < 30e-6  # parsing is about 3 us; this only catches a blow-up
    assert deep_history < 2 * small_history
    assert big_read < 2 * small_read


# --- the chatty notice of an old logd -------------------------------------------------

# The notices an Android 7 device logged (recording C06), with the number of
# lines each says were dropped.
REAL_NOTICES = [
    (each["line"], lost)
    for each, lost in zip(
        load(level_dir(24), "C06")["facts"]["notice_details"],
        [4, 26, 2, 2, 1, 2, 16, 3, 1, 2, 15, 21],
        strict=True,
    )
]


def notice(lost: int = 3, text: str | None = None) -> str:
    """A synthetic notice line in the shape of the recorded ones."""
    message = text or f"uid=10014(com.example) expire {lost} lines"
    return line(1.0, message, tag=CHATTY_TAG, uid="10014")


class TestChattyNotice:
    @pytest.mark.parametrize(("recorded", "lost"), REAL_NOTICES)
    def test_a_recorded_notice_gives_a_gap_before_its_own_entry(self, recorded, lost):
        feeder = Feeder("s1")
        before = datetime.now(UTC)
        out = feeder.feed(data(line(0, "first"), recorded, line(2, "last")))
        segments = flat(out)
        assert shape(out) == [1, "Gap", 2]
        gap = segments[1]
        assert gap.serial == "s1"
        assert (gap.reason, gap.cause, gap.lost) == ("device_reported", "notice", lost)
        notice_entry = segments[2][0]
        assert notice_entry.tag == CHATTY_TAG
        assert gap.start_at == notice_entry.logged_at
        assert before <= gap.detected_at <= datetime.now(UTC)
        assert (feeder.gaps, feeder.lost) == (1, lost)
        assert feeder.entries == 3

    def test_the_gap_comes_when_the_condition_removes_the_notice(self):
        feeder = Feeder("s1", condition=Tag("keep"))
        out = feeder.feed(
            data(line(0, "a", tag="keep"), notice(5), line(2, "b", tag="keep"))
        )
        assert shape(out) == [1, "Gap", 1]
        assert [e.message for e in entries_of(out)] == ["a", "b"]
        assert (feeder.gaps, feeder.lost, feeder.entries, feeder.lines) == (1, 5, 2, 3)

    def test_the_notice_line_is_delivered_when_the_condition_passes_it(self):
        feeder = Feeder("s1", condition=Tag(CHATTY_TAG))
        out = feeder.feed(data(line(0, "a"), notice(5)))
        assert shape(out) == ["Gap", 1]
        assert entries_of(out)[0].tag == CHATTY_TAG

    def test_a_notice_replayed_by_a_resume_check_is_dropped_without_a_gap(self):
        feeder = Feeder("s1")
        feeder.begin_connection(FakeCheck([notice(5).encode()]))
        out = feeder.feed(data(notice(5), line(2, "n")))
        assert shape(out) == [1]
        assert (feeder.gaps, feeder.lost, feeder.duplicates) == (0, 0, 1)

    def test_two_notices_are_two_gaps_and_add_up(self):
        feeder = Feeder("s1")
        out = feeder.feed(data(notice(5), notice(7)))
        assert shape(out) == ["Gap", 1, "Gap", 1]
        assert (feeder.gaps, feeder.lost) == (2, 12)

    @pytest.mark.parametrize(
        "message",
        [
            "uid=10014(com.example) com.example.Worker identical 3 lines",
            "uid=10014 identical 1 line",
            "uid=10014(com.example) expire lines",
            "uid=abc expire 3 lines",
            "expire 3 lines",
            "uid=10014(com.example) expire 3 lines and more",
            "hello",
        ],
    )
    def test_other_messages_with_the_tag_give_no_gap(self, message):
        assert chatty_loss(message) is None
        feeder = Feeder("s1")
        out = feeder.feed(data(notice(text=message)))
        assert shape(out) == [1]
        assert (feeder.gaps, feeder.lost) == (0, 0)

    def test_the_text_of_a_notice_under_another_tag_is_not_a_notice(self):
        feeder = Feeder("s1")
        text = notice(4).replace("chatty", "other ")
        assert shape(feeder.feed(data(text))) == [1]
        assert feeder.gaps == 0

    def test_a_count_of_more_than_18_digits_is_no_notice(self):
        assert chatty_loss(f"uid=10014 expire {'9' * 18} lines") == int("9" * 18)
        assert chatty_loss(f"uid=10014 expire {'9' * 19} lines") is None
        # Beyond int()'s default limit of 4,300 digits: the line is delivered as
        # an entry, the feed goes on, and no gap is counted.
        feeder = Feeder("s1")
        out = feeder.feed(data(notice(text=f"uid=10014 expire {'1' * 4301} lines")))
        assert shape(out) == [1]
        assert (feeder.gaps, feeder.lost) == (0, 0)

    def test_the_total_of_the_counts_stays_serializable(self):
        # Each count converts on its own, but two of them add up to 4,301 digits,
        # which json.dumps (through int-to-str) refuses.
        feeder = Feeder("s1")
        big = notice(text=f"uid=10014 expire {'9' * 4300} lines")
        feeder.feed(data(big, big))
        json.dumps({"lost": feeder.lost})
        assert (feeder.gaps, feeder.lost) == (0, 0)

    def test_the_count_ignores_trailing_blanks_and_one_line_wording(self):
        assert chatty_loss("uid=1000(system) expire 1 line ") == 1
        assert chatty_loss("uid=1000 /system/bin/lmkd expire 12 lines") == 12


class TestGapLogging:
    """The first gap of each reason is a WARNING; later ones are told at the end."""

    def test_the_first_gap_of_a_reason_warns_and_later_ones_are_counted(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        feeder = Feeder("s1")
        with caplog.at_level("WARNING", logger="logprobe"):
            feeder.feed(data(line(0, "a"), notice(5), notice(2), notice(4)))
        warnings = [r.getMessage() for r in caplog.records]
        assert len(warnings) == 1
        assert warnings[0].startswith("s1: a gap in the log (device_reported)")
        assert "dropped 5 lines" in warnings[0]
        assert (feeder.gaps, feeder.lost) == (3, 11)
        caplog.clear()
        with caplog.at_level("WARNING", logger="logprobe"):
            feeder.tell_later_gaps()
            feeder.tell_later_gaps()  # told once: the counts start again
        assert [r.getMessage() for r in caplog.records] == [
            "s1: 2 more gaps in the log after the first of each kind "
            "(device_reported 2)"
        ]

    def test_nothing_is_told_at_the_end_without_later_gaps(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        feeder = Feeder("s1")
        with caplog.at_level("WARNING", logger="logprobe"):
            feeder.feed(data(line(0, "a"), notice(5)))
            feeder.tell_later_gaps()
        assert len(caplog.records) == 1  # the first gap only

    def test_each_reason_warns_once_and_the_end_line_counts_by_reason(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        feeder = Feeder("s1")
        now = datetime.now(UTC)
        gaps = [
            Gap("s1", reason, "disconnected", now, None)
            for reason in ("ring_rotated", "continuity_unknown", "ring_rotated")
        ]
        with caplog.at_level("WARNING", logger="logprobe"):
            for gap in gaps:
                feeder._count_gap(gap)
            feeder.feed(data(notice(5)))
            feeder.tell_later_gaps()
        messages = [r.getMessage() for r in caplog.records]
        assert [m.split(":")[1].strip() for m in messages[:3]] == [
            "a gap in the log (ring_rotated)",
            "a gap in the log (continuity_unknown)",
            "a gap in the log (device_reported)",
        ]
        assert "after a reconnect (disconnected)" in messages[0]
        assert messages[3:] == [
            "s1: 1 more gaps in the log after the first of each kind (ring_rotated 1)"
        ]

    def test_a_raising_handler_does_not_stop_a_read_or_its_end(self) -> None:
        feeder = Feeder("s1")

        class Raising(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                raise RuntimeError(record.getMessage())

            def handle(self, record: logging.LogRecord) -> bool:
                self.emit(record)
                return True

        log = logging.getLogger("logprobe")
        handler = Raising()
        log.addHandler(handler)
        try:
            out = feeder.feed(data(line(0, "a"), notice(5), notice(2)))  # no exception
            feeder.tell_later_gaps()  # no exception
        finally:
            log.removeHandler(handler)
        assert shape(out) == [1, "Gap", 1, "Gap", 1]
        assert (feeder.gaps, feeder.lost, feeder.entries) == (2, 7, 3)
