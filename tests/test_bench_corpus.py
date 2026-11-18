"""Tests for the benchmark line generator."""

from __future__ import annotations

import re

import pytest

from bench.corpus import (
    BROKEN_POOL,
    DENSE_LINE_BYTES,
    KINDS,
    build_lines,
    recorded_live_lines,
    sized_lines,
)
from logprobe import parse_lines

LIVE = re.compile(
    rb"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{6} [+-]\d{4} +\S+ +\d+ +\d+ [VDIWEF] "
)


@pytest.mark.parametrize("kind", KINDS)
def test_lines_are_deterministic_and_end_in_a_line_feed(kind):
    first = build_lines(kind, 300)
    assert first == build_lines(kind, 300)
    assert len(first) == 300
    assert all(line.endswith(b"\n") and line.count(b"\n") == 1 for line in first)
    first[0].decode("utf-8")  # every kind is valid UTF-8


def test_live_lines_come_from_the_recordings_and_repeat_in_order():
    pool = recorded_live_lines()
    assert len(pool) > 1000
    lines = build_lines("live", len(pool) + 2)
    assert lines[0] == (pool[0] + "\n").encode()
    assert lines[len(pool)] == lines[0]
    assert all(LIVE.match(line) for line in lines)


def test_dense_lines_are_exactly_60_bytes_and_live_format():
    lines = build_lines("dense", 25_000)
    assert {len(line) for line in lines} == {DENSE_LINE_BYTES}
    assert all(LIVE.match(line) for line in lines[:1000])
    assert len(set(lines)) > 1000


def test_multibyte_lines_are_mostly_multibyte_and_every_fourth_has_an_emoji():
    lines = build_lines("multibyte", 400)
    for i, line in enumerate(lines):
        text = line.decode()
        assert len(line) > 2 * len(text) * 0.6  # many 3-byte characters
        assert any(ord(c) > 0xFFFF for c in text) == (i % 4 == 3)


def test_broken_lines_are_short_and_do_not_parse():
    lines = build_lines("broken", 3 * len(BROKEN_POOL))
    assert max(len(line) for line in lines) <= 12
    entries = parse_lines(line.decode() for line in lines)
    assert not any(entry.parsed for entry in entries)


def test_live_dense_and_multibyte_lines_parse():
    for kind in ("live", "dense", "multibyte"):
        entries = list(parse_lines(line.decode() for line in build_lines(kind, 200)))
        assert all(entry.parsed for entry in entries), kind


def test_sized_lines_have_the_requested_message_size():
    for size in (0, 7, 100, 1600):
        lines = sized_lines(50, size)
        assert len(set(lines)) == 50 or size == 0
        for line in lines:
            message = line.decode().rstrip("\n").partition(" I sized: ")[2]
            assert len(message) == size


def test_bad_arguments_are_refused():
    with pytest.raises(ValueError, match="unknown kind"):
        build_lines("nope", 1)
    with pytest.raises(ValueError, match="negative"):
        build_lines("live", -1)
