"""Helpers for the recordings of real devices in ``tests/fixtures/device``.

A recording is a JSON file per probe, ``api<level>/<KEY>_<slug>.json``, holding
the steps a device was driven through (``argv``, ``stdout`` lines) and the
facts read from them. Only API 24 and 36 were recorded.

The regular expressions here are the contract, written from the AOSP format
strings and the recordings, independently of the parsers under test.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "device"
LEVELS = (24, 36)

# The live wire format: -v threadtime -v year -v usec -v zone -v uid.
LIVE_MODIFIERS = ["threadtime", "year", "usec", "zone", "uid"]
LIVE_LINE = re.compile(
    r"^(?P<date>\d{4}-\d\d-\d\d) (?P<time>\d\d:\d\d:\d\d\.\d{6}) (?P<zone>[+-]\d{4}) "
    r"+(?P<uid>\S+) +(?P<pid>\d+) +(?P<tid>\d+) (?P<level>[VDIWEF]) "
    r"(?P<tag>.*?) *: (?P<msg>.*)$"
)
PROCESS_LINE = re.compile(r"^[VDIWEF]\( *\d+\) .*  \((?P<tag>[^()]*)\)$")


def level_dir(level: int) -> Path:
    """Return the fixture directory of an API level."""
    return FIXTURES / f"api{level}"


def load(directory: Path, key: str) -> dict[str, Any]:
    """Load the recording ``<key>_*.json`` from ``directory``."""
    matches = sorted(directory.glob(f"{key}_*.json"))
    assert len(matches) == 1, f"expected one {key}_*.json in {directory}, got {matches}"
    return json.loads(matches[0].read_text(encoding="utf-8"))


def step(rec: dict[str, Any], name: str) -> dict[str, Any]:
    """Return the step called ``name``."""
    found = [s for s in rec["steps"] if s["name"] == name]
    assert found, (
        f"{rec['id']}: no step {name!r} in {[s['name'] for s in rec['steps']]}"
    )
    return found[0]


def body(lines: list[str]) -> list[str]:
    """``lines`` without ``--------- beginning of <buffer>`` dividers."""
    return [line for line in lines if not line.startswith("--------- ")]
