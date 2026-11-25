"""The list commands, and what their output amounts to."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .._parse.uid import MAX_UID
from .owners import _APP_ID_MODULUS


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


# -- The list of every installed package ----------------------------------------

#: Lists every installed package with its uid (Android 16; Android 7 does not
#: know ``-U``).
PM_LIST_ARGV: tuple[str, ...] = ("pm", "list", "packages", "-U")
#: Prints the record of every installed package; used where ``-U`` is unknown.
DUMPSYS_PACKAGES_ARGV: tuple[str, ...] = ("dumpsys", "package", "packages")

# A uid is a 32-bit number, so it has at most ten ASCII digits; a longer number
# is not a uid but garbage, and so is a ten-digit number above `MAX_UID`.
_UID = r"[0-9]{1,10}"
_PM_LINE = re.compile(rf"package:(\S+) +uid:({_UID}(?:,{_UID})*)")
_RECORD_HEADER = re.compile(r"Package \[([^\]\s]+)\](?: \([^()]*\))?:?")
_RECORD_UID = re.compile(rf"(?:userId|appId)=({_UID})(?:\s|$)")
_DASH_U = re.compile(r"(?<![\w-])-U\b")


@dataclass(frozen=True, slots=True)
class Listed:
    """A list command printed the installed packages.

    Attributes:
        uids: Package name to uid, as printed (not reduced to an app id).
            Packages that share a uid appear as several names with the same
            number.
    """

    uids: dict[str, int]


@dataclass(frozen=True, slots=True)
class Fallback:
    """``pm list packages -U`` gave no usable list; run `DUMPSYS_PACKAGES_ARGV`.

    Attributes:
        unsupported: True when the device said it does not know ``-U``, so
            later lists on it can go to ``dumpsys`` straight away. False when
            the output was merely not a list (no ``package:`` line, or one
            without a usable uid); the next list may try ``-U`` again.
    """

    unsupported: bool


@dataclass(frozen=True, slots=True)
class Failed:
    """A list command failed.

    Attributes:
        reason: What went wrong, worded to follow "the command ... on <serial>",
            for example ``did not succeed (exit status 1)``.
        exit_status: The command's exit status, None when it ended without one.
    """

    reason: str
    exit_status: int | None


#: What one run of `PM_LIST_ARGV` amounts to.
type PmListOutcome = Listed | Fallback | Failed
#: What one run of `DUMPSYS_PACKAGES_ARGV` amounts to.
type DumpsysOutcome = Listed | Failed


def parse_pm_list(text: str) -> dict[str, int] | None:
    """Read the output of ``pm list packages -U``.

    Each package is a line ``package:<name> uid:<uid>``; on a device with
    several users the uid may be a comma-separated list, whose members then
    share one app id and the first is kept. Blank and unrelated lines are
    skipped. If a name is listed twice, its first line wins.

    Returns:
        Package name to uid, or None when there is no ``package:`` line, or a
        ``package:`` line has no usable uid (a device that ignores ``-U`` would
        print bare names; a number above the 32-bit range is no uid either).
    """
    uids: dict[str, int] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("package:"):
            continue
        found = _PM_LINE.fullmatch(stripped)
        if found is None:
            return None
        numbers = [int(number) for number in found.group(2).split(",")]
        if max(numbers) > MAX_UID:
            return None
        if len({number % _APP_ID_MODULUS for number in numbers}) != 1:
            return None
        uids.setdefault(found.group(1), numbers[0])
    return uids or None


def parse_dumpsys_packages(text: str) -> dict[str, int] | None:
    """Read the output of ``dumpsys package packages``.

    A record starts with a line ``Package [<name>]`` (optionally followed by
    a hash in parentheses and a colon) and covers the more deeply indented
    lines that follow; its uid is the first ``userId=`` (Android 7) or
    ``appId=`` (Android 16) line inside it (a value that is not a uid, such as
    a number above the 32-bit range, does not count). A record without a uid
    is skipped. If a package has several
    records (the hidden system packages repeat some names), the first one
    with a uid wins.

    Returns:
        Package name to uid, as printed, or None when no record has a uid.
    """
    uids: dict[str, int] = {}
    base: int | None = None  # indentation of the header of the record being read
    name: str | None = None  # its package, until its uid is found
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        depth = _indent(line)
        if base is not None and depth <= base:
            base = None
        if base is None:
            header = _RECORD_HEADER.fullmatch(stripped)
            if header is not None:
                base, name = depth, header.group(1)
            continue
        if name is not None:
            found = _RECORD_UID.match(stripped)
            if found is not None and int(found.group(1)) <= MAX_UID:
                uids.setdefault(name, int(found.group(1)))
                name = None
    return uids or None


def _unknown_option(text: str) -> bool:
    """Whether ``text`` has a line saying that ``-U`` is an unknown option."""
    return any(
        "Unknown option" in line and _DASH_U.search(line) is not None
        for line in text.splitlines()
    )


def _exit_failure(exit_status: int | None) -> Failed | None:
    if exit_status is None:
        return Failed("ended without an exit status", None)
    if exit_status != 0:
        return Failed(f"did not succeed (exit status {exit_status})", exit_status)
    return None


def read_pm_list(
    exit_status: int | None, stdout: bytes, stderr: bytes
) -> PmListOutcome:
    """Decide what a run of `PM_LIST_ARGV` amounts to.

    The output decides first: Android 7 prints ``Error: Unknown option: -U``
    and still exits with status 0, so that text means `Fallback` (unsupported)
    whatever the exit status. Otherwise a missing or non-zero exit status is
    `Failed`, and an output `parse_pm_list` cannot read is `Fallback`.
    """
    out = stdout.decode("utf-8", "replace")
    if _unknown_option(out) or _unknown_option(stderr.decode("utf-8", "replace")):
        return Fallback(unsupported=True)
    failure = _exit_failure(exit_status)
    if failure is not None:
        return failure
    uids = parse_pm_list(out)
    if uids is None:
        return Fallback(unsupported=False)
    return Listed(uids)


def read_dumpsys_packages(exit_status: int | None, stdout: bytes) -> DumpsysOutcome:
    """Decide what a run of `DUMPSYS_PACKAGES_ARGV` amounts to.

    A missing or non-zero exit status is `Failed`, and so is an output with no
    package record that has a uid (for example ``Error: Could not access the
    Package Manager`` while the device boots).
    """
    failure = _exit_failure(exit_status)
    if failure is not None:
        return failure
    uids = parse_dumpsys_packages(stdout.decode("utf-8", "replace"))
    if uids is None:
        return Failed("printed no package list", exit_status)
    return Listed(uids)
