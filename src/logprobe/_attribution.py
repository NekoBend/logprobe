"""Package attribution: deciding which log lines belong to watched packages.

A log line carries the uid of the process that wrote it. To tell whether the
line belongs to a watched package, the uid has to be mapped to package names,
and the device is the only source for that mapping: one command lists every
installed package with its uid (`PM_LIST_ARGV`, or `DUMPSYS_PACKAGES_ARGV` on
devices that do not know ``-U``). This module holds the pure part of that
work: the commands, what their output amounts to, and the verdict of each line
against the latest list. It does no I/O, starts no threads and never reads a
clock: the caller passes the current time (any monotonic float, in seconds) to
every call that needs it, runs the commands itself and hands the output back.

How a stream drives a `PackageAttributor`::

    attributor = PackageAttributor(condition, serial=serial)
    attributor.boundary = clock  # the device clock, read just before the list
    take_list(attributor)         # see below
    # For each read:
    if attributor.needs_list(segments, running=job is not None):
        # wait for the running job (list_done once it is finished), or
        # until attributor.ready_at() and take a list (never while blind)
        take_list(attributor)
    deliver(attributor.judge(segments))
    # Before a network read (the reader goes on reading while it runs):
    if attributor.list_due(now) and now >= attributor.ready_at():
        job = attributor.list_started(now)
        run_commands(job)  # elsewhere; reads are judged with the old list
        ...
        attributor.list_done(job, now)  # before a later network read

    def take_list(attributor):
        job = attributor.list_started(now)
        run_commands(job)
        attributor.list_done(job, now)

    def run_commands(job):
        job.started = now  # as the first command starts
        while not job.finished:
            result = run(job.argv)  # job.fail(reason) when it cannot be run
            job.take(result.exit_status, result.stdout, result.stderr)

The attributor is not thread-safe: only the job may be filled in elsewhere
(another thread or task), and `list_done` is called by the reader once it
is finished. At most one list of a device runs at a time.

Segments are what a reader makes of one read: lists of entries, and `Gap`
records, in the order they happened. `PackageAttributor.judge` keeps that
order; it holds nothing back.
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ._parse.uid import MAX_UID
from ._records import Gap

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from ._conditions import Condition
    from ._entry import LogEntry

__all__ = [
    "DUMPSYS_PACKAGES_ARGV",
    "LIST_INTERVAL",
    "LIST_MIN_TIME",
    "LIST_WAIT",
    "PM_LIST_ARGV",
    "RECHECK_INTERVAL",
    "DumpsysOutcome",
    "Failed",
    "Fallback",
    "ListJob",
    "Listed",
    "PackageAttributor",
    "PmListOutcome",
    "Segment",
    "dump_judge",
    "parse_dumpsys_packages",
    "parse_pm_list",
    "read_dumpsys_packages",
    "read_pm_list",
]

#: One piece of a reader's output: a list of entries, or a gap.
type Segment = list[LogEntry] | Gap

#: Least time between the starts of two lists of one device.
LIST_INTERVAL = 0.5
#: How often the list is taken again, to notice a reinstall; also how long a
#: device stays without a usable list after a list failed.
RECHECK_INTERVAL = 30.0
#: Longest time a read waits for a list before it is judged without one
#: (the wait for ``LIST_INTERVAL``, the command and the reader's other waits
#: since its bytes arrived all count). The regular list (every
#: `RECHECK_INTERVAL`, run while the reader goes on reading) has the time of
#: any other device command instead; a read that waits for it still waits at
#: most this long.
LIST_WAIT = 2.0
#: The least time a read's list needs: a read starts a list only when at
#: least this many seconds of its `LIST_WAIT` are left; otherwise its lines
#: are judged without a list. A list that was started and then cut by a time
#: limit counts as failed.
LIST_MIN_TIME = 1.0

# Uids are app_id + 100000 * user. App ids from 10000 up to (excluding) 20000
# are those of installed apps; the ranges around them hold system services,
# sandboxes and isolated processes (90000 and up) that no list names.
_APP_ID_MODULUS = 100_000
_FIRST_APP_ID = 10_000
_LAST_APP_ID = 20_000


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


class ListJob:
    """One package list of one device: the command to run next, and the outcome.

    It starts with `PM_LIST_ARGV`, or with `DUMPSYS_PACKAGES_ARGV` on a device
    known not to support ``-U``. Run `argv` and pass the result to `take`;
    when ``pm`` asks for the fallback, `argv` changes and the job is not
    finished yet. A command that could not be run to its end (timeout,
    cancel, adb error) ends the job through `fail`.

    Args:
        unsupported: The device is known not to support ``-U``.

    Attributes:
        argv: The command to run next (or the last one run, once finished).
        unsupported: Whether the device said it does not know ``-U``.
        outcome: `Listed` or `Failed` once finished, else None.
        stderr: What the last command wrote to stderr.
        wanted: The app ids of lines read before the list started that
            waited for a list (set by `PackageAttributor.list_started`).
        started: When the first command of the job started (the caller's
            clock), or None before that. The pacing between two lists counts
            from then, for a job that its runner started later than
            `PackageAttributor.list_started` was called.
    """

    __slots__ = (
        "argv",
        "counts",
        "outcome",
        "started",
        "stderr",
        "unsupported",
        "wanted",
    )

    def __init__(self, *, unsupported: bool = False) -> None:
        self.unsupported = unsupported
        self.argv = DUMPSYS_PACKAGES_ARGV if unsupported else PM_LIST_ARGV
        self.outcome: Listed | Failed | None = None
        self.stderr = b""
        self.wanted: frozenset[int] = frozenset()
        self.started: float | None = None
        # The lines judged before the list started (see `PackageAttributor`).
        self.counts = _Counts()

    @property
    def finished(self) -> bool:
        """Whether the job has an outcome."""
        return self.outcome is not None

    def take(self, exit_status: int | None, stdout: bytes, stderr: bytes) -> None:
        """Take the result of running `argv`."""
        self.stderr = stderr
        if self.argv == PM_LIST_ARGV:
            outcome = read_pm_list(exit_status, stdout, stderr)
            if isinstance(outcome, Fallback):
                self.unsupported = self.unsupported or outcome.unsupported
                self.argv = DUMPSYS_PACKAGES_ARGV
                return
            self.outcome = outcome
        else:
            self.outcome = read_dumpsys_packages(exit_status, stdout)

    def fail(self, reason: str, stderr: bytes = b"") -> None:
        """End the job: `argv` could not be run to its end, for ``reason``.

        ``stderr`` is what the command had written to stderr by then, when the
        caller has it (a command that took too long).
        """
        self.stderr = stderr
        self.outcome = Failed(reason, None)


class _Counts:
    """Lines judged per app id, by the rule that decided their app id.

    The rules are those of `PackageAttributor`. ``seen``: by the owner map
    (rule 2); ``others``: named by the list for a package that is not watched
    (5, and a system uid the list names); ``early``: logged before the
    boundary (6); ``absent``: absent, and a term without packages settled the
    line (7); ``unknown``: no list explains the
    app id, and a term without packages settled the line (9), or the app id
    is outside the app range and the latest list (if any) does not name it
    (3).
    """

    __slots__ = ("absent", "early", "others", "seen", "unknown")

    def __init__(self) -> None:
        self.seen: dict[int, int] = {}
        self.others: dict[int, int] = {}
        self.early: dict[int, int] = {}
        self.absent: dict[int, int] = {}
        self.unknown: dict[int, int] = {}

    def _all(self) -> tuple[dict[int, int], ...]:
        return (self.seen, self.others, self.early, self.absent, self.unknown)

    def add(self, other: _Counts) -> None:
        """Add the counts of ``other`` to these."""
        for mine, theirs in zip(self._all(), other._all(), strict=True):
            for app_id, lines in theirs.items():
                mine[app_id] = mine.get(app_id, 0) + lines

    def drop(self, app_ids: Iterable[int]) -> None:
        """Forget every count of ``app_ids``."""
        for counts in self._all():
            for app_id in app_ids:
                counts.pop(app_id, None)


def _owner_maps(
    names: Iterable[str], app_ids: dict[str, int]
) -> tuple[dict[str, int], dict[int, frozenset[str]], dict[int, str]]:
    """The watched names that are installed, and the owners and display per app id.

    ``app_ids`` maps every installed package to its app id. The display
    package of an app id is the first of its watched owners by name.
    """
    watched = {name: app_ids[name] for name in sorted(names) if name in app_ids}
    owners: dict[int, list[str]] = {}
    for name, app_id in watched.items():
        owners.setdefault(app_id, []).append(name)
    return (
        watched,
        {key: frozenset(value) for key, value in owners.items()},
        {key: value[0] for key, value in owners.items()},
    )


def _system_uid_text(serial: str, name: str, app_id: int) -> str:
    return (
        f"{serial}: {name} runs under the system uid {app_id}: every process of "
        "that uid is taken as belonging to it"
    )


class PackageAttributor:
    """Decides which lines of one device belong to watched packages.

    The watched packages are the names of the condition's `Package` terms
    (``Crash`` and ``Anr`` with a package read the message text and are not
    watched). The owners of a line come from the latest package list of the
    device. A line is decided as follows (the app id is the uid modulo
    100000, so other users of the device match by app id):

    1. A line without a uid belongs to no watched package.
    2. An app id that a watched package has: that package (all of them, when
       several share the uid).
    3. An app id outside 10000-19999 that no watched package has belongs to
       none: those are system services and isolated processes (such as a
       WebView renderer of an app, 90000 and up), which no list names.
    4. An app id that a watched package left at a list (it got a new app id,
       or was removed), a system uid included: every line of it is judged as
       in 8 (counted in `unattributed`, even when a term without packages
       settles its verdict), and no list is taken for it, until a successful
       list that started at least `RECHECK_INTERVAL` seconds after that one
       (normally the next regular list), or until a list shows a watched
       package under it (2 then applies). A list taken for a read in between
       does not end it. Its lines may be late ones of that package (the
       reader may be behind the device). This rule comes before 3.
    5. An app id the latest list names belongs to an installed package that is
       not watched.
    6. A line logged before `boundary` whose app id the list does not name
       belongs to an app that was removed before the list was taken.
    7. An app id that a list taken after its line was read did not name
       either is remembered until a list names it, and no list is taken for
       it. A line of it logged at or after `boundary` (any line when
       `boundary` is None; older lines are judged by 6) whose verdict
       depends on its app is judged as in 8 and counted in `unattributed`:
       a watched app may have been installed and removed while the reader
       was behind the device, and no list could check it. So lines of an app
       that is not watched, installed and removed meanwhile, are counted too,
       and so is every such line of an app id that no list ever names
       (perhaps an app installed only for another user, which is not
       verified), for as long as the stream runs.
    8. While the device has no usable list (`blind`: the last list failed),
       a line is judged as if no package owned it and counted in
       `unattributed`.
    9. Otherwise the verdict needs a newer list: `needs_list` says so, and
       `judge` decides such lines as in 8 when none came.

    Every other line with a uid that `judge` decides is counted per app id
    until the next successful list, whether or not the condition had to ask
    about its package: by 2, 3 (a later list may show a watched package under
    a system uid), 5 or 6, and also a line of 7, or one that would need a
    newer list (9), when a term without packages settles its verdict (it is
    delivered without a package). The next successful list adds those counts
    to `unattributed`, with a WARNING, when they may have been judged with an
    outdated list:

    - a watched package got a new app id or is no longer installed: the lines
      of its old app id;
    - a watched package turned up under an app id whose lines were decided
      by 3, 5, 6, 7 or 9 (the app id was freed and given again, the app
      appeared after its lines, or the device clock stepped back), or joined
      an app id that other watched packages had: the lines of that app id.

    The lines of one app id are added once per list (when several watched
    packages leave one app id together, the first WARNING has the count).
    The lines a reader judges while a list runs elsewhere are judged with
    the list before it. That list may have been taken before they were
    read, so their counts are kept apart: the list adds those of the app
    ids it adds, and the rest go on to the next list, which adds them when
    it finds a change. A line is added at most once.

    So the lines decided by 6 count only when a later list shows a watched
    package under their app id. A watched app that ran only between two lists
    (installed after one, removed before the list taken for its read: the
    reader is behind the device, or a reconnect reads missed lines again) is
    never seen by a list: its lines logged at or after `boundary` whose
    verdict depends on their app are counted by 7. Its lines that look older
    than `boundary` (the device clock stepped back) are judged by 6 and not
    counted. Nor is a line whose verdict a term without packages settles: it
    is delivered or left out as it would be with its app known (a delivered
    one without ``package``).

    A line whose verdict a term without packages settles (``Package(a) |
    Tag("x")`` for a line tagged ``x``) never needs a list.

    Args:
        condition: The condition to judge lines with.
        packages: The packages to watch; the names of the condition's
            `Package` terms when omitted.
        serial: The device's serial, for the messages.

    Attributes:
        boundary: The device clock (epoch seconds) read just before the first
            list, or None (rule 6 then does not apply).
    """

    def __init__(
        self,
        condition: Condition,
        packages: Iterable[str] | None = None,
        *,
        serial: str = "",
    ) -> None:
        self._serial = serial
        self._names = frozenset(
            condition._package_names() if packages is None else packages  # noqa: SLF001
        )
        self._judge: Callable[[LogEntry], bool | None] = condition._compile_membership(  # noqa: SLF001
            self._member
        )
        self._judge_blind: Callable[[LogEntry], bool | None] = (
            condition._compile_membership(  # noqa: SLF001
                _no_owner
            )
        )
        self.boundary: float | None = None

        self._messages: list[tuple[int, str]] = []
        self._unattributed = 0
        self._failure_told = False
        self._unattributed_told = False
        self._missing_told = False
        self._system_told: set[str] = set()

        # The latest successful list (None before the first one).
        self._listed: frozenset[int] | None = None
        self._app_ids: dict[str, int] = {}
        self._owners: dict[int, frozenset[str]] = {}
        self._display: dict[int, str] = {}
        self._unsupported = False
        self._blind = False
        self._last_list_at: float | None = None
        self._next_list_at: float | None = None

        # App ids that a list taken after their line was read did not name,
        # the app ids of lines that wait for the next list, and the app ids
        # that watched packages left (rule 4), each with when the list that
        # showed it started.
        self._absent: set[int] = set()
        self._wanted: set[int] = set()
        self._left: dict[int, float] = {}

        # Lines judged since the latest list started (see `_Counts`); those
        # judged before it started went with its job.
        self._counts = _Counts()

    # -- State -----------------------------------------------------------------

    @property
    def unattributed(self) -> int:
        """Lines judged without knowing their owner, or judged by an owner map
        that may have been outdated."""
        return self._unattributed

    @property
    def blind(self) -> bool:
        """Whether the last list failed (until the next one succeeds)."""
        return self._blind

    @property
    def listed(self) -> bool:
        """Whether a list succeeded on this device."""
        return self._listed is not None

    def take_messages(self) -> list[tuple[int, str]]:
        """Return the messages so far, as ``(logging level, text)``, and clear them."""
        taken = self._messages[:]
        self._messages.clear()
        return taken

    # -- Lists -----------------------------------------------------------------

    def list_due(self, now: float) -> bool:
        """Whether the regular list (every `RECHECK_INTERVAL` seconds) is due."""
        due = self._next_list_at
        return due is not None and now >= due

    def ready_at(self) -> float:
        """The earliest time the next list may start (`LIST_INTERVAL` pacing)."""
        last = self._last_list_at
        return -math.inf if last is None else last + LIST_INTERVAL

    def list_started(self, now: float) -> ListJob:
        """A list starts now; return the job that runs its commands.

        The app ids that lines asked about so far go with the job: only a
        list that started after a line was read can tell that its app id is
        absent. Lines that ask while the list runs wait for the next one. The
        counts of the lines judged so far go with the job too (see the class).
        A runner that starts the job's first command later sets
        `ListJob.started`; the pacing then counts from that moment.
        """
        self._last_list_at = now
        job = ListJob(unsupported=self._unsupported)
        job.wanted = frozenset(self._wanted)
        self._wanted = set()
        job.counts = self._counts
        self._counts = _Counts()
        return job

    def list_done(self, job: ListJob, now: float) -> None:
        """Take the outcome of a list (a job that is finished).

        A failed list makes the device `blind` until the next list, due
        `RECHECK_INTERVAL` seconds from now; what it was to settle waits for
        the next list. A successful one replaces the owner map, and counts
        what an outdated map may have judged (see the class); the next list is
        due `RECHECK_INTERVAL` seconds after this one started.
        """
        self._unsupported = job.unsupported
        started = job.started
        last = self._last_list_at
        if started is not None and (last is None or started > last):
            self._last_list_at = started
        outcome = job.outcome
        if not isinstance(outcome, Listed):
            reason = "did not finish" if outcome is None else outcome.reason
            self._wanted |= job.wanted  # for the next list
            job.counts.add(self._counts)
            self._counts = job.counts
            self._blind = True
            self._next_list_at = now + RECHECK_INTERVAL
            if not self._failure_told:
                self._failure_told = True
                self._messages.append(
                    (
                        logging.WARNING,
                        f"could not list the packages of {self._serial} (the "
                        f"command {' '.join(job.argv)!r} {reason}); lines whose "
                        "app is not known are counted as unattributed until the "
                        f"next list in {RECHECK_INTERVAL:g} s",
                    )
                )
            return
        during = self._counts
        counts = _Counts()
        counts.add(job.counts)
        counts.add(during)
        started = now if self._last_list_at is None else self._last_list_at
        app_ids = {name: uid % _APP_ID_MODULUS for name, uid in outcome.uids.items()}
        added = self._learn(app_ids, job.wanted, counts, started)
        # The lines judged while the list ran may be newer than it: those of
        # the app ids it did not add go on to the next list.
        during.drop(added)
        self._wanted -= self._listed or frozenset()
        self._blind = False
        self._next_list_at = started + RECHECK_INTERVAL

    def _learn(
        self,
        app_ids: dict[str, int],
        wanted: frozenset[int],
        counts: _Counts,
        started: float,
    ) -> set[int]:
        """Take a successful list that started at ``started``.

        Return the app ids whose lines it added.
        """
        first = self._listed is None
        listed = frozenset(app_ids.values())
        watched, owners, display = _owner_maps(self._names, app_ids)
        old_owners = self._owners
        serial = self._serial
        # App ids whose lines were added already, with the package whose
        # message gave the count and that count.
        counted: dict[int, tuple[str, int]] = {}
        # Rule 4 ends for an app id once a list starts RECHECK_INTERVAL after
        # the one that showed the move; a list taken for a read sooner keeps it.
        left = {
            app_id: moved
            for app_id, moved in self._left.items()
            if started - moved < RECHECK_INTERVAL
        }
        for name in sorted(self._names):
            old = self._app_ids.get(name)
            new = watched.get(name)
            if old is not None and old != new:
                left[old] = started
                self._messages.append(self._moved(name, old, new, counts, counted))
            if (
                new is not None
                and new < _FIRST_APP_ID
                and name not in self._system_told
            ):
                self._system_told.add(name)
                self._messages.append(
                    (logging.WARNING, _system_uid_text(serial, name, new))
                )
        # A watched package under an app id whose lines were judged as not its
        # own: the app id was not listed (absent, or not known yet), listed for
        # packages that are not watched (they were removed and the app id was
        # given again), or its lines looked older than the boundary; or a
        # watched package joined an app id that other watched packages had.
        for app_id in sorted(owners):
            before = old_owners.get(app_id, frozenset())
            joined = owners[app_id] - before
            if not joined or app_id in counted:
                continue
            if before:
                lines = counts.seen.get(app_id, 0)
            else:
                lines = (
                    counts.absent.get(app_id, 0)
                    + counts.others.get(app_id, 0)
                    + counts.early.get(app_id, 0)
                    + counts.unknown.get(app_id, 0)
                )
            counted[app_id] = (min(joined), lines)
            if lines:
                self._unattributed += lines
                self._messages.append(
                    (
                        logging.WARNING,
                        f"{serial}: {min(joined)} appeared under uid {app_id}: "
                        f"{lines} lines judged before it was known are counted "
                        "as unattributed",
                    )
                )
        # An app id that lines asked about again while the list ran may be
        # newer than the list: it waits for the next one instead.
        self._absent = (self._absent | (wanted - self._wanted)) - listed
        self._left = {
            app_id: moved for app_id, moved in left.items() if app_id not in owners
        }
        self._listed = listed
        self._app_ids = watched
        self._owners = owners
        self._display = display
        if first and not self._missing_told:
            self._missing_told = True
            for name in sorted(self._names - watched.keys()):
                self._messages.append(
                    (
                        logging.INFO,
                        f"{name} is not installed on {serial}; its lines are "
                        "matched once a later list shows it",
                    )
                )
        return set(counted)

    def _moved(
        self,
        name: str,
        old: int,
        new: int | None,
        counts: _Counts,
        counted: dict[int, tuple[str, int]],
    ) -> tuple[int, str]:
        """Add the lines of the app id a watched package left; return the message.

        The lines of one app id are added once: a second package that leaves
        it refers to the first one's count. Without lines it is an INFO.
        """
        serial = self._serial
        what = "has a new uid" if new is not None else "is no longer installed"
        if old in counted:
            first, lines = counted[old]
            if not lines:
                return logging.INFO, f"{serial}: {name} {what}"
            return (
                logging.WARNING,
                f"{serial}: {name} {what}: the lines judged with the old uid are "
                f"counted with those of {first}",
            )
        lines = counts.seen.get(old, 0)
        counted[old] = (name, lines)
        if not lines:
            return logging.INFO, f"{serial}: {name} {what}"
        self._unattributed += lines
        return (
            logging.WARNING,
            f"{serial}: {name} {what}: {lines} lines judged with the old uid "
            "since the last list are counted as unattributed",
        )

    # -- Judging ---------------------------------------------------------------

    def needs_list(self, segments: Iterable[Segment], *, running: bool = False) -> bool:
        """Whether a line of ``segments`` needs a newer list for its verdict.

        Nothing is counted; the app ids of those lines are remembered, so that
        the next list that starts after this call can tell which of them are
        absent. While the device is `blind` it is False, unless a list runs
        already (``running``) that the read may wait for: `judge` then decides
        such lines without a list.
        """
        if self._blind and not running:
            return False
        owners = self._owners
        absent = self._absent
        left = self._left
        found = False
        for segment in segments:
            if isinstance(segment, Gap):
                continue
            for entry in segment:
                uid = entry.uid
                if uid is None:
                    continue
                app_id = uid % _APP_ID_MODULUS
                if (
                    app_id in owners
                    or not _FIRST_APP_ID <= app_id < _LAST_APP_ID
                    or app_id in left
                    or app_id in absent
                    or self._explained(entry, app_id)
                ):
                    continue
                if self._judge(entry) is None:
                    self._wanted.add(app_id)
                    found = True
        return found

    def judge(
        self, segments: Iterable[Segment], cause: str | None = None
    ) -> list[Segment]:
        """Return the segments with the lines no condition accepts left out.

        Delivered entries get their display package (the first watched owner
        by name) in ``package``. Gaps stay in place. A line whose verdict
        still needs a newer list or depends on an app no list could check
        (rule 7), and every line of an app id that a watched package left
        (rule 4), is judged as if no package owned it and counted in
        `unattributed`; ``cause`` says why no list answered a line that needs
        one, for the first such line's message. Every other line with a uid
        is counted per app id for the next list (see the class).
        """
        judge = self._judge
        left = self._left
        out: list[Segment] = []
        for segment in segments:
            if isinstance(segment, Gap):
                out.append(segment)
                continue
            kept: list[LogEntry] = []
            for entry in segment:
                uid = entry.uid
                if uid is not None and uid % _APP_ID_MODULUS in left:
                    # Rule 4, before any term is asked: whatever settles the
                    # verdict, the line may be a late one of the package.
                    self._count_unattributed(self._cause(entry, cause))
                    verdict = self._judge_blind(entry)
                elif (verdict := judge(entry)) is None:
                    self._count_unattributed(self._cause(entry, cause))
                    verdict = self._judge_blind(entry)
                else:
                    self._tally(entry)
                if verdict:
                    self._fill(entry)
                    kept.append(entry)
            if kept:
                out.append(kept)
        return out

    def _member(self, entry: LogEntry, names: frozenset[str]) -> bool | None:
        uid = entry.uid
        if uid is None:
            return False
        app_id = uid % _APP_ID_MODULUS
        owners = self._owners.get(app_id)
        if owners is not None:
            return not names.isdisjoint(owners)
        if not _FIRST_APP_ID <= app_id < _LAST_APP_ID:
            return False
        if app_id in self._absent:
            # Rule 7: no list is taken for it (`needs_list` skips it), so a
            # line that is not older than the boundary stays undecided.
            return False if self._before_list(entry) else None
        if self._explained(entry, app_id):
            return False
        return None

    def _tally(self, entry: LogEntry) -> None:
        """Count a decided line under the rule that decided its app id."""
        uid = entry.uid
        if uid is None:
            return
        app_id = uid % _APP_ID_MODULUS
        listed = self._listed
        counts = self._counts
        if app_id in self._owners:
            tally = counts.seen
        elif listed is not None and app_id in listed:
            tally = counts.others  # also a system uid, for a later owner
        elif not _FIRST_APP_ID <= app_id < _LAST_APP_ID:
            # Rule 3: a later list may show a watched package under this
            # (system) uid.
            tally = counts.unknown
        elif self._before_list(entry):
            tally = counts.early
        elif app_id in self._absent:
            tally = counts.absent
        else:  # no list explains it; a term without packages settled the line
            tally = counts.unknown
        tally[app_id] = tally.get(app_id, 0) + 1

    def _explained(self, entry: LogEntry, app_id: int) -> bool:
        """Whether the latest list explains an app id that no watched package has.

        It does when the list names the app id, or when the line was logged
        before the list began (the app was removed before that).
        """
        listed = self._listed
        return listed is not None and (app_id in listed or self._before_list(entry))

    def _before_list(self, entry: LogEntry) -> bool:
        """Whether a list succeeded and ``entry`` was logged before `boundary`."""
        boundary = self.boundary
        return (
            boundary is not None
            and self._listed is not None
            and entry.logged_at.timestamp() < boundary
        )

    def _cause(self, entry: LogEntry, cause: str | None) -> str:
        """Why ``entry`` (a line `judge` could not decide) has no verdict."""
        uid = entry.uid
        if uid is not None and uid % _APP_ID_MODULUS in self._left:
            return "its uid belonged to a watched package until a recent package list"
        if uid is not None and uid % _APP_ID_MODULUS in self._absent:
            return (
                "the app of its uid could not be checked: the package list taken "
                "after the line was read did not name the uid"
            )
        if cause is not None:
            return cause
        if self._blind:
            return "the last package list failed"
        return "the package list taken for its read no longer names its uid"

    def _count_unattributed(self, cause: str) -> None:
        self._unattributed += 1
        if self._unattributed_told:
            return
        self._unattributed_told = True
        self._messages.append(
            (
                logging.WARNING,
                f"{self._serial}: lines whose app could not be determined are "
                f"counted as unattributed (first: {cause})",
            )
        )

    def _fill(self, entry: LogEntry) -> None:
        """Set the display package of an entry that is about to be delivered."""
        uid = entry.uid
        if uid is not None:
            name = self._display.get(uid % _APP_ID_MODULUS)
            if name is not None:
                # Nobody has seen the entry yet, so filling the display field of
                # the frozen record cannot be observed from outside.
                object.__setattr__(entry, "package", name)


def dump_judge(
    condition: Condition, uids: dict[str, int], serial: str = ""
) -> tuple[Callable[[list[LogEntry]], list[LogEntry]], list[tuple[int, str]]]:
    """The filter a dump applies, from the list read just before it.

    The verdict is two-valued: an app id that no watched package has in the
    list belongs to none (a dump takes no second list). Delivered entries get
    their display package in ``package``.

    Args:
        condition: The dump's condition (it has a `Package` term).
        uids: Package name to uid, as `Listed` holds it.
        serial: The device's serial, for the messages.

    Returns:
        The filter (a list of entries in, the kept entries out) and the
        messages, as ``(logging level, text)``: an INFO for each watched
        package that is not installed, a WARNING for each that runs under a
        system uid.
    """
    names = condition._package_names()  # noqa: SLF001
    app_ids = {name: uid % _APP_ID_MODULUS for name, uid in uids.items()}
    watched, owners, display = _owner_maps(names, app_ids)
    messages: list[tuple[int, str]] = [
        (
            logging.INFO,
            f"{name} is not installed on {serial}; the dump has no lines of it",
        )
        for name in sorted(names - watched.keys())
    ]
    messages.extend(
        (logging.WARNING, _system_uid_text(serial, name, app_id))
        for name, app_id in watched.items()
        if app_id < _FIRST_APP_ID
    )

    def member(entry: LogEntry, wanted: frozenset[str]) -> bool:
        uid = entry.uid
        if uid is None:
            return False
        found = owners.get(uid % _APP_ID_MODULUS)
        return found is not None and not wanted.isdisjoint(found)

    judge = condition._compile_membership(member)  # noqa: SLF001

    def keep(entries: list[LogEntry]) -> list[LogEntry]:
        kept: list[LogEntry] = []
        for entry in entries:
            if judge(entry):
                uid = entry.uid
                if uid is not None:
                    name = display.get(uid % _APP_ID_MODULUS)
                    if name is not None:
                        object.__setattr__(entry, "package", name)
                kept.append(entry)
        return kept

    return keep, messages


def _no_owner(_entry: LogEntry, _names: frozenset[str]) -> bool:
    return False
