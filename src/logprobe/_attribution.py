"""Package attribution: deciding which log lines belong to watched packages.

A log line carries the uid of the process that wrote it. To tell whether the
line belongs to a watched package, the uid has to be mapped to package names,
and the device is the only source for that mapping (``dumpsys package <name>``).
This module holds the pure part of that work. It does no I/O, starts no
threads and never reads a clock: the caller passes the current time (any
monotonic float, in seconds) to every call that needs it, runs the lookups
itself and hands the answers back.

How a caller drives a `PackageAttributor`::

    attributor = PackageAttributor(condition)
    # Before reading: learn the uids of the watched packages.
    while (lookup := attributor.next_lookup(now)) is not None:
        uid = parse_package_uid(run(lookup.command), lookup.package)
        attributor.lookup_done(lookup, uid, now)
    # While reading: pass every read in, get decided segments out.
    for segment in attributor.admit(segments, now):
        deliver(segment)
    # Between reads: look at ``next_deadline()``, call ``next_lookup`` and
    # ``expire``, and send what they return on.
    # At the end:
    for segment in attributor.close():
        deliver(segment)

Segments are what a reader makes of one read: lists of entries, and `Gap`
records, in the order they happened. The attributor keeps that order, also for
the lines it has to hold back.

Verdicts are three-valued (see ``Condition._compile_membership``): a line is
held back only while its verdict depends on a uid whose owner is not known yet.
Everything held back sits in one first-in-first-out queue, so a line that is
already decided waits behind an undecided one. A held line is released with
its real verdict as soon as the owner is known. If the answer does not come in
time, or the queue grows past its limits, the oldest lines are judged as if no
package owned them and counted in `PackageAttributor.unattributed`.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ._outbox import MARKER_BYTES
from ._records import Gap

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator

    from ._conditions import Condition
    from ._entry import LogEntry

__all__ = [
    "CHUNK_CHARGE",
    "CHUNK_ENTRIES",
    "HOLD_CHARGE",
    "HOLD_LINES",
    "HOLD_SECONDS",
    "LOOKUP_INTERVAL",
    "NEGATIVE_LIFETIME",
    "RECHECK_INTERVAL",
    "Lookup",
    "PackageAttributor",
    "Segment",
    "parse_package_uid",
]

#: One piece of a reader's output: a list of entries, or a gap.
type Segment = list[LogEntry] | Gap

#: Longest time a line is held back before it is judged without package names.
HOLD_SECONDS = 2.0
#: Most lines held back at once; a gap counts as one line.
HOLD_LINES = 10_000
#: Most charge (input bytes) held back at once.
HOLD_CHARGE = 4 * 1024 * 1024
#: Entries in one output list, at most.
CHUNK_ENTRIES = 2_048
#: Charge of one output list, at most (a single entry may exceed it alone).
CHUNK_CHARGE = 64 * 1024
#: Least time between two lookups of the same package.
LOOKUP_INTERVAL = 0.5
#: How often a known uid is looked up again, to notice a reinstall.
RECHECK_INTERVAL = 30.0
#: How long an app id that belongs to no watched package stays remembered.
NEGATIVE_LIFETIME = 30.0

# Uids are app_id + 100000 * user. App ids from 10000 up to (excluding) 20000
# are those of installed apps; the ranges around them hold system services,
# sandboxes and isolated processes that no watched package can own.
_APP_ID_MODULUS = 100_000
_FIRST_APP_ID = 10_000
_LAST_APP_ID = 20_000


@dataclass(frozen=True, slots=True)
class Lookup:
    """A request to read the uid of one package from the device.

    Run `command` on the device, pass its output to `parse_package_uid` and
    give the result back with `PackageAttributor.lookup_done`.

    Attributes:
        package: The package name.
        number: Counts the lookups of one attributor; makes each request unique.
        in_round: Whether the lookup belongs to a search for an unknown uid.
    """

    package: str
    number: int
    in_round: bool = False

    @property
    def command(self) -> str:
        """The shell command that prints the package record."""
        return f"dumpsys package {self.package}"


_USER_ID = re.compile(r"(?:userId|appId)=(\d+)(?:\s|$)")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def parse_package_uid(output: str, package: str) -> int | None:
    """Read the uid of ``package`` from the output of ``dumpsys package <name>``.

    The output holds one record per package whose name matches, and often
    several unrelated records. A record starts with a line ``Package [<name>]``
    (optionally followed by a hash in parentheses and a colon)
    and covers the more deeply indented lines that follow. Only the record of
    exactly ``package`` is read; a name that merely shares a prefix, or a
    package that is mentioned inside another record, is ignored. The uid is the
    first ``userId=`` (Android 7) or ``appId=`` (Android 16) line of that
    record. If the output holds several records of the package, the first one
    that has a uid wins.

    Returns:
        The number, or None when the output has no such record or the record
        has no uid. The number is returned as printed (not reduced to an app
        id).
    """
    header = re.compile(rf"Package \[{re.escape(package)}\](?: \([^()]*\))?:?")
    base: int | None = None
    for line in output.splitlines():
        text = line.strip()
        if not text:
            continue
        depth = _indent(line)
        if base is not None and depth <= base:
            base = None
        if base is None:
            if header.fullmatch(text) is not None:
                base = depth
            continue
        found = _USER_ID.match(text)
        if found is not None:
            return int(found.group(1))
    return None


class _Held:
    """One segment in the hold queue: a list of entries (from ``pos``) or a gap."""

    __slots__ = ("at", "entries", "gap", "per_line", "pos", "scan")

    def __init__(
        self,
        entries: list[LogEntry] | None,
        gap: Gap | None,
        per_line: int,
        at: float,
    ) -> None:
        self.entries = entries
        self.gap = gap
        self.pos = 0
        self.scan = 0  # entries before this index were checked for unknown app ids
        self.per_line = per_line
        self.at = at


class _Output:
    """Collects decided segments in lists of bounded size, with their charge."""

    def __init__(self) -> None:
        self.segments: list[Segment] = []
        self.charges: list[int] = []
        self._entries: list[LogEntry] | None = None
        self._charge = 0

    def entry(self, entry: LogEntry, charge: int) -> None:
        current = self._entries
        if current is not None and (
            len(current) >= CHUNK_ENTRIES or self._charge + charge > CHUNK_CHARGE
        ):
            self._close()
            current = None
        if current is None:
            current = self._entries = []
            self.segments.append(current)
        current.append(entry)
        self._charge += charge

    def gap(self, gap: Gap) -> None:
        self._close()
        self.segments.append(gap)
        self.charges.append(MARKER_BYTES)

    def finish(self) -> None:
        self._close()

    def _close(self) -> None:
        if self._entries is not None:
            self.charges.append(self._charge)
            self._entries = None
            self._charge = 0


class PackageAttributor:
    """Decides which lines belong to watched packages, holding back what it must.

    Args:
        condition: The condition to judge lines with. Its `Package` terms are
            decided by the owners of the line's uid.
        packages: The packages to look up; the packages named by
            ``condition.packages()`` when omitted.
        hold_seconds: How long a line may be held back.
        hold_lines: How many lines (gaps included) may be held back.
        hold_charge: How much charge may be held back.

    The limits are the arguments' defaults; they are parameters for tests.

    When a lookup fails, the app ids it was meant to resolve are judged without
    owners until `NEGATIVE_LIFETIME` has passed: their lines are decided as if
    they belonged to no watched package and counted in ``unattributed``. Then
    they are looked up again.

    Attributes:
        warnings: Texts for the user, in the order they arose. The caller may
            read and clear the list (see `take_warnings`).
        last_charges: The charge of each segment the last call returned,
            parallel to the returned list. A gap is charged
            ``MARKER_BYTES``; a list of entries is charged the average charge
            of the read its lines came from.
    """

    def __init__(
        self,
        condition: Condition,
        packages: Iterable[str] | None = None,
        *,
        hold_seconds: float = HOLD_SECONDS,
        hold_lines: int = HOLD_LINES,
        hold_charge: int = HOLD_CHARGE,
    ) -> None:
        names = sorted(
            set(condition.packages() if packages is None else packages)
            if condition._has_package()  # noqa: SLF001
            else ()
        )
        self._names = names
        self._judge: Callable[[LogEntry], bool | None] = condition._compile_membership(  # noqa: SLF001
            self._member
        )
        self._judge_blind: Callable[[LogEntry], bool | None] = (
            condition._compile_membership(  # noqa: SLF001
                _no_owner
            )
        )
        self._hold_seconds = hold_seconds
        self._hold_lines = hold_lines
        self._hold_charge = hold_charge

        self.warnings: list[str] = []
        self.last_charges: list[int] = []

        self._now = 0.0
        self._closed = False
        self._unattributed = 0
        self._held: deque[_Held] = deque()
        self._lines = 0
        self._charge = 0

        # What is known about the packages.
        self._app_ids: dict[str, int] = {}
        self._owners: dict[int, frozenset[str]] = {}
        self._display: dict[int, str] = {}
        # Lines judged through the owner map, per app id (running total), the
        # total each package had at its last successful check, and the stretches
        # of those totals that were already added to ``unattributed``.
        self._seen: dict[int, int] = {}
        self._mark: dict[str, int] = {}
        self._added: dict[int, list[tuple[int, int]]] = {}
        self._last_judged: LogEntry | None = None
        self._last_try: dict[str, float] = {}
        self._next_check: dict[str, float] = {}

        # App ids with no owner among the watched packages, and app ids whose
        # search failed; both are forgotten after a while.
        self._negative: set[int] = set()
        self._blind: set[int] = set()
        self._forget_at: float | None = None

        # The search for the owners of unknown app ids: every package is looked
        # up once; the app ids still without an owner afterwards belong to none.
        self._round: deque[str] | None = deque(names) if names else None
        self._round_begun = False
        self._round_failed = False
        self._round_ids: set[int] = set()
        self._next_ids: set[int] = set()

        self._outstanding: Lookup | None = None
        self._lookups = 0

    # -- Counters ------------------------------------------------------------

    @property
    def unattributed(self) -> int:
        """Lines judged without knowing their owner, or judged by an owner map
        that turned out to be outdated."""
        return self._unattributed

    @property
    def held_lines(self) -> int:
        """Lines held back now; a gap counts as one."""
        return self._lines

    @property
    def held_charge(self) -> int:
        """The charge of the lines held back now."""
        return self._charge

    def take_warnings(self) -> list[str]:
        """Return the warnings so far and clear the list."""
        taken = self.warnings[:]
        self.warnings.clear()
        return taken

    # -- The driving calls ---------------------------------------------------

    def admit(
        self, segments: Iterable[Segment], now: float, charge: int | None = None
    ) -> list[Segment]:
        """Take one read's segments; return the segments that are decided.

        Args:
            segments: Lists of entries and gaps, in the order they happened.
            now: The current time.
            charge: The charge of the whole read (its input bytes); by default
                an estimate from the UTF-8 length of each line plus a newline.

        Returns:
            The segments that can be delivered now, in order, each list at most
            ``CHUNK_ENTRIES`` entries long. Entries that no condition accepts
            are left out.

        Raises:
            RuntimeError: `close` was called.
        """
        if self._closed:
            msg = "the attributor is closed"
            raise RuntimeError(msg)
        self._enter(now)
        segments = list(segments)
        count = sum(len(s) for s in segments if not isinstance(s, Gap))
        if count:
            if charge is None:
                charge = sum(
                    len(e.raw.encode("utf-8", "replace")) + 1
                    for s in segments
                    if not isinstance(s, Gap)
                    for e in s
                )
            per_line = max(1, charge // count)
        else:
            per_line = 0
        for segment in segments:
            if isinstance(segment, Gap):
                self._held.append(_Held(None, segment, MARKER_BYTES, now))
                self._lines += 1
                self._charge += MARKER_BYTES
            elif segment:
                self._held.append(_Held(segment, None, per_line, now))
                self._lines += len(segment)
                self._charge += per_line * len(segment)
        return self._collect(now)

    def next_lookup(self, now: float) -> Lookup | None:
        """Return the next lookup to run, or None.

        Lookups run one at a time: while one is outstanding, the answer is
        awaited. A package is not looked up twice within ``LOOKUP_INTERVAL``.
        Unknown packages come first (those of a search for an unknown uid),
        then known uids that are due for a new check.
        """
        self._enter(now)
        if self._closed or self._outstanding is not None:
            return None
        if self._round:
            for name in self._round:
                if self._may_try(name, now):
                    self._round.remove(name)
                    self._round_begun = True
                    return self._start(name, now, in_round=True)
        due = [
            (when, name)
            for name, when in self._next_check.items()
            if when <= now and self._may_try(name, now)
        ]
        if due:
            return self._start(min(due)[1], now, in_round=False)
        return None

    def lookup_done(
        self,
        lookup: Lookup,
        result: int | None,
        now: float,
        *,
        failed: bool = False,
    ) -> list[Segment]:
        """Take the answer of a lookup; return the segments it decided.

        Args:
            lookup: The request, as `next_lookup` returned it. An answer to
                any other request is ignored.
            result: What `parse_package_uid` read: the uid, or None when the
                device has no such package.
            now: The current time.
            failed: The lookup could not be run (it timed out or the command
                failed). The previous answer for the package stays, and lines
                of an app id that stay unresolved because of it are judged
                without package names.
        """
        if self._closed or lookup is not self._outstanding:
            return []
        self._outstanding = None
        self._enter(now)
        name = lookup.package
        if failed:
            if lookup.in_round:
                self._round_failed = True
            if name in self._next_check:
                self._next_check[name] = now + RECHECK_INTERVAL
        else:
            self._record(
                name, None if result is None else result % _APP_ID_MODULUS, now
            )
        if lookup.in_round and not self._round:
            self._finish_round()
        return self._collect(now)

    def expire(self, now: float) -> list[Segment]:
        """Judge the lines held back for too long without package names.

        Returns the segments that became decided (also those that were
        waiting behind the expired lines).
        """
        self._enter(now)
        if self._closed:
            return []
        return self._collect(now)

    def next_deadline(self) -> float | None:
        """The earliest time the caller should call in again, or None.

        That is the first of: the time the oldest held line expires, the time
        a wanted lookup may start, and the time a known uid is due for a new
        check. A time that has already passed means "now". None means there is
        nothing to wait for.
        """
        if self._closed:
            return None
        times: list[float] = []
        if self._held:
            times.append(self._held[0].at + self._hold_seconds)
        if self._outstanding is None:
            if self._round:
                times.extend(self._ready_at(name) for name in self._round)
            times.extend(
                max(when, self._ready_at(name))
                for name, when in self._next_check.items()
            )
        return min(times) if times else None

    def close(self) -> Iterator[Segment]:
        """Release everything held back and stop.

        Lines whose owner is still unknown are judged without package names
        and counted in `unattributed`. Every call after this one returns
        nothing; `admit` raises.
        """
        if self._closed:
            self.last_charges = []
            return iter(())
        self._closed = True
        self._outstanding = None
        out = _Output()
        self._drain(self._now, out, closing=True)
        out.finish()
        self.last_charges = out.charges
        return iter(out.segments)

    # -- The judging ---------------------------------------------------------

    def _member(self, entry: LogEntry, names: frozenset[str]) -> bool | None:
        uid = entry.uid
        if uid is None or not self._names:
            return False
        app_id = uid % _APP_ID_MODULUS
        if app_id in self._round_ids or app_id in self._next_ids:
            # A search is under way: the owners found so far may be only some
            # of them, so the verdict waits until the search has ended.
            return None
        owners = self._owners.get(app_id)
        if owners is not None:
            if entry is not self._last_judged:
                self._last_judged = entry
                self._seen[app_id] = self._seen.get(app_id, 0) + 1
            return not names.isdisjoint(owners)
        if not _FIRST_APP_ID <= app_id < _LAST_APP_ID or app_id in self._negative:
            return False
        if app_id not in self._blind:
            self._want(app_id)
        return None

    def _collect(self, now: float) -> list[Segment]:
        out = _Output()
        self._drain(now, out, closing=False)
        out.finish()
        self.last_charges = out.charges
        return out.segments

    def _drain(self, now: float, out: _Output, *, closing: bool) -> None:
        held = self._held
        if not held:
            return
        judge = self._judge
        blind_ids = self._blind
        lines = self._lines
        charge = self._charge
        limit_lines = self._hold_lines
        limit_charge = self._hold_charge
        while held:
            head = held[0]
            if head.gap is not None:
                out.gap(head.gap)
                held.popleft()
                lines -= 1
                charge -= MARKER_BYTES
                continue
            entries = head.entries
            assert entries is not None  # noqa: S101  (a held item is a gap or entries)
            per_line = head.per_line
            expires = head.at + self._hold_seconds
            i = head.pos
            end = len(entries)
            stalled = False
            while i < end:
                entry = entries[i]
                verdict = judge(entry)
                if verdict is None:
                    uid = entry.uid
                    if (
                        closing
                        or lines > limit_lines
                        or charge > limit_charge
                        or expires <= now
                        or (
                            blind_ids
                            and uid is not None
                            and uid % _APP_ID_MODULUS in blind_ids
                        )
                    ):
                        self._unattributed += 1
                        verdict = self._judge_blind(entry)
                    else:
                        stalled = True
                        break
                if verdict:
                    self._fill(entry)
                    out.entry(entry, per_line)
                i += 1
                lines -= 1
                charge -= per_line
            if stalled:
                head.pos = i
                self._register_backlog()
                break
            held.popleft()
        self._lines = lines
        self._charge = charge

    def _register_backlog(self) -> None:
        """Note every unknown app id among the held lines, so one search finds all.

        The queue is judged only up to its first undecided line; without this,
        each unknown app id behind it would start a search of its own, one
        after the other. Every held line is looked at once: lines that were
        looked at before form the front of the queue, so the walk goes from the
        back and stops at the first one already seen.
        """
        for item in reversed(self._held):
            entries = item.entries
            if entries is None:
                continue
            start = max(item.scan, item.pos)
            end = len(entries)
            if start >= end:
                break
            item.scan = end
            for index in range(start, end):
                uid = entries[index].uid
                if uid is None:
                    continue
                app_id = uid % _APP_ID_MODULUS
                if (
                    _FIRST_APP_ID <= app_id < _LAST_APP_ID
                    and app_id not in self._owners
                    and app_id not in self._negative
                    and app_id not in self._blind
                ):
                    self._want(app_id)

    # -- The knowledge about uids -------------------------------------------

    def _fill(self, entry: LogEntry) -> None:
        """Set the display package of an entry that is about to be delivered."""
        uid = entry.uid
        if uid is not None:
            name = self._display.get(uid % _APP_ID_MODULUS)
            if name is not None:
                # Nobody has seen the entry yet, so filling the display field of
                # the frozen record cannot be observed from outside.
                object.__setattr__(entry, "package", name)

    def _enter(self, now: float) -> None:
        self._now = now
        if self._forget_at is None:
            self._forget_at = now + NEGATIVE_LIFETIME
        elif now >= self._forget_at:
            self._negative.clear()
            self._blind.clear()
            self._forget_at = now + NEGATIVE_LIFETIME

    def _ready_at(self, name: str) -> float:
        tried = self._last_try.get(name)
        return self._now if tried is None else tried + LOOKUP_INTERVAL

    def _may_try(self, name: str, now: float) -> bool:
        tried = self._last_try.get(name)
        return tried is None or now >= tried + LOOKUP_INTERVAL

    def _start(self, name: str, now: float, *, in_round: bool) -> Lookup:
        self._lookups += 1
        self._last_try[name] = now
        self._outstanding = Lookup(name, self._lookups, in_round)
        return self._outstanding

    def _want(self, app_id: int) -> None:
        """Note a line with an app id of unknown owner; a search will find it."""
        if app_id in self._round_ids or app_id in self._next_ids:
            return
        if self._round is None:
            if not self._names:
                self._negative.add(app_id)
                return
            self._round = deque(self._names)
            self._round_begun = False
            self._round_failed = False
            self._round_ids = {app_id}
        elif self._round_begun:
            self._next_ids.add(app_id)
        else:
            self._round_ids.add(app_id)

    def _finish_round(self) -> None:
        unresolved = self._blind if self._round_failed else self._negative
        unresolved.update(i for i in self._round_ids if i not in self._owners)
        # Every package was looked up, so ids that got owners meanwhile are done.
        self._round_ids = {
            i
            for i in self._next_ids
            if i not in self._owners
            and i not in self._negative
            and i not in self._blind
        }
        self._next_ids = set()
        self._round_failed = False
        self._round_begun = False
        self._round = deque(self._names) if self._round_ids else None

    def _record(self, name: str, app_id: int | None, now: float) -> None:
        """Take the app id found for a package (None: the package is not there)."""
        old = self._app_ids.get(name)
        if old is not None and old != app_id:
            since = self._seen.get(old, 0) - self._mark.get(name, 0)
            self._unattributed += self._count_new(old, self._mark.get(name, 0))
            self.warnings.append(
                f"{name} has a new uid"
                if app_id is not None
                else f"{name} is no longer installed"
            )
            self.warnings[-1] += (
                f": {since} lines judged with the old uid since the last check are "
                "counted as unattributed"
            )
        if app_id is None:
            self._app_ids.pop(name, None)
            self._next_check.pop(name, None)
            self._mark.pop(name, None)
        else:
            self._app_ids[name] = app_id
            self._mark[name] = self._seen.get(app_id, 0)
            self._next_check[name] = now + RECHECK_INTERVAL
            self._negative.discard(app_id)
            self._blind.discard(app_id)
            if app_id < _FIRST_APP_ID and old != app_id:
                self.warnings.append(
                    f"{name} runs under the system uid {app_id}: every process of "
                    "that uid is taken as belonging to it"
                )
        owners: dict[int, list[str]] = {}
        for package, owned in sorted(self._app_ids.items()):
            owners.setdefault(owned, []).append(package)
        self._owners = {key: frozenset(value) for key, value in owners.items()}
        self._display = {key: value[0] for key, value in owners.items()}

    def _count_new(self, app_id: int, start: int) -> int:
        """Count the lines of ``app_id`` after total ``start`` not yet added.

        Co-owners of one uid are checked at different times, so the stretches
        they report overlap; each line is added to ``unattributed`` only once.
        """
        end = self._seen.get(app_id, 0)
        if end <= start:
            return 0
        merged: list[tuple[int, int]] = []
        new = end - start
        low, high = start, end
        for a, b in self._added.get(app_id, []):
            if b < low or a > high:
                merged.append((a, b))
                continue
            new -= min(b, end) - max(a, start)
            low, high = min(a, low), max(b, high)
        merged.append((low, high))
        merged.sort()
        self._added[app_id] = merged
        return new


def _no_owner(_entry: LogEntry, _names: frozenset[str]) -> bool:
    return False
