"""One run of the list commands, filled in by whoever runs them."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .commands import (
    DUMPSYS_PACKAGES_ARGV,
    PM_LIST_ARGV,
    Failed,
    Fallback,
    Listed,
    read_dumpsys_packages,
    read_pm_list,
)

if TYPE_CHECKING:
    from collections.abc import Iterable


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
