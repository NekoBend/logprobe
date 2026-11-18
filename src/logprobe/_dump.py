"""Read what a device's logcat holds right now and return it as entries.

With a condition on the app (``Package``), the device's package list is read
once before ``logcat -d`` (``pm list packages -U``, or ``dumpsys package
packages`` where ``-U`` is unknown), and the lines are judged by it alone.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Final

from logprobe import _adb, _marks
from logprobe._attribution import Listed, ListJob, dump_judge
from logprobe._errors import LogprobeError, command_failed
from logprobe._feed import Feeder

if TYPE_CHECKING:
    from collections.abc import Callable

    from logprobe._adb import ShellResult
    from logprobe._conditions import Condition
    from logprobe._entry import LogEntry
    from logprobe._feed import Chunk

    #: Keeps the entries a condition on the app accepts, with their package.
    type Keep = Callable[[list[LogEntry]], list[LogEntry]]

#: Seconds without any byte from the device after which a dump gives up.
#: ``logcat -d`` prints from memory and exits, so a connection this quiet is
#: stuck; the limit is per wait, not for the whole dump, which may be long.
IDLE_TIMEOUT: Final = 30.0
#: How many bytes of the command's stderr go into an error.
_STDERR_TAIL: Final = 2000
_LOG = logging.getLogger(__name__)


def _never() -> bool:
    """A ``cancelled`` callback that never cancels.

    Passing any callback makes the adb layer cut every wait into short slices
    (so Ctrl-C is delivered promptly on Windows too); nothing here cancels.
    """
    return False


def _open(
    address: _adb.ServerAddress, serial: str, argv: list[str]
) -> _adb.ShellStream:
    """Open the shell connection that runs ``argv`` on the device."""
    return _adb.open_shell(address, serial, argv, cancelled=_never)


def _decode_tail(tail: bytearray) -> str:
    """Decode a byte tail, dropping a multi-byte character the cut split."""
    start = 0
    while start < min(3, len(tail)) and 0x80 <= tail[start] <= 0xBF:
        start += 1
    return bytes(tail[start:]).decode("utf-8", "replace")


def needs_list(condition: Condition | None) -> bool:
    """Whether the dump must read the package list first (a ``Package`` term)."""
    return condition is not None and condition._has_package()  # noqa: SLF001


def take_ran(job: ListJob, ran: ShellResult | TimeoutError) -> None:
    """Give ``job`` what running its command gave: the result, or the timeout.

    A command that took longer than ``_marks.COMMAND_LIMIT`` ends the job as
    failed, with what it had written to stderr by then.
    """
    if isinstance(ran, TimeoutError):
        stderr = ran.stderr if isinstance(ran, _adb.CommandTimeoutError) else b""
        job.fail(f"did not finish within {_marks.COMMAND_LIMIT:g} seconds", stderr)
    else:
        job.take(ran.exit_status, ran.stdout, ran.stderr)


def package_filter(serial: str, condition: Condition, job: ListJob) -> Keep:
    """The filter of a dump from its finished list job; logs the job's messages.

    Raises:
        LogprobeError: ``device_command_failed`` when the list failed;
            ``details`` has ``serial``, ``command``, ``exit_status`` and
            ``stderr`` (its last lines).
    """
    outcome = job.outcome
    if not isinstance(outcome, Listed):
        reason = "did not finish" if outcome is None else outcome.reason
        exit_status = None if outcome is None else outcome.exit_status
        raise command_failed(
            serial, list(job.argv), exit_status, job.stderr, outcome=reason
        )
    keep, messages = dump_judge(condition, outcome.uids, serial)
    for level, message in messages:
        _LOG.log(level, message)
    return keep


def _take_list(address: _adb.ServerAddress, serial: str) -> ListJob:
    """Read the device's package list; each command gets ``COMMAND_LIMIT``."""
    job = ListJob()
    while not job.finished:
        ran: ShellResult | TimeoutError
        try:
            ran = _adb.run_shell(
                address, serial, job.argv, _marks.COMMAND_LIMIT, _never
            )
        except TimeoutError as error:
            ran = error
        take_ran(job, ran)
    return job


def idle_timeout() -> TimeoutError:
    """The error for a device that sent nothing for ``IDLE_TIMEOUT`` seconds."""
    return TimeoutError(f"the device sent no output for {IDLE_TIMEOUT:g} seconds")


class Collector:
    """What a dump has read so far, and the result once the command ended.

    The blocking and the asyncio dump feed it their output, so the two keep
    the same entries and map the exit status to the same error. How they
    read (time limits, protocol errors) stays with each of them.

    Args:
        serial: The device's serial number, for the entries and the errors.
        condition: A condition the entries must match.
        keep: With a condition on the app, the filter from the package list
            (`package_filter`); the feeder then passes every line to it.
    """

    def __init__(
        self, serial: str, condition: Condition | None, keep: Keep | None = None
    ) -> None:
        self._serial = serial
        self._feeder = Feeder(serial, condition=condition)
        self._keep = keep
        self._entries: list[LogEntry] = []
        self._stderr = bytearray()

    def take(self, kind: str, data: bytes) -> None:
        """Take one ``("stdout", bytes)`` or ``("stderr", bytes)`` event."""
        if kind == "stdout":
            self._collect(self._feeder.feed(data))
        else:
            self._stderr += data
            del self._stderr[:-_STDERR_TAIL]

    def finish(self, status: int | None) -> list[LogEntry]:
        """Return the entries, given the command's exit status.

        The final line without a line feed is kept only on status 0.

        Raises:
            LogprobeError: ``device_lost`` if ``status`` is None (the connection
                closed without an exit status) or ``logcat_failed`` if it is
                not 0.
        """
        serial = self._serial
        if status is None:
            raise LogprobeError(
                "device_lost",
                f"the connection to {serial} closed before logcat finished",
                {"serial": serial},
            )
        if status != 0:
            raise LogprobeError(
                "logcat_failed",
                f"logcat on {serial} exited with status {status}",
                {
                    "serial": serial,
                    "exit_status": status,
                    "stderr": _decode_tail(self._stderr),
                },
            )
        self._collect(self._feeder.finish())
        self._feeder.tell_later_gaps()
        return self._entries

    def _collect(self, chunks: list[Chunk]) -> None:
        keep = self._keep
        for chunk in chunks:
            for segment in chunk.segments:
                if isinstance(segment, list):
                    self._entries.extend(segment if keep is None else keep(segment))


def run_dump(
    address: _adb.ServerAddress,
    serial: str,
    condition: Condition | None,
    tail: int | None,
) -> list[LogEntry]:
    """Run ``logcat -d`` on the device and return the entries ``condition`` keeps.

    A condition on the app reads the package list first.

    Raises:
        TimeoutError: If the device sent nothing for ``IDLE_TIMEOUT`` seconds.
        LogprobeError: ``adb_error`` (no ``shell_v2``, or a protocol violation),
            ``logcat_failed`` (non-zero exit status), ``device_lost`` (the
            connection closed without an exit status) or
            ``device_command_failed`` (the package list failed).
    """
    argv = _adb.logcat_argv(dump=True, tail=tail, t=None)
    _adb.require_shell_v2(address, serial, cancelled=_never)
    keep: Keep | None = None
    if condition is not None and needs_list(condition):
        keep = package_filter(serial, condition, _take_list(address, serial))
    collector = Collector(serial, condition, keep)
    try:
        with _open(address, serial, argv) as stream:
            stream.set_timeout(IDLE_TIMEOUT)
            while (event := stream.read(_never)) is not None:
                collector.take(*event)
            status = stream.exit_status
    except TimeoutError:
        raise idle_timeout() from None
    return collector.finish(status)
