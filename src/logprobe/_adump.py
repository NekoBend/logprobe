"""Read what a device's logcat holds right now, on asyncio.

The counterpart of :mod:`logprobe._dump` for code that runs on an event loop.
It feeds the same :class:`~logprobe._dump.Collector`, so both keep the same
entries and map the exit status to the same error. No thread, executor or
process is started.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from logprobe import _aadb, _adb, _astream, _dump, _marks
from logprobe._attribution import ListJob

if TYPE_CHECKING:
    from logprobe._adb import ShellResult
    from logprobe._conditions import Condition
    from logprobe._entry import LogEntry


async def _open(
    address: _adb.ServerAddress, serial: str, argv: list[str]
) -> _aadb.AsyncShellStream:
    """Open the shell connection that runs ``argv`` on the device."""
    return await _aadb.aopen_shell(address, serial, argv)


async def _take_list(address: _adb.ServerAddress, serial: str) -> ListJob:
    """Read the device's package list (the blocking `_dump._take_list`)."""
    job = ListJob()
    while not job.finished:
        ran: ShellResult | TimeoutError
        try:
            ran = await _aadb.arun_shell(
                address, serial, job.argv, _marks.COMMAND_LIMIT
            )
        except TimeoutError as error:
            ran = error
        _dump.take_ran(job, ran)
    return job


async def arun_dump(
    address: _adb.ServerAddress,
    serial: str,
    condition: Condition | None,
    tail: int | None,
) -> list[LogEntry]:
    """Run ``logcat -d`` on the device and return the entries ``condition`` keeps.

    Each network read waits at most ``_dump.IDLE_TIMEOUT`` seconds for bytes,
    as in the blocking dump; there is no limit for the whole dump. Output is
    taken as the asyncio stream takes it: what one network read brought, up
    to about 8 KiB, is fed in one piece, and then the task lets the event
    loop run other tasks. A batch can exceed that by less than the part of one
    packet that one network read brought (up to 64 KiB), which is never
    split. A condition on the app reads the package list first, as in the
    blocking dump. Cancelling the task closes the connection (also that of a
    list command) and lets ``CancelledError`` pass.

    Raises:
        TimeoutError: If the device sent nothing for ``_dump.IDLE_TIMEOUT``
            seconds.
        LogprobeError: As :func:`logprobe._dump.run_dump`.
    """
    argv = _adb.logcat_argv(dump=True, tail=tail, t=None)
    await _aadb.arequire_shell_v2(address, serial)
    keep: _dump.Keep | None = None
    if condition is not None and _dump.needs_list(condition):
        job = await _take_list(address, serial)
        keep = _dump.package_filter(serial, condition, job)
    collector = _dump.Collector(serial, condition, keep)
    try:
        async with await _open(address, serial, argv) as stream:
            stream.set_timeout(_dump.IDLE_TIMEOUT)
            while True:
                batch = await _astream.gather(stream, None)
                for data in batch.err:
                    collector.take("stderr", data)
                if batch.out:
                    collector.take("stdout", b"".join(batch.out))
                if batch.broken is not None:
                    raise batch.broken
                if batch.ended:
                    break
                if not batch:
                    raise _dump.idle_timeout()
                await asyncio.sleep(0)
            status = stream.exit_status
        return collector.finish(status)
    finally:
        collector.tell_later_gaps()  # also when the dump failed or was cancelled
