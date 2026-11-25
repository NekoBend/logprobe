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

from .attributor import PackageAttributor, Segment
from .commands import (
    DUMPSYS_PACKAGES_ARGV,
    PM_LIST_ARGV,
    DumpsysOutcome,
    Failed,
    Fallback,
    Listed,
    PmListOutcome,
    parse_dumpsys_packages,
    parse_pm_list,
    read_dumpsys_packages,
    read_pm_list,
)
from .dump import dump_judge
from .job import ListJob
from .timing import LIST_INTERVAL, LIST_MIN_TIME, LIST_WAIT, RECHECK_INTERVAL

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
