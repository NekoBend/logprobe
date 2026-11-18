"""Benchmark rows for the streaming layer.

Run from the repository root, inside the project's environment::

    uv run python -m bench.stream_bench                       # every row
    uv run python -m bench.stream_bench transport feeder      # chosen rows
    uv run python -m bench.stream_bench burst --repeat 3 --json

Rows that measure one part of the path, with no stream object involved:

``transport``
    The fake adb server (another process) writes the packets, a socket reads
    them, `ShellV2Decoder` decodes them. Nothing else.
``feeder``
    `Feeder.feed` over bytes that are already in memory: framing, decoding,
    parsing and building entries, with no I/O. Run once with reads of 64 KiB
    and once with one line per call.
``delivery``
    Chunks of 500 entries that were built beforehand go through `Outbox` to a
    consumer thread that iterates them. Neither transport nor parsing is
    included.
``memory``
    What an entry costs in memory: the fixed size of one `LogEntry`, the size
    per input byte for the corpus, for multi-byte-heavy lines and for short
    broken lines (tracemalloc), and the resident memory of a full output queue
    at the default limits (one fresh process per kind of line).

Rows that run the public stream API against the fake server, end to end::

    throughput   a 200,000-line backlog, default settings
    burst        10,000 and 50,000 lines, default settings, entry count checked
    slow-burst   the same bursts with a consumer that spends 20 us per entry

They use ``Device.stream()``.

Rows that run the asyncio stream (``Device.astream()``) the same way::

    async-throughput   the 200,000-line backlog, read with ``async for``
    async-lag          the largest burst (50,000 lines) of 60-byte lines while a
                       second task wakes every millisecond and records how late it ran
                       (the gate: at most 10 ms, p99 at most 5 ms)

Rows that read two fake devices in one stream and check correctness only (the
rate is recorded, there is no speed gate): ``multi`` (``logprobe.stream``) and
``async-multi`` (``logprobe.astream``).

Every timed row prints one line per variant: the median of ``--repeat`` runs
and the range. The ``memory`` row measures each variant once. ``--json`` prints
one JSON object per run instead.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import gc
import json
import math
import os
import platform
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
import tracemalloc
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Self

import logprobe
from bench.corpus import KINDS, build_lines, sized_lines
from bench.fake_adb import DEFAULT_PACKING, FakeAdbProcess
from logprobe import LogprobeError, _adb
from logprobe._feed import Feeder
from logprobe._outbox import Outbox

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from logprobe import LogEntry

DEFAULT_LINES: Final = 200_000
DEFAULT_BURST_LINES: Final = (10_000, 50_000)
DEFAULT_SLOW_US: Final = 20.0
DEFAULT_REPEAT: Final = 5
#: Entries per chunk in the delivery row.
DELIVERY_CHUNK: Final = 500
#: Entries the delivery row sends in all.
DELIVERY_ENTRIES: Final = 1_000_000
#: The queue limits of ``Device.stream()``.
BUFFER_LINES: Final = 10_000
BUFFER_BYTES: Final = 4 * 1024 * 1024
#: Size of the reads handed to the feeder in its first variant.
READ_BYTES: Final = 64 * 1024
#: Lines parsed to measure the memory of entries.
MEMORY_LINES: Final = 20_000
#: Message sizes of the lines that tell the fixed size of an entry from the rest.
MEMORY_MESSAGE_BYTES: Final = (0, 100, 400, 1600, 6400)
SERIAL: Final = "bench-0001"
MULTI_SERIALS: Final = (SERIAL, "bench-0002")
# A run that is slower than this counts as hung.
MIN_LINES_PER_SECOND: Final = 10_000.0
RUN_TIMEOUT: Final = 60.0
#: A stream run that receives nothing for this long is stopped (a short
#: delivery is then reported instead of waiting for the run timeout).
SETTLE_SECONDS: Final = 2.0
#: How often the watchdog of a stream run looks at the clock.
WATCH_SECONDS: Final = 0.25

RUNNABLE_ROWS: Final = (
    "transport",
    "feeder",
    "delivery",
    "memory",
    "throughput",
    "burst",
    "slow-burst",
    "async-throughput",
    "async-lag",
    "multi",
    "async-multi",
)
#: Seconds between the wake-ups of the second task of the async-lag row.
LAG_PERIOD: Final = 0.001

type Extra = dict[str, float | int | str | None]


class Skipped(Exception):  # noqa: N818  (a signal to the caller, not an error)
    """A row cannot run here; the text says why."""


@dataclasses.dataclass(frozen=True, slots=True)
class Sample:
    """One run of one variant of a row.

    Attributes:
        row: The row's name.
        label: The variant, such as ``10,000 lines``.
        expected: Lines the run should deliver.
        delivered: Lines it delivered.
        seconds: How long the run took; 0.0 for a row that measures no time.
        extra: Further numbers of the row.
    """

    row: str
    label: str
    expected: int
    delivered: int
    seconds: float
    extra: Extra = dataclasses.field(default_factory=dict)

    @property
    def rate(self) -> float:
        """Lines delivered per second; 0.0 when no time was measured."""
        return self.delivered / self.seconds if self.seconds > 0 else 0.0


def busy(seconds: float) -> None:
    """Spend ``seconds`` of CPU in a loop (a sleep would be too coarse)."""
    end = time.perf_counter() + seconds
    while time.perf_counter() < end:
        pass


def run_timeout(count: int, consumer_cost: float) -> float:
    """Seconds a run of ``count`` lines may take before it counts as hung."""
    return RUN_TIMEOUT + count * (1.0 / MIN_LINES_PER_SECOND + consumer_cost)


_lines_cache: dict[tuple[str, int], list[bytes]] = {}


def lines_of(kind: str, count: int) -> list[bytes]:
    """`build_lines`, remembered for the run (building is not what is measured)."""
    key = (kind, count)
    if key not in _lines_cache:
        _lines_cache[key] = build_lines(kind, count)
    return _lines_cache[key]


# -- transport -----------------------------------------------------------------


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            msg = "the fake adb server closed the connection early"
            raise ConnectionError(msg)
        data += chunk
    return bytes(data)


def _open_logcat(port: int, serial: str) -> socket.socket:
    """Connect and do the handshake of a logcat shell, as the client does."""
    sock = socket.create_connection(("127.0.0.1", port))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    command = _adb.device_command(_adb.logcat_argv(dump=False, tail=None, t=None))
    for request in (f"host:transport:{serial}", f"shell,v2,raw:{command}"):
        sock.sendall(_adb.encode_request(request))
        if _recv_exact(sock, 4) != b"OKAY":
            msg = f"the fake adb server refused {request!r}"
            raise ConnectionError(msg)
    sock.sendall(struct.pack("<BI", 4, 0))  # close stdin, as open_shell does
    return sock


def _transport_once(srv: FakeAdbProcess) -> Sample:
    sock = _open_logcat(srv.port, srv.serial)
    decoder = _adb.ShellV2Decoder()
    nbytes = nlines = 0
    status = None
    with sock:
        recv = sock.recv
        start = time.perf_counter()
        while status is None:
            data = recv(_adb.RECV_SIZE)
            if not data:
                break
            out, _err, status = decoder.feed(data)
            nbytes += len(out)
            nlines += out.count(b"\n")
        seconds = time.perf_counter() - start
    if status != 0:
        msg = f"the stream ended without exit status 0 (got {status})"
        raise RuntimeError(msg)
    extra: Extra = {
        "stdout_bytes": nbytes,
        "mb_per_s": nbytes / seconds / 1e6,
        "packets": srv.packets,
    }
    return Sample("transport", "live", srv.lines, nlines, seconds, extra)


def row_transport(args: argparse.Namespace) -> list[Sample]:
    """Fake server, socket and `ShellV2Decoder` only."""
    with FakeAdbProcess("live", args.lines, args.packing, SERIAL) as srv:
        return [_transport_once(srv) for _ in range(args.repeat)]


# -- feeder ----------------------------------------------------------------------


def _count_entries(chunks: Sequence[Any]) -> int:
    total = 0
    for chunk in chunks:
        for segment in chunk.segments:
            if type(segment) is list:
                total += len(segment)
    return total


def _feed_once(label: str, pieces: list[bytes], expected: int) -> Sample:
    feeder = Feeder(SERIAL)
    entries = 0
    gc.collect()
    start = time.perf_counter()
    for piece in pieces:
        entries += _count_entries(feeder.feed(piece))
    entries += _count_entries(feeder.finish())
    seconds = time.perf_counter() - start
    return Sample("feeder", label, expected, entries, seconds)


def row_feeder(args: argparse.Namespace) -> list[Sample]:
    """`Feeder.feed` over bytes in memory, in reads of 64 KiB and line by line."""
    lines = lines_of("live", args.lines)
    data = b"".join(lines)
    reads = [data[i : i + READ_BYTES] for i in range(0, len(data), READ_BYTES)]
    variants = (("64 KiB reads", reads), ("one line per read", lines))
    return [
        _feed_once(label, pieces, args.lines)
        for _ in range(args.repeat)
        for label, pieces in variants
    ]


# -- delivery --------------------------------------------------------------------


def _entry_chunks(count: int) -> tuple[list[list[LogEntry]], list[int]]:
    """Parse ``count`` live lines into chunks of `DELIVERY_CHUNK` and charges."""
    lines = lines_of("live", count)
    feeder = Feeder(SERIAL)
    entries: list[LogEntry] = []
    data = b"".join(lines)
    for i in range(0, len(data), READ_BYTES):
        for chunk in feeder.feed(data[i : i + READ_BYTES]):
            for segment in chunk.segments:
                if type(segment) is list:
                    entries.extend(segment)
    for chunk in feeder.finish():
        for segment in chunk.segments:
            if type(segment) is list:
                entries.extend(segment)
    chunks = [
        entries[i : i + DELIVERY_CHUNK] for i in range(0, len(entries), DELIVERY_CHUNK)
    ]
    charges = [
        sum(len(line) for line in lines[i : i + DELIVERY_CHUNK])
        for i in range(0, len(entries), DELIVERY_CHUNK)
    ]
    return chunks, charges


class _Entries:
    """The shape of a blocking iterator over the queue.

    It keeps the entries of the chunk it took and a position in them, and reads
    the queue's kill flag before it hands out each entry, as a stream's iterator
    does. A segment that is not a list ends it.
    """

    def __init__(self, box: Outbox) -> None:
        self._box = box
        self._buffer: list[Any] = []
        self._position = 0
        self._done = False

    def __iter__(self) -> Self:
        return self

    def _refill(self) -> bool:
        while (segments := self._box.take(WATCH_SECONDS)) is None:
            if self._box.killed:
                return False
        self._buffer = []
        for segment in segments:
            if type(segment) is list:
                self._buffer.extend(segment)
            else:
                self._buffer.append(segment)
        self._position = 0
        return True

    def __next__(self) -> LogEntry:
        box = self._box
        while not self._done:
            if self._position < len(self._buffer):
                item = self._buffer[self._position]
                self._position += 1
                if box.killed:
                    break
                if type(item) is not _EndMark:
                    return item
                break
            if not self._refill():
                break
        self._done = True
        raise StopIteration


class _EndMark:
    """The last element of a delivery run."""


def _delivery_once(
    chunks: list[list[LogEntry]], charges: list[int], passes: int
) -> Sample:
    box = Outbox(BUFFER_LINES, BUFFER_BYTES)
    received = [0]
    failure: list[BaseException] = []

    def consume() -> None:
        try:
            count = 0
            for _entry in _Entries(box):
                count += 1
            received[0] = count
        except BaseException as error:  # noqa: BLE001  (handed to the caller)
            failure.append(error)
            box.request_kill()

    consumer = threading.Thread(target=consume, daemon=True)
    pairs = list(zip(chunks, charges, strict=True))
    consumer.start()
    start = time.perf_counter()
    try:
        for _ in range(passes):
            for chunk, charge in pairs:
                box.put([chunk], charge)
        box.put([_EndMark()], 0)
        while consumer.is_alive():
            consumer.join(WATCH_SECONDS)
    except BaseException:
        box.request_kill()
        consumer.join(5.0)
        raise
    seconds = time.perf_counter() - start
    if failure:
        raise failure[0]
    expected = passes * sum(len(chunk) for chunk in chunks)
    extra: Extra = {"us_per_line": seconds / expected * 1e6}
    return Sample("delivery", "500-entry chunks", expected, received[0], seconds, extra)


def row_delivery(args: argparse.Namespace) -> list[Sample]:
    """Pre-built chunks through `Outbox` to a consumer thread.

    The consumer is an iterator that checks the kill flag and the type of every
    entry it hands out, as a blocking ``for`` over a stream does.
    """
    pool = min(args.lines, 20_000)
    chunks, charges = _entry_chunks(pool)
    passes = max(1, DELIVERY_ENTRIES // pool)
    return [_delivery_once(chunks, charges, passes) for _ in range(args.repeat)]


# -- memory ----------------------------------------------------------------------


def _entries_of(lines: list[bytes]) -> list[LogEntry]:
    feeder = Feeder(SERIAL)
    entries: list[LogEntry] = []
    data = b"".join(lines)
    pieces = [data[i : i + READ_BYTES] for i in range(0, len(data), READ_BYTES)]
    for piece in pieces:
        for chunk in feeder.feed(piece):
            for segment in chunk.segments:
                if type(segment) is list:
                    entries.extend(segment)
    for chunk in feeder.finish():
        for segment in chunk.segments:
            if type(segment) is list:
                entries.extend(segment)
    return entries


def traced_bytes_per_entry(lines: list[bytes]) -> tuple[float, float]:
    """Return the memory of one entry and the input bytes per line, for ``lines``.

    tracemalloc counts what is still allocated after parsing, minus the list
    that holds the entries (8 bytes of pointer per slot).
    """
    gc.collect()
    tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        entries = _entries_of(lines)
        gc.collect()
        after = tracemalloc.get_traced_memory()[0]
    finally:
        tracemalloc.stop()
    held = after - before - sys.getsizeof(entries)
    return held / len(entries), sum(map(len, lines)) / len(lines)


def fixed_entry_bytes() -> tuple[float, float]:
    """Return ``(O, k)``: the memory of an entry that does not depend on its input.

    A straight line is fitted through the memory of an entry against its input
    size, for lines whose messages are 0 to 6,400 bytes long; O is where the line
    meets zero input bytes and k is its slope.
    """
    sizes: list[float] = []
    held: list[float] = []
    for message_bytes in MEMORY_MESSAGE_BYTES:
        per_entry, per_line = traced_bytes_per_entry(sized_lines(2_000, message_bytes))
        sizes.append(per_line)
        held.append(per_entry)
    slope, intercept = statistics.linear_regression(sizes, held)
    return intercept, slope


def _resident_kib() -> int | None:
    """The process's resident memory in KiB, or None where /proc has no answer."""
    try:
        text = Path("/proc/self/status").read_text(encoding="ascii")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return None


def _rss_child(kind: str) -> dict[str, Any]:
    """Fill an `Outbox` at the default limits with entries of ``kind``; measure RSS.

    Runs in a fresh process, so that nothing earlier inflates the figures.
    """
    lines = build_lines(kind, 60_000)
    data = b"".join(lines)
    pieces = [data[i : i + READ_BYTES] for i in range(0, len(data), READ_BYTES)]
    feeder = Feeder(SERIAL)
    box = Outbox(BUFFER_LINES, BUFFER_BYTES)
    gc.collect()
    before = _resident_kib()
    full = False
    for piece in pieces:
        for chunk in feeder.feed(piece):
            if box.pending_lines >= BUFFER_LINES or box.pending_bytes >= BUFFER_BYTES:
                full = True
                break
            box.put(chunk.segments, chunk.charge)
        if full:
            break
    gc.collect()
    after = _resident_kib()
    return {
        "queued_lines": box.pending_lines,
        "charged_bytes": box.pending_bytes,
        "rss_before_kib": before,
        "rss_after_kib": after,
        "rss_growth_kib": None if before is None or after is None else after - before,
    }


def _rss_of_full_queue(kind: str) -> dict[str, Any]:
    done = subprocess.run(
        [sys.executable, "-m", "bench.stream_bench", "--rss-child", kind],
        stdout=subprocess.PIPE,  # stderr is inherited: a failure shows its traceback
        text=True,
        check=True,
        cwd=Path(__file__).resolve().parent.parent,
    )
    return json.loads(done.stdout)


def row_memory(args: argparse.Namespace) -> list[Sample]:  # noqa: ARG001
    """The memory an entry takes, and the resident memory of a full queue."""
    fixed, per_byte = fixed_entry_bytes()
    samples = [
        Sample(
            "memory",
            "fixed size of one entry (O)",
            0,
            0,
            0.0,
            {"O_bytes": fixed, "ascii_bytes_per_input_byte": per_byte},
        )
    ]
    for kind in KINDS:
        lines = lines_of(kind, MEMORY_LINES)
        per_entry, per_line = traced_bytes_per_entry(lines)
        extra: Extra = {
            "bytes_per_entry": per_entry,
            "input_bytes_per_line": per_line,
            "bytes_per_input_byte": per_entry / per_line,
        }
        extra.update(_rss_of_full_queue(kind))
        samples.append(Sample("memory", kind, MEMORY_LINES, MEMORY_LINES, 0.0, extra))
    return samples


# -- end to end through Device.stream() ------------------------------------------


def _stream_factory(device: logprobe.Device) -> Callable[..., Any]:
    factory = getattr(device, "stream", None)
    if factory is None:
        msg = "stream API not available"
        raise Skipped(msg)
    return factory


def _open_stream(device: logprobe.Device) -> Any:  # noqa: ANN401
    """Create the stream with its default settings."""
    return _stream_factory(device)()


def _ended_by_the_device(error: LogprobeError) -> bool:
    """Whether ``error`` is the device closing the connection after exit status 0."""
    return error.code == "device_lost" and error.details.get("exit_status") == 0


def _stream_once(
    row: str, label: str, srv: FakeAdbProcess, consumer_cost: float
) -> Sample:
    device = logprobe.Device(srv.serial, adb_server=srv.address)
    stream = _open_stream(device)
    expected = srv.lines
    limit = run_timeout(expected, consumer_cost)
    delivered = 0
    start = time.perf_counter()
    last = start
    finished = threading.Event()
    stopped_by: list[str] = []

    def watch() -> None:
        # Ends a run that went quiet (stop) or that took far too long (kill).
        while not finished.wait(WATCH_SECONDS):
            now = time.perf_counter()
            if now - start > limit:
                stopped_by.append("run timeout")
                stream.kill()
                return
            if now - last > SETTLE_SECONDS:
                stopped_by.append("no entry for a while")
                stream.stop()
                return

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    try:
        with stream:
            for _entry in stream:
                if consumer_cost > 0:
                    busy(consumer_cost)
                delivered += 1
                last = time.perf_counter()
                if delivered == expected:
                    break
    except LogprobeError as error:
        if not _ended_by_the_device(error):
            raise
    finally:
        finished.set()
        watcher.join(5.0)
    seconds = last - start if delivered else 0.0
    extra: Extra = {
        "complete": delivered == expected,
        "timed_out": "run timeout" in stopped_by,
    }
    return Sample(row, label, expected, delivered, seconds, extra)


def _stream_case(
    row: str,
    sizes: Sequence[int],
    args: argparse.Namespace,
    consumer_cost: float,
    *,
    kind: str = "live",
) -> list[Sample]:
    run_once = _astream_once if row.startswith("async-") else _stream_once
    if (
        getattr(
            logprobe.Device, "astream" if row.startswith("async-") else "stream", None
        )
        is None
    ):
        msg = "stream API not available"
        raise Skipped(msg)
    samples: list[Sample] = []
    for size in sizes:
        with FakeAdbProcess(kind, size, args.packing, SERIAL, hold=True) as srv:
            samples += [
                run_once(row, f"{size:,} lines", srv, consumer_cost)
                for _ in range(args.repeat)
            ]
    return samples


def row_throughput(args: argparse.Namespace) -> list[Sample]:
    """A backlog read end to end by a plain ``for`` loop (sync)."""
    return _stream_case("throughput", [args.lines], args, 0.0)


def row_burst(args: argparse.Namespace) -> list[Sample]:
    """Bursts at the default settings; the expected entry count is checked."""
    return _stream_case("burst", args.burst_lines, args, 0.0)


def row_slow_burst(args: argparse.Namespace) -> list[Sample]:
    """Bursts read by a consumer that spends ``--slow-us`` per entry."""
    return _stream_case("slow-burst", args.burst_lines, args, args.slow_us / 1e6)


async def _tick_lags(lags: list[float]) -> None:
    """Wake every ``LAG_PERIOD`` seconds and record how late each wake-up was."""
    loop = asyncio.get_running_loop()
    while True:
        due = loop.time() + LAG_PERIOD
        await asyncio.sleep(LAG_PERIOD)
        lags.append(loop.time() - due)


async def _read_async(
    row: str, srv: FakeAdbProcess, limit: float, lags: list[float]
) -> tuple[int, float, list[str]]:
    """Read ``srv.lines`` entries with ``async for``; a watchdog ends a stuck run."""
    stream = logprobe.Device(srv.serial, adb_server=srv.address).astream()
    delivered = 0
    start = last = time.perf_counter()
    stopped_by: list[str] = []

    async def watch() -> None:
        while True:
            await asyncio.sleep(WATCH_SECONDS)
            now = time.perf_counter()
            if now - start > limit:
                stopped_by.append("run timeout")
                stream.kill()
                return
            if now - last > SETTLE_SECONDS:
                stopped_by.append("no entry for a while")
                stream.stop()
                return

    tasks = [asyncio.create_task(watch())]
    if row == "async-lag":
        tasks.append(asyncio.create_task(_tick_lags(lags)))
    try:
        async with stream:
            async for _entry in stream:
                delivered += 1
                last = time.perf_counter()
                if delivered == srv.lines:
                    break
    except LogprobeError as error:
        if not _ended_by_the_device(error):
            raise
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return delivered, last - start if delivered else 0.0, stopped_by


def _astream_once(
    row: str, label: str, srv: FakeAdbProcess, _consumer_cost: float
) -> Sample:
    lags: list[float] = []
    limit = run_timeout(srv.lines, 0.0)
    delivered, seconds, stopped_by = asyncio.run(_read_async(row, srv, limit, lags))
    extra: Extra = {
        "complete": delivered == srv.lines,
        "timed_out": "run timeout" in stopped_by,
    }
    if row == "async-lag":
        ms = [lag * 1000 for lag in lags]
        extra["wakeups"] = len(ms)
        extra["max_lag_ms"] = max(ms, default=0.0)
        extra["p99_lag_ms"] = (
            statistics.quantiles(ms, n=100)[98] if len(ms) > 1 else 0.0
        )
    return Sample(row, label, srv.lines, delivered, seconds, extra)


def row_async_throughput(args: argparse.Namespace) -> list[Sample]:
    """A backlog read end to end by ``async for`` on the asyncio stream."""
    return _stream_case("async-throughput", [args.lines], args, 0.0)


def row_async_lag(args: argparse.Namespace) -> list[Sample]:
    """The loop's lag during the largest burst of 60-byte lines."""
    return _stream_case("async-lag", [args.burst_lines[-1]], args, 0.0, kind="dense")


def _multi_once(row: str, label: str, servers: Sequence[FakeAdbProcess]) -> Sample:
    """Read all ``servers`` in one stream and count the entries per serial."""
    is_async = row.startswith("async-")
    devices = [logprobe.Device(s.serial, adb_server=s.address) for s in servers]
    stream: Any = (logprobe.astream if is_async else logprobe.stream)(devices)
    wanted = Counter({s.serial: s.lines for s in servers})
    counts: Counter[str] = Counter()
    start = last = time.perf_counter()
    finished = threading.Event()
    stopped_by: list[str] = []

    def watch() -> None:
        while not finished.wait(WATCH_SECONDS):
            now = time.perf_counter()
            if now - start > run_timeout(wanted.total(), 0.0):
                stopped_by.append("run timeout")
                stream.kill()
                return
            if now - last > SETTLE_SECONDS:
                stopped_by.append("no entry for a while")
                stream.stop()
                return

    def take(entry: LogEntry) -> bool:
        nonlocal last
        counts[str(entry.serial)] += 1
        last = time.perf_counter()
        return counts.total() == wanted.total()

    async def read_async() -> None:
        async with stream:
            async for entry in stream:
                if take(entry):
                    break

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    try:
        if is_async:
            asyncio.run(read_async())
        else:
            with stream:
                for entry in stream:
                    if take(entry):
                        break
    except LogprobeError as error:
        if not _ended_by_the_device(error):
            raise
    finally:
        finished.set()
        watcher.join(5.0)
    extra: Extra = {
        "complete": counts == wanted,
        "timed_out": "run timeout" in stopped_by,
    }
    seconds = last - start if counts else 0.0
    return Sample(row, label, wanted.total(), counts.total(), seconds, extra)


def _multi_case(row: str, args: argparse.Namespace) -> list[Sample]:
    api = "astream" if row.startswith("async-") else "stream"
    if getattr(logprobe, api, None) is None:
        msg = "stream API not available"
        raise Skipped(msg)
    sizes = (max(args.lines // 2, 2), max(args.lines // 4, 1))
    first, second = (
        FakeAdbProcess("live", size, args.packing, serial, hold=True)
        for size, serial in zip(sizes, MULTI_SERIALS, strict=True)
    )
    label = f"{sizes[0]:,}+{sizes[1]:,} lines"
    with first, second:
        return [_multi_once(row, label, (first, second)) for _ in range(args.repeat)]


ROW_FUNCTIONS: Final[dict[str, Callable[[argparse.Namespace], list[Sample]]]] = {
    "transport": row_transport,
    "feeder": row_feeder,
    "delivery": row_delivery,
    "memory": row_memory,
    "throughput": row_throughput,
    "burst": row_burst,
    "slow-burst": row_slow_burst,
    "async-throughput": row_async_throughput,
    "async-lag": row_async_lag,
    "multi": lambda args: _multi_case("multi", args),
    "async-multi": lambda args: _multi_case("async-multi", args),
}


# -- report ----------------------------------------------------------------------


def load_average() -> str:
    """The 1, 5 and 15 minute load averages as text, or ``n/a`` (Windows)."""
    getter = getattr(os, "getloadavg", None)
    if getter is None:
        return "n/a"
    return ", ".join(f"{value:.2f}" for value in getter())


def environment_line(repeat: int) -> str:
    """Describe where the numbers come from: versions, platform, CPUs, load."""
    load = load_average()
    return (
        f"logprobe benchmark; Python {platform.python_version()}"
        f" ({platform.python_implementation()}); {platform.platform()};"
        f" {os.cpu_count()} logical CPUs; load average {load};"
        f" {repeat} run(s) per row"
    )


def _spread(values: Sequence[float], digits: int = 0) -> str:
    return (
        f"{statistics.median(values):,.{digits}f}"
        f" ({min(values):,.{digits}f}..{max(values):,.{digits}f})"
    )


def format_group(samples: Sequence[Sample]) -> str:
    """Summarise the runs of one variant of one row as a line of text."""
    first = samples[0]
    head = f"{first.row:<12} {first.label:<28}"
    if first.row == "memory":
        pairs = ", ".join(
            f"{key}={value:,.2f}" if isinstance(value, float) else f"{key}={value}"
            for key, value in first.extra.items()
        )
        return f"{head} {pairs}"
    delivered = statistics.median_low([s.delivered for s in samples])
    text = (
        f"{head} lines/s median (min..max) {_spread([s.rate for s in samples])};"
        f" delivered {delivered:,}/{first.expected:,}"
    )
    if first.row in {
        "burst",
        "slow-burst",
        "throughput",
        "async-throughput",
        "async-lag",
        "multi",
        "async-multi",
    }:
        late = sum(1 for s in samples if s.extra.get("timed_out"))
        everything = not late and all(
            s.delivered == s.expected and s.extra.get("complete", True) for s in samples
        )
        text += "; 100% delivery: " + ("yes" if everything else "NO")
        if late:
            text += f"; TIMED OUT in {late} of {len(samples)} run(s)"
    if first.row == "async-lag":
        text += "; " + ", ".join(
            f"{key} median {_spread([float(s.extra[key] or 0) for s in samples], 2)}"
            for key in ("max_lag_ms", "p99_lag_ms")
        )
    if first.row == "delivery":
        text += (
            f"; us/line {_spread([s.seconds / s.expected * 1e6 for s in samples], 3)}"
        )
    return text


def print_samples(samples: Sequence[Sample]) -> None:
    """Print the samples grouped by row and variant, in the order they came."""
    groups: dict[tuple[str, str], list[Sample]] = {}
    for sample in samples:
        groups.setdefault((sample.row, sample.label), []).append(sample)
    for group in groups.values():
        print(format_group(group))


def print_json(samples: Sequence[Sample]) -> None:
    """Print one JSON object per sample."""
    for sample in samples:
        record = dataclasses.asdict(sample)
        record["rate"] = sample.rate
        print(json.dumps(record))


# -- entry point -----------------------------------------------------------------


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        msg = f"must be at least 1, got {value}"
        raise argparse.ArgumentTypeError(msg)
    return value


def _positive_float(text: str) -> float:
    value = float(text)
    if not (math.isfinite(value) and value > 0):
        msg = f"must be a finite number above 0, got {text}"
        raise argparse.ArgumentTypeError(msg)
    return value


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse the command line (see the module docs)."""
    parser = argparse.ArgumentParser(
        prog="python -m bench.stream_bench",
        description="Benchmark rows for the streaming layer.",
    )
    parser.add_argument(
        "rows",
        nargs="*",
        metavar="ROW",
        choices=RUNNABLE_ROWS,
        help=f"rows to run (default: {' '.join(RUNNABLE_ROWS)})",
    )
    parser.add_argument("--lines", type=_positive_int, default=DEFAULT_LINES)
    parser.add_argument(
        "--burst-lines",
        nargs="+",
        type=_positive_int,
        default=list(DEFAULT_BURST_LINES),
    )
    parser.add_argument("--slow-us", type=_positive_float, default=DEFAULT_SLOW_US)
    parser.add_argument("--repeat", type=_positive_int, default=DEFAULT_REPEAT)
    parser.add_argument(
        "--packing",
        default=DEFAULT_PACKING,
        help="how the fake server packs lines into packets: 'line' (one line per "
        "packet, as the benchmark assumes devices do) or 'bytes:N' "
        "(default: %(default)s)",
    )
    parser.add_argument("--json", action="store_true", help="one JSON object per run")
    parser.add_argument("--rss-child", choices=KINDS, help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns the process exit status."""
    args = parse_args(argv)
    if args.rss_child:
        print(json.dumps(_rss_child(args.rss_child)))
        return 0
    rows = args.rows or list(RUNNABLE_ROWS)
    if not args.json:
        print(environment_line(args.repeat))
    try:
        for name in rows:
            try:
                samples = ROW_FUNCTIONS[name](args)
            except Skipped as skipped:
                print(
                    json.dumps({"row": name, "skipped": str(skipped)})
                    if args.json
                    else f"{name}: skipped: {skipped}"
                )
                continue
            (print_json if args.json else print_samples)(samples)
            sys.stdout.flush()
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
