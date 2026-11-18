"""A fake adb server that runs in its own process.

It speaks just enough of the adb smart-socket protocol for logprobe's client:
``host:version``, ``host:devices-l``, ``host-serial:SERIAL:features``,
``host:transport:SERIAL`` and ``shell,v2,raw:COMMAND``. A shell command that
runs ``logcat`` is answered with pre-built shell protocol v2 stdout packets
holding the lines of `bench.corpus`, then an exit packet with status 0, then
the connection closes (with ``--hold`` there is no exit packet and the
connection stays open, as a live device's does). Any other shell command gets
an empty output and exit status 0.

The server is a separate process on purpose: its work (and its garbage
collector) must not share the Python lock of the client being measured. It
builds every byte it will send before it listens, and serves each connection
with plain ``sendall`` calls of large slices, so it costs the client little
besides the kernel's copy.

Run it by hand::

    uv run python -m bench.fake_adb --kind live --lines 200000

It prints one JSON line (``port``, ``lines``, ``bytes``, ``packets``) when it
listens, and stops when its standard input closes or on SIGTERM. In Python code
use `FakeAdbProcess`.

Packing. The benchmark assumes that a device sends about one line per packet,
so `pack_packets` defaults to ``"line"``. The other packing is ``"bytes:N"``,
which puts whole lines into a packet until it holds at least N bytes (N up to
60,000; the last packet can be shorter).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import signal
import socket
import struct
import subprocess
import sys
import threading
from pathlib import Path
from typing import IO, TYPE_CHECKING, Final, Self

from bench.corpus import KINDS, build_lines

if TYPE_CHECKING:
    from types import TracebackType

__all__ = [
    "DEFAULT_PACKING",
    "DEFAULT_SERIAL",
    "FakeAdbProcess",
    "pack_packets",
    "parse_packing",
]

#: One line per packet, as the benchmark assumes devices send them.
DEFAULT_PACKING: Final = "line"
#: Serial of the one device the server knows.
DEFAULT_SERIAL: Final = "bench-0001"

_ID_STDOUT: Final = 1
_ID_EXIT: Final = 3
_HEADER: Final = struct.Struct("<BI")
_SLICE: Final = 256 * 1024
_MAX_PACKET: Final = 60_000
_ADB_VERSION: Final = 41
_FEATURES: Final = "shell_v2,cmd,stat_v2"


def parse_packing(text: str) -> int:
    """Return the packet size a packing name stands for.

    ``"line"`` is 1 (every line is a packet of its own); ``"bytes:N"`` is N.

    Raises:
        ValueError: For any other text or an N outside 1 to 60,000.
    """
    if text == "line":
        return 1
    name, _, number = text.partition(":")
    if name == "bytes" and number.isdecimal() and 1 <= int(number) <= _MAX_PACKET:
        return int(number)
    msg = (
        f"packing must be 'line' or 'bytes:N' with N from 1 to {_MAX_PACKET}: {text!r}"
    )
    raise ValueError(msg)


def pack_packets(
    lines: list[bytes], packing: str = DEFAULT_PACKING, *, exit_packet: bool = True
) -> tuple[bytes, int]:
    """Return the shell v2 byte stream for ``lines`` and its packet count.

    The stream is stdout packets followed, unless ``exit_packet`` is false, by
    one exit packet (status 0); the exit packet is part of the count.
    """
    minimum = parse_packing(packing)
    parts: list[bytes] = []
    packets = 0
    pending: list[bytes] = []
    size = 0
    for line in lines:
        pending.append(line)
        size += len(line)
        if size >= minimum:
            parts.append(_HEADER.pack(_ID_STDOUT, size))
            parts.extend(pending)
            packets += 1
            pending = []
            size = 0
    if pending:
        parts.append(_HEADER.pack(_ID_STDOUT, size))
        parts.extend(pending)
        packets += 1
    if exit_packet:
        parts.append(_HEADER.pack(_ID_EXIT, 1) + b"\x00")
        packets += 1
    return b"".join(parts), packets


def _read_exact(sock: socket.socket, size: int) -> bytes | None:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return bytes(data)


def _reply(sock: socket.socket, data: bytes) -> None:
    sock.sendall(b"OKAY%04x" % len(data) + data)


def _fail(sock: socket.socket, message: str) -> None:
    data = message.encode()
    sock.sendall(b"FAIL%04x" % len(data) + data)


def _serve_shell(
    sock: socket.socket, command: str, stream: bytes, *, hold: bool
) -> None:
    sock.sendall(b"OKAY")
    _read_exact(sock, _HEADER.size)  # the client's close-stdin packet
    if "logcat" in command:
        view = memoryview(stream)
        for start in range(0, len(view), _SLICE):
            sock.sendall(view[start : start + _SLICE])
    else:
        sock.sendall(_HEADER.pack(_ID_EXIT, 1) + b"\x00")
    if not hold:
        sock.shutdown(socket.SHUT_WR)
    # Let the client read to the end before the connection goes away (with
    # ``hold``, until the client closes it).
    while sock.recv(4096):
        pass


def _serve_requests(
    sock: socket.socket, serial: str, stream: bytes, *, hold: bool
) -> None:
    while True:
        header = _read_exact(sock, 4)
        body = None if header is None else _read_exact(sock, int(header, 16))
        if body is None:
            return
        request = body.decode()
        if request == "host:version":
            _reply(sock, b"%04x" % _ADB_VERSION)
        elif request == "host:devices-l":
            info = "device product:bench model:Bench device:bench transport_id:1"
            _reply(sock, f"{serial:<22} {info}\n".encode())
        elif request.startswith("host-serial:") and request.endswith(":features"):
            _reply(sock, _FEATURES.encode())
        elif request == f"host:transport:{serial}":
            sock.sendall(b"OKAY")
            continue
        elif request.startswith("shell,v2,raw:"):
            _serve_shell(sock, request[len("shell,v2,raw:") :], stream, hold=hold)
        elif request.startswith("host:transport:"):
            _fail(sock, f"device '{request[len('host:transport:') :]}' not found")
        else:
            _fail(sock, f"unknown request: {request}")
        return


def _handle(sock: socket.socket, serial: str, stream: bytes, *, hold: bool) -> None:
    with sock, contextlib.suppress(OSError):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        _serve_requests(sock, serial, stream, hold=hold)


def _accept_loop(
    listener: socket.socket, serial: str, stream: bytes, *, hold: bool
) -> None:
    while True:
        try:
            sock, _ = listener.accept()
        except OSError:
            return
        threading.Thread(
            target=_handle,
            args=(sock, serial, stream),
            kwargs={"hold": hold},
            daemon=True,
        ).start()


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m bench.fake_adb")
    parser.add_argument("--kind", choices=KINDS, default="live")
    parser.add_argument("--lines", type=int, default=200_000)
    parser.add_argument("--packing", default=DEFAULT_PACKING)
    parser.add_argument("--serial", default=DEFAULT_SERIAL)
    parser.add_argument(
        "--hold",
        action="store_true",
        help="send no exit packet and keep the connection open after the lines",
    )
    args = parser.parse_args(argv)
    stream, packets = pack_packets(
        build_lines(args.kind, args.lines), args.packing, exit_packet=not args.hold
    )
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    threading.Thread(
        target=_accept_loop,
        args=(listener, args.serial, stream),
        kwargs={"hold": args.hold},
        daemon=True,
    ).start()
    info = {
        "port": listener.getsockname()[1],
        "lines": args.lines,
        "bytes": len(stream),
        "packets": packets,
    }
    sys.stdout.write(json.dumps(info) + "\n")
    sys.stdout.flush()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda _signum, _frame: stop.set())

    def watch_stdin() -> None:
        sys.stdin.read()  # returns at end of file: the parent closed it or died
        stop.set()

    threading.Thread(target=watch_stdin, daemon=True).start()
    stop.wait()
    listener.close()
    return 0


class FakeAdbProcess:
    """The server in a child process, for use as a context manager.

    Args:
        kind: A kind of `bench.corpus.KINDS`.
        lines: How many lines every shell connection receives.
        packing: ``"line"`` or ``"bytes:N"`` (see the module docs).
        serial: The serial of the device.
        hold: Send no exit packet and keep each connection open after the lines.

    Attributes:
        port: The loopback port it listens on (after entering).
        address: ``tcp:127.0.0.1:PORT``, for ``Device(adb_server=...)``.
        stream_bytes: Size of the byte stream one connection receives.
        packets: Number of packets in it, the exit packet included (none with
            ``hold``).
    """

    def __init__(
        self,
        kind: str = "live",
        lines: int = 200_000,
        packing: str = DEFAULT_PACKING,
        serial: str = DEFAULT_SERIAL,
        *,
        hold: bool = False,
    ) -> None:
        parse_packing(packing)
        self.hold = hold
        self.kind = kind
        self.lines = lines
        self.packing = packing
        self.serial = serial
        self.port = 0
        self.stream_bytes = 0
        self.packets = 0
        self._process: subprocess.Popen[str] | None = None

    @property
    def address(self) -> str:
        """The server address in the form logprobe takes."""
        return f"tcp:127.0.0.1:{self.port}"

    def __enter__(self) -> Self:
        command = [
            sys.executable,
            "-m",
            "bench.fake_adb",
            "--kind",
            self.kind,
            "--lines",
            str(self.lines),
            "--packing",
            self.packing,
            "--serial",
            self.serial,
        ]
        if self.hold:
            command.append("--hold")
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            cwd=Path(__file__).resolve().parent.parent,
        )
        self._process = process
        try:
            stdout: IO[str] | None = process.stdout
            first = stdout.readline() if stdout is not None else ""
            if not first:
                msg = "the fake adb server exited before it listened"
                raise RuntimeError(msg)
            info = json.loads(first)
        except BaseException:
            self._stop()
            raise
        self.port = info["port"]
        self.stream_bytes = info["bytes"]
        self.packets = info["packets"]
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._stop()

    def _stop(self) -> None:
        process, self._process = self._process, None
        if process is None:
            return
        if process.stdin is not None:
            with contextlib.suppress(OSError):
                process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        if process.stdout is not None:
            process.stdout.close()


if __name__ == "__main__":
    sys.exit(_main())
