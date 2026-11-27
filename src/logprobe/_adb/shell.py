"""Shell protocol v2: running a command on a device and reading its output."""

from __future__ import annotations

import contextlib
import shlex
import socket
import struct
import time
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from .limits import DEFAULT_TIMEOUT, MAX_SHELL_PACKET, RECV_SIZE
from .protocol import (
    _io,
    _send_all,
    _send_request,
    check_token,
    connect,
    connection_failed,
    protocol_error,
    shell_request,
    transport_request,
)
from .sockets import Cancelled

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from types import TracebackType

    from logprobe._errors import LogprobeError

    from .address import ServerAddress


type ShellEvent = tuple[Literal["stdout", "stderr"], bytes]
type ShellPiece = tuple[Literal["stdout", "stderr"], memoryview, bool]


# ---------------------------------------------------------------------------
# Shell protocol v2
# ---------------------------------------------------------------------------

_ID_STDOUT = 1
_ID_STDERR = 2
_ID_EXIT = 3
_ID_CLOSE_STDIN = 4
_HEADER = struct.Struct("<BI")
#: The first bytes a client sends after the shell request: close stdin at once.
CLOSE_STDIN = _HEADER.pack(_ID_CLOSE_STDIN, 0)
_EMPTY_EXIT = "the adb server sent an empty exit packet"
_AFTER_EXIT = "the adb server sent data after the exit packet"


def device_command(args: Sequence[str]) -> str:
    """Build the device-side command line for ``args``.

    ``args[0]`` is the program. The line matches what the adb client sends and
    makes the program a direct child of adbd (``exec``).

    Raises:
        TypeError: If ``args`` is a string or holds a non-string.
        ValueError: If ``args`` is empty or an argument contains NUL or a line break.
    """
    if isinstance(args, str):
        msg = "args must be a sequence of strings, not a single string"
        raise TypeError(msg)
    if not args:
        msg = "args must not be empty"
        raise ValueError(msg)
    for arg in args:
        if isinstance(arg, str) and not arg:
            continue  # an empty argument is fine once quoted
        check_token(arg, "argument")
    if not args[0]:
        msg = "the program name (args[0]) must not be empty"
        raise ValueError(msg)
    return 'export ANDROID_LOG_TAGS=""; exec ' + " ".join(shlex.quote(a) for a in args)


class ShellV2Decoder:
    """Incremental decoder for the shell protocol v2 byte stream.

    A packet is a one-byte kind, a four-byte little-endian payload length and
    the payload. :meth:`feed` takes the bytes of one network read, in any
    split, and returns the output they contain. Payloads are passed on as they
    arrive, so nothing larger than the chunk is ever held; the only state is a
    partial header (at most five bytes), the kind and remaining length of the
    current packet, and the first byte of an exit payload.

    Empty output packets and packets of unknown kind are skipped.
    """

    __slots__ = ("_done", "_header", "_kind", "_remaining", "_status")

    def __init__(self) -> None:
        self._header = bytearray()
        self._kind = 0
        self._remaining = 0
        self._status: int | None = None
        self._done = False

    def feed_pieces(
        self, data: bytes
    ) -> tuple[list[ShellPiece], int | None, LogprobeError | None]:
        """Decode ``data`` without raising; return what it holds up to any error.

        Returns the output pieces in order, the exit status and the protocol
        error that ended decoding (or None). A piece is ``(kind, payload,
        ends_packet)``: the part of one packet's payload that lies in ``data``
        (a view of it, not a copy) and whether it is the last part of that
        packet. The status is None unless ``data`` completed the exit packet.
        After an error the decoder rejects all further data.
        """
        pieces: list[ShellPiece] = []
        size = len(data)
        if self._done and size:
            return pieces, None, protocol_error(_AFTER_EXIT)
        view = memoryview(data)
        pos = 0
        status: int | None = None
        while pos < size:
            if self._remaining == 0:
                take = min(_HEADER.size - len(self._header), size - pos)
                self._header += view[pos : pos + take]
                pos += take
                if len(self._header) < _HEADER.size:
                    break
                self._kind, self._remaining = _HEADER.unpack(self._header)
                self._header.clear()
                if self._kind == _ID_EXIT and self._remaining == 0:
                    self._done = True
                    return pieces, None, protocol_error(_EMPTY_EXIT)
                if self._remaining > MAX_SHELL_PACKET:
                    self._done = True
                    return (
                        pieces,
                        None,
                        protocol_error(
                            "the adb server sent a shell packet longer than "
                            f"{MAX_SHELL_PACKET} bytes",
                            length=self._remaining,
                        ),
                    )
                continue
            take = min(self._remaining, size - pos)
            piece = view[pos : pos + take]
            pos += take
            self._remaining -= take
            ends = self._remaining == 0
            if self._kind == _ID_STDOUT:
                pieces.append(("stdout", piece, ends))
            elif self._kind == _ID_STDERR:
                pieces.append(("stderr", piece, ends))
            elif self._kind == _ID_EXIT:
                if self._status is None:
                    self._status = piece[0]
                if ends:
                    self._done = True
                    status = self._status
                    if pos < size:
                        return pieces, status, protocol_error(_AFTER_EXIT)
        return pieces, status, None

    @property
    def receiving(self) -> str | None:
        """``"stdout"`` or ``"stderr"`` while the payload of such a packet is
        only partly received, else None."""
        if self._remaining == 0:
            return None
        if self._kind == _ID_STDOUT:
            return "stdout"
        if self._kind == _ID_STDERR:
            return "stderr"
        return None

    def feed(self, data: bytes) -> tuple[bytes, bytes, int | None]:
        """Decode ``data``; return its stdout bytes, stderr bytes and exit status.

        The stdout returned is at most ``len(data)`` bytes. The status is None
        unless the exit packet was completed by ``data``.

        Raises:
            LogprobeError: ``adb_error`` for an empty exit packet, for bytes
                after the exit packet, or for a packet that declares more than
                ``MAX_SHELL_PACKET`` bytes.
        """
        pieces, status, error = self.feed_pieces(data)
        if error is not None:
            raise error
        out = b"".join(piece for kind, piece, _ in pieces if kind == "stdout")
        err = b"".join(piece for kind, piece, _ in pieces if kind == "stderr")
        return out, err, status


def collect_events(
    decoder: ShellV2Decoder,
    chunk: bytes,
    partial: bytearray,
    pending: deque[ShellEvent],
) -> tuple[int | None, LogprobeError | None]:
    """Decode one network read into whole output events.

    The output of the packet being received waits in ``partial`` until the
    packet is complete, so a connection that drops mid-packet delivers none
    of it; every complete packet is appended to ``pending``. Returns the exit
    status (None unless ``chunk`` completed the exit packet) and the protocol
    error that ended decoding (or None).
    """
    pieces, status, error = decoder.feed_pieces(chunk)
    for kind, piece, ends in pieces:
        partial += piece
        if ends:
            pending.append((kind, bytes(partial)))
            partial.clear()
    return status, error


def collect_parts(
    decoder: ShellV2Decoder, chunk: bytes, pending: deque[ShellEvent]
) -> tuple[int | None, LogprobeError | None]:
    """Decode one network read into the output parts it holds.

    Unlike `collect_events` this does not wait for a packet to be complete:
    the part of a packet that ``chunk`` holds is appended to ``pending`` at
    once, as a reader that decodes the socket itself sees it. Returns the exit
    status (None unless ``chunk`` completed the exit packet) and the protocol
    error that ended decoding (or None).
    """
    pieces, status, error = decoder.feed_pieces(chunk)
    pending.extend((kind, bytes(piece)) for kind, piece, _ in pieces)
    return status, error


class ShellStream:
    """Decoder for a shell protocol v2 connection to a device command.

    Call :meth:`read` repeatedly until it returns None. ``close`` is
    idempotent. ``exit_status`` holds the command's exit status once
    :meth:`read` has returned None; it is None before that, and stays None
    when the connection closed without an exit packet.
    """

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._decoder = ShellV2Decoder()
        self._pending: deque[ShellEvent] = deque()
        # The packet being received: its output waits here until it is
        # complete, so a connection that drops mid-packet delivers none of it.
        self._partial = bytearray()
        self._error: LogprobeError | None = None
        # The decoded exit status; published as exit_status once read() ends.
        self._status: int | None = None
        self._finished = False
        self._closed = False
        self._deadline: float | None = None
        self._timeout: float | None = None
        self._sliced = False
        self.exit_status: int | None = None

    def __enter__(self) -> ShellStream:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def sock(self) -> socket.socket:
        """The connection's socket, for a caller that decodes the output itself.

        A caller that reads this socket directly (with a :class:`ShellV2Decoder`)
        must not also call :meth:`read`; it still ends the connection with
        :meth:`close`.
        """
        return self._sock

    def set_timeout(self, timeout: float | None) -> None:
        """Set how long one :meth:`read` may block (None: forever)."""
        self._timeout = timeout
        if not self._closed:
            self._sock.settimeout(timeout)
            self._sliced = False

    def set_deadline(self, deadline: float | None) -> None:
        """Set an absolute ``time.monotonic()`` deadline for :meth:`read`.

        Every blocking receive gets the time left as its timeout, so slowly
        arriving data cannot extend the total. It replaces
        :meth:`set_timeout`; None removes it.
        """
        self._deadline = deadline
        if deadline is None:
            # Drop the replaced timeout too, so no stale finite value stays.
            self.set_timeout(None)

    def read(self, cancelled: Callable[[], bool] | None = None) -> ShellEvent | None:
        """Return the next stdout or stderr event, or None at the end.

        Only output events come back: ``("stdout", bytes)`` or
        ``("stderr", bytes)``. The exit status is not an event. After
        ``read()`` returns None, read it from :attr:`exit_status` (None when
        the connection closed without an exit packet).

        With ``cancelled``, a blocking wait is cut into slices of ``TICK``
        seconds and the callback is asked between them.

        Raises:
            TimeoutError: If a timeout or deadline was set and expired.
            LogprobeError: ``adb_error`` if the device sent an empty exit
                packet or a packet that declares more than
                ``MAX_SHELL_PACKET`` bytes. Output received before it is
                returned first. Bytes after the exit packet are ignored.
            Cancelled: If ``cancelled()`` returned true; the stream is closed
                (by this thread, which owns the socket) before it is raised.
        """
        while True:
            if self._pending:
                return self._pending.popleft()
            if self._error is not None:
                # Raise once: the stream is finished, so later reads return None.
                error, self._error = self._error, None
                self.close()
                raise error
            if self._finished:
                self.exit_status = self._status
                self.close()
                return None
            self._fill(cancelled)

    def _fill(self, cancelled: Callable[[], bool] | None) -> None:
        if self._closed:
            self._finished = True
            return
        sock = self._sock
        if cancelled is None and self._sliced:
            sock.settimeout(self._timeout)
            self._sliced = False
        self._sliced = self._sliced or cancelled is not None
        try:
            chunk = _io(
                sock,
                lambda: sock.recv(RECV_SIZE),
                self._deadline,
                cancelled,
                self._timeout,
            )
        except TimeoutError:
            raise
        except Cancelled:
            self.close()
            raise
        except OSError:
            chunk = b""
        if not chunk:
            self._finished = True
            return
        status, error = collect_events(
            self._decoder, chunk, self._partial, self._pending
        )
        if status is not None:
            # Whatever follows the exit packet in the same read is ignored,
            # as it is when it arrives in a later read that is never made.
            self._status = status
            self._finished = True
        elif error is not None:
            self._error = error
            self._finished = True

    def held_stderr(self) -> bytes:
        """The received part of a stderr packet that is not complete yet.

        `read` returns a packet only once it is complete; this is for an error
        report when the command did not get that far.
        """
        if self._decoder.receiving != "stderr":
            return b""
        return bytes(self._partial)

    def close(self) -> None:
        """Close the connection. Safe to call more than once."""
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(OSError):
            self._sock.shutdown(socket.SHUT_RDWR)
        self._sock.close()


def open_shell(
    address: ServerAddress,
    serial: str,
    args: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    deadline: float | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> ShellStream:
    """Start ``args`` on a device and return its output stream.

    ``timeout`` covers connecting and the handshake only; afterwards reads
    block until data arrives. With a ``deadline`` (a ``time.monotonic()``
    value) every connect, send and receive of the handshake gets the time
    left instead, and running out raises ``TimeoutError``. The deadline does
    not carry over to the stream; see :meth:`ShellStream.set_deadline`.
    With ``cancelled``, every wait is cut into slices of ``TICK`` seconds; if
    the callback returns true the socket is closed and :class:`Cancelled` is
    raised.
    """
    check_token(serial, "serial")
    command = device_command(args)
    sock = connect(address, timeout, deadline, cancelled=cancelled)
    try:
        _send_request(
            sock, transport_request(serial), serial, deadline, cancelled, timeout
        )
        _send_request(
            sock, shell_request(command), serial, deadline, cancelled, timeout
        )
        # Close the command's stdin at once, so a command that reads it gets
        # EOF instead of waiting until the connection closes.
        try:
            _send_all(sock, CLOSE_STDIN, deadline, cancelled, timeout)
        except OSError as error:
            if deadline is not None and isinstance(error, TimeoutError):
                raise
            raise connection_failed(error) from error
        sock.settimeout(None)
    except BaseException:
        sock.close()
        raise
    return ShellStream(sock)


@dataclass(frozen=True, slots=True)
class ShellResult:
    """Outcome of a one-shot device command.

    ``exit_status`` is None when the connection dropped before the device
    reported one; ``stdout`` and ``stderr`` may then be incomplete: ``stdout``
    holds only the packets that arrived whole, and ``stderr`` may end with the
    received part of a packet that was cut off.
    """

    exit_status: int | None
    stdout: bytes
    stderr: bytes


class CommandTimeoutError(TimeoutError):
    """A one-shot command did not finish within its time limit.

    Attributes:
        stderr: What the command had written to stderr by then.
    """

    def __init__(self, message: str, stderr: bytes) -> None:
        super().__init__(message)
        self.stderr = stderr


def run_shell(
    address: ServerAddress,
    serial: str,
    args: Sequence[str],
    timeout: float | None = 30.0,
    cancelled: Callable[[], bool] | None = None,
    max_output: int | None = None,
) -> ShellResult:
    """Run a command on a device to completion and collect its output.

    ``timeout`` is one overall limit in seconds for connecting, the handshake
    and the whole command, however slowly its output trickles in. None means
    no limit on the command; connecting and the handshake then use
    ``DEFAULT_TIMEOUT``.

    When the connection ends without an exit status, the stderr of the result
    ends with the received part of a stderr packet that was cut off; its
    stdout holds only the packets that arrived whole. ``max_output`` limits
    stdout and stderr together, in bytes (None: no limit).

    Raises:
        TimeoutError: If everything did not finish within ``timeout`` seconds
            (a `CommandTimeoutError`, with the stderr received by then, the
            received part of an unfinished stderr packet included).
        LogprobeError: As :func:`open_shell`, or ``adb_error`` on a protocol
            violation or when the output exceeds ``max_output``.
        Cancelled: If ``cancelled`` is given and returned true; the socket is
            closed before this is raised.
    """
    out = bytearray()
    err = bytearray()
    deadline = None if timeout is None else time.monotonic() + timeout
    opened: ShellStream | None = None
    try:
        with open_shell(
            address, serial, args, deadline=deadline, cancelled=cancelled
        ) as stream:
            opened = stream
            stream.set_deadline(deadline)
            while (event := stream.read(cancelled)) is not None:
                (out if event[0] == "stdout" else err).extend(event[1])
                check_output(args, out, err, max_output)
    except TimeoutError:
        if opened is not None:
            err += opened.held_stderr()
        check_output(args, out, err, max_output)
        msg = f"command did not finish within {timeout} seconds"
        raise CommandTimeoutError(msg, bytes(err)) from None
    if stream.exit_status is None:  # the connection ended inside a packet
        err += stream.held_stderr()
        check_output(args, out, err, max_output)
    return ShellResult(stream.exit_status, bytes(out), bytes(err))


def check_output(
    args: Sequence[str], out: bytearray, err: bytearray, limit: int | None
) -> None:
    """Raise `output_too_long` when ``out`` and ``err`` together pass ``limit``.

    It runs after every whole packet and after the held part of a cut stderr
    packet is added, so the output kept is never over the limit; what the
    reader holds of an unfinished packet meanwhile is bounded by
    ``MAX_SHELL_PACKET``.
    """
    if limit is not None and len(out) + len(err) > limit:
        raise output_too_long(args, limit)


def output_too_long(args: Sequence[str], limit: int) -> LogprobeError:
    """The error for a command whose output passed ``limit`` bytes."""
    return protocol_error(
        f"the command wrote more than {limit} bytes of output",
        command=" ".join(args),
        limit=limit,
    )
