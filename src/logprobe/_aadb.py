"""The adb smart-socket client on asyncio.

This is the counterpart of the blocking client in :mod:`logprobe._adb` for
code that runs on an event loop. It shares the blocking client's protocol
functions (request texts, status and length parsing, the FAIL message to
error mapping, the shell protocol decoder), so the two cannot disagree about
what goes on the wire; only the reading and writing differ.

Everything here uses asyncio streams only. No thread, no executor and no
process is ever started, and no adb server is started. The code does not
depend on a particular event loop, so it works on Windows' default proactor
loop as well as on the selector loop.

Time limits are ``asyncio.timeout`` blocks. Cancelling a task closes the
connection the call has open and lets ``CancelledError`` pass unchanged. A
cancelled :meth:`AsyncShellStream.read` is the exception: it leaves the stream
open for the next read, and the stream's owner closes it with ``close()`` or
``async with``.
"""

from __future__ import annotations

import asyncio
import socket
from collections import deque
from typing import TYPE_CHECKING

from logprobe._adb import (
    CLOSE_STDIN,
    DEFAULT_TIMEOUT,
    RECV_SIZE,
    ServerAddress,
    ShellEvent,
    ShellResult,
    ShellV2Decoder,
    check_shell_v2,
    check_token,
    collect_events,
    collect_parts,
    connect_failed,
    connection_failed,
    decode_length,
    device_command,
    encode_request,
    failure,
    features_request,
    numeric_addrinfo,
    parse_features,
    server_closed,
    server_timeout,
    shell_request,
    status_is_okay,
    transport_request,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence
    from types import TracebackType

    from logprobe._errors import LogprobeError


class _Reader(asyncio.StreamReader):
    """A stream reader that remembers why its connection was lost."""

    lost: Exception | None = None


class _Protocol(asyncio.StreamReaderProtocol):
    """Report a lost connection to the reader as end of stream.

    ``StreamReader.read`` raises a stored connection error before it returns
    the data already received, so a reset would swallow output that arrived
    before it. Handing the reader a plain end of stream keeps that data
    readable; the error is kept in ``reader.lost`` for the callers that need
    to tell a reset from an orderly close.
    """

    def __init__(self, reader: _Reader, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__(reader, loop=loop)
        self._lost_reader = reader

    def connection_lost(self, exc: Exception | None) -> None:
        self._lost_reader.lost = exc
        super().connection_lost(None)


type _Connection = tuple[_Reader, asyncio.StreamWriter]


def _timed_out() -> TimeoutError:
    return TimeoutError("timed out")


async def _within[T](
    step: Awaitable[T], limit: float | None, on_timeout: Callable[[], Exception]
) -> T:
    """Await ``step`` for at most ``limit`` seconds (None: no limit).

    Raises ``on_timeout()`` when this limit ran out. A ``TimeoutError`` that
    comes from elsewhere (an enclosing limit, the operating system) is not
    this one and passes on unchanged.
    """
    scope = asyncio.timeout(limit)
    try:
        async with scope:
            return await step
    except TimeoutError:
        if scope.expired():
            raise on_timeout() from None
        raise


def _drop(writer: asyncio.StreamWriter) -> None:
    """Close the connection at once, without waiting for unsent data."""
    writer.transport.abort()


async def _attempt(
    loop: asyncio.AbstractEventLoop,
    info: tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple[object, ...]],
) -> _Connection:
    family, kind, proto, _name, sockaddr = info
    sock = socket.socket(family, kind, proto)
    try:
        sock.settimeout(0)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        await loop.sock_connect(sock, sockaddr)
        reader = _Reader(loop=loop)
        transport, protocol = await loop.create_connection(
            lambda: _Protocol(reader, loop), sock=sock
        )
        return reader, asyncio.StreamWriter(transport, protocol, reader, loop)
    except BaseException:
        sock.close()
        raise


async def _connect(address: ServerAddress, limit: float | None) -> _Connection:
    """Connect to the adb server; every attempt is limited to ``limit`` seconds.

    Raises:
        LogprobeError: ``adb_server_unavailable`` if no attempt succeeded.
    """
    loop = asyncio.get_running_loop()
    last_error: OSError | None = None
    try:
        infos = numeric_addrinfo(address)
    except OSError as error:
        raise connect_failed(address, error) from error
    for info in infos:
        try:
            return await _within(_attempt(loop, info), limit, _timed_out)
        except OSError as error:
            last_error = error
    raise connect_failed(
        address, last_error or OSError("getaddrinfo returned no address")
    ) from last_error


async def _send(writer: asyncio.StreamWriter, data: bytes, limit: float | None) -> None:
    try:
        writer.write(data)
        await _within(writer.drain(), limit, _timed_out)
    except OSError as error:
        raise connection_failed(error) from error


async def _receive(reader: _Reader, size: int, limit: float | None) -> bytes:
    """Read exactly ``size`` bytes; ``limit`` applies to each receive.

    Like the blocking client, this is an idle limit: a reply that trickles in
    keeps going as long as no single wait outlasts ``limit``.
    """
    buffer = bytearray()
    while len(buffer) < size:
        chunk = await _within(reader.read(size - len(buffer)), limit, server_timeout)
        if not chunk:
            if reader.lost is not None:
                raise connection_failed(reader.lost) from reader.lost
            raise server_closed()
        buffer.extend(chunk)
    return bytes(buffer)


async def _request(
    connection: _Connection, payload: str, serial: str | None, limit: float | None
) -> None:
    """Send a request and consume the OKAY/FAIL status."""
    reader, writer = connection
    await _send(writer, encode_request(payload), limit)
    if status_is_okay(await _receive(reader, 4, limit)):
        return
    size = decode_length(await _receive(reader, 4, limit))
    message = await _receive(reader, size, limit)
    raise failure(message.decode(errors="replace"), serial)


async def ahost_query(
    address: ServerAddress,
    payload: str,
    *,
    serial: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> bytes:
    """Send one ``host:`` request and return its length-prefixed reply.

    ``timeout`` limits each step (connecting, sending, each read) on its own.
    """
    connection = await _connect(address, timeout)
    try:
        await _request(connection, payload, serial, timeout)
        size = decode_length(await _receive(connection[0], 4, timeout))
        return await _receive(connection[0], size, timeout)
    finally:
        _drop(connection[1])


async def adevice_features(
    address: ServerAddress, serial: str, timeout: float = DEFAULT_TIMEOUT
) -> frozenset[str]:
    """Return the device's feature names (``host-serial:<serial>:features``)."""
    check_token(serial, "serial")
    reply = await ahost_query(
        address, features_request(serial), serial=serial, timeout=timeout
    )
    return parse_features(reply)


async def arequire_shell_v2(
    address: ServerAddress, serial: str, timeout: float = DEFAULT_TIMEOUT
) -> None:
    """Check that the device supports the shell protocol v2.

    Raises:
        LogprobeError: ``adb_error`` if the device does not list the
            ``shell_v2`` feature; ``details["missing_feature"]`` names it.
    """
    check_shell_v2(await adevice_features(address, serial, timeout), serial)


class AsyncShellStream:
    """Decoder for a shell protocol v2 connection to a device command.

    Await :meth:`read` repeatedly until it returns None. ``exit_status`` holds
    the command's exit status once :meth:`read` has returned None; it is None
    before that, and stays None when the connection closed without an exit
    packet.

    :meth:`read` may be cancelled (by ``asyncio.timeout`` or by its task)
    without harm: it only waits for bytes, and what it has already decoded
    stays in the stream, so the next call carries on without losing or
    repeating anything. Cancelling does not close the stream; the owner does,
    with :meth:`close` or ``async with``.
    """

    def __init__(self, reader: _Reader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer
        self._decoder = ShellV2Decoder()
        self._pending: deque[ShellEvent] = deque()
        self._partial = bytearray()
        self._error: LogprobeError | None = None
        self._status: int | None = None
        self._finished = False
        self._closed = False
        self._timeout: float | None = None
        self.exit_status: int | None = None

    async def __aenter__(self) -> AsyncShellStream:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def set_timeout(self, timeout: float | None) -> None:
        """Set how long one network read may wait for bytes (None: forever).

        A read that waits longer raises ``TimeoutError``. Like any cut read it
        loses nothing: the stream stays open, and the next call carries on.
        Each read that brings bytes starts the time again, even when the bytes
        complete no event (part of a packet header, for example).
        """
        self._timeout = timeout

    async def read(self) -> ShellEvent | None:
        """Return the next stdout or stderr event, or None at the end.

        An event is the output of one whole packet: a connection that drops in
        the middle of a packet delivers none of it.

        Only output events come back: ``("stdout", bytes)`` or
        ``("stderr", bytes)``. The exit status is not an event; read it from
        :attr:`exit_status` after the end.

        Raises:
            LogprobeError: ``adb_error`` if the device sent an empty exit
                packet. Output received before it is returned first, the
                stream is closed, and later reads return None.
        """
        return await self._next(parts=False)

    async def read_part(self) -> ShellEvent | None:
        """Like :meth:`read`, but returns output as it arrives.

        Each event is the part of one packet that one network read brought: it
        is returned at once, without waiting for the rest of the packet, so a
        connection that drops in the middle of a packet still delivers what
        arrived. Use either this or :meth:`read` on one stream, not both.
        Cancelling is as harmless as for :meth:`read`.
        """
        return await self._next(parts=True)

    async def _next(self, *, parts: bool) -> ShellEvent | None:
        while True:
            if self._pending:
                return self._pending.popleft()
            if self._error is not None:
                error, self._error = self._error, None
                self.close()
                raise error
            if self._finished:
                self.exit_status = self._status
                self.close()
                return None
            await self._fill(parts=parts)

    async def _fill(self, *, parts: bool) -> None:
        if self._closed:
            self._finished = True
            return
        # A reset after output arrived reads as the end of the stream, as in
        # the blocking stream: the output stays readable, there is no status.
        if self._timeout is None:
            chunk = await self._reader.read(RECV_SIZE)
        else:
            async with asyncio.timeout(self._timeout):
                chunk = await self._reader.read(RECV_SIZE)
        if not chunk:
            self._finished = True
            return
        if parts:
            status, error = collect_parts(self._decoder, chunk, self._pending)
        else:
            status, error = collect_events(
                self._decoder, chunk, self._partial, self._pending
            )
        if status is not None:
            # Whatever follows the exit packet in the same read is ignored.
            self._status = status
            self._finished = True
        elif error is not None:
            self._error = error
            self._finished = True

    def decoded(self) -> int:
        """The number of events decoded already and not returned yet.

        They came with an earlier network read: returning them needs no new
        one. Closing the stream keeps them readable.
        """
        return len(self._pending)

    def close(self) -> None:
        """Close the connection at once. Safe to call more than once."""
        if self._closed:
            return
        self._closed = True
        _drop(self._writer)


async def _open(
    address: ServerAddress, serial: str, args: Sequence[str], limit: float | None
) -> AsyncShellStream:
    check_token(serial, "serial")
    command = device_command(args)
    connection = await _connect(address, limit)
    try:
        await _request(connection, transport_request(serial), serial, limit)
        await _request(connection, shell_request(command), serial, limit)
        # Close the command's stdin at once, so a command that reads it gets
        # EOF instead of waiting until the connection closes.
        await _send(connection[1], CLOSE_STDIN, limit)
    except BaseException:
        _drop(connection[1])
        raise
    return AsyncShellStream(*connection)


async def aopen_shell(
    address: ServerAddress,
    serial: str,
    args: Sequence[str],
    *,
    timeout: float | None = DEFAULT_TIMEOUT,
) -> AsyncShellStream:
    """Start ``args`` on a device and return its output stream.

    ``timeout`` limits each step of connecting and the handshake on its own
    (None: no limit per step, for a caller that limits the whole call itself,
    with ``asyncio.timeout`` or by cancelling the task);
    afterwards reads wait until data arrives, so a caller that needs a limit
    wraps :meth:`AsyncShellStream.read` in ``asyncio.timeout`` or calls
    :meth:`AsyncShellStream.set_timeout`. If the task is
    cancelled during the handshake the connection is closed and
    ``CancelledError`` propagates.
    """
    return await _open(address, serial, args, timeout)


async def arun_shell(
    address: ServerAddress,
    serial: str,
    args: Sequence[str],
    timeout: float | None = 30.0,
) -> ShellResult:
    """Run a command on a device to completion and collect its output.

    ``timeout`` is one overall limit in seconds for connecting, the handshake
    and the whole command, however slowly its output trickles in. None means
    no limit on the command; connecting and the handshake then use
    ``DEFAULT_TIMEOUT`` for each step.

    Raises:
        TimeoutError: If everything did not finish within ``timeout`` seconds.
        LogprobeError: As :func:`aopen_shell`, or ``adb_error`` on a protocol
            violation.
    """
    out = bytearray()
    err = bytearray()
    scope = asyncio.timeout(timeout)
    try:
        async with scope:
            step = DEFAULT_TIMEOUT if timeout is None else None
            async with await _open(address, serial, args, step) as stream:
                while (event := await stream.read()) is not None:
                    (out if event[0] == "stdout" else err).extend(event[1])
    except TimeoutError:
        if not scope.expired():
            raise
        msg = f"command did not finish within {timeout} seconds"
        raise TimeoutError(msg) from None
    return ShellResult(stream.exit_status, bytes(out), bytes(err))
