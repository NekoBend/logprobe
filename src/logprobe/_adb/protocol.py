"""The smart-socket protocol: requests, replies, errors and host queries."""

from __future__ import annotations

import re
import socket
import time
from functools import partial
from typing import TYPE_CHECKING

from logprobe._errors import LogprobeError

from .limits import _MAX_PAYLOAD, DEFAULT_TIMEOUT, TICK
from .sockets import Cancelled, _open_numeric, unavailable

if TYPE_CHECKING:
    from collections.abc import Callable

    from .address import ServerAddress


# ---------------------------------------------------------------------------
# Wire protocol
# ---------------------------------------------------------------------------


def check_token(value: object, what: str) -> str:
    """Return ``value`` if it is safe to put into a request.

    Raises:
        TypeError: If it is not a string.
        ValueError: If it is empty or contains NUL or a line break.
    """
    if not isinstance(value, str):
        msg = f"{what} must be a string, not {type(value).__name__}"
        raise TypeError(msg)
    if not value:
        msg = f"{what} must not be empty"
        raise ValueError(msg)
    for bad, name in (("\0", "NUL"), ("\n", "newline"), ("\r", "carriage return")):
        if bad in value:
            msg = f"{what} must not contain a {name} character: {value!r}"
            raise ValueError(msg)
    return value


def encode_request(payload: str) -> bytes:
    """Frame a request: four lowercase hex digits of the length, then the payload."""
    data = payload.encode()
    if len(data) > _MAX_PAYLOAD:
        msg = f"request is too long ({len(data)} bytes, at most {_MAX_PAYLOAD})"
        raise ValueError(msg)
    return b"%04x" % len(data) + data


def protocol_error(message: str, **details: object) -> LogprobeError:
    return LogprobeError("adb_error", message, dict(details))


def connection_failed(error: BaseException) -> LogprobeError:
    """The error for a send or receive that failed with ``error``."""
    return protocol_error(f"connection to the adb server failed: {error}")


def server_timeout() -> LogprobeError:
    """The error for a receive that waited too long."""
    return protocol_error("timed out waiting for the adb server")


def server_closed() -> LogprobeError:
    """The error for a connection that ended before the reply was complete."""
    return protocol_error("the adb server closed the connection unexpectedly")


def connect_failed(address: ServerAddress, error: BaseException) -> LogprobeError:
    """The error for a connection attempt that failed with ``error``."""
    return unavailable(
        address,
        allowed=None,
        reason="the adb server stopped accepting connections",
        error=error,
    )


def _remaining(deadline: float) -> float:
    """Return the seconds left before ``deadline``.

    Raises:
        TimeoutError: If the deadline has passed.
    """
    left = deadline - time.monotonic()
    if left <= 0:
        msg = "the deadline has passed"
        raise TimeoutError(msg)
    return left


def _io[T](
    sock: socket.socket,
    operation: Callable[[], T],
    deadline: float | None,
    cancelled: Callable[[], bool] | None,
    idle: float | None,
) -> T:
    """Run one blocking socket call, honoring a deadline and a cancel callback.

    Without ``cancelled`` this sets the time left before ``deadline`` as the
    socket timeout (if there is a deadline) and runs ``operation`` once. With
    ``cancelled`` the wait is cut into slices of at most ``TICK`` seconds and
    ``cancelled()`` is asked before each; the wait is limited by ``deadline``,
    or, without one, by ``idle`` seconds for this one call (None: no limit).

    Raises:
        TimeoutError: If the deadline, or ``idle``, ran out.
        Cancelled: If ``cancelled()`` returned true. The socket is not closed
            here; the caller that owns it does that.
    """
    if cancelled is None:
        if deadline is not None:
            sock.settimeout(_remaining(deadline))
        return operation()
    limit = deadline
    if limit is None and idle is not None:
        limit = time.monotonic() + idle
    while True:
        if cancelled():
            raise Cancelled
        if limit is None:
            sock.settimeout(TICK)
        else:
            sock.settimeout(min(TICK, _remaining(limit)))
        try:
            return operation()
        except TimeoutError:
            continue


def _recv_exact(
    sock: socket.socket,
    size: int,
    deadline: float | None = None,
    cancelled: Callable[[], bool] | None = None,
    idle: float | None = None,
) -> bytes:
    """Read exactly ``size`` bytes.

    With a ``deadline`` (``time.monotonic()`` value) every recv gets the time
    left as its timeout and running out raises ``TimeoutError``; without one,
    the timeout already set on the socket applies (or ``idle``, when
    ``cancelled`` is given) and expiry is an ``adb_error``.
    """
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        try:
            chunk = _io(sock, partial(sock.recv, remaining), deadline, cancelled, idle)
        except TimeoutError as error:
            if deadline is not None:
                raise
            raise server_timeout() from error
        except OSError as error:
            raise connection_failed(error) from error
        if not chunk:
            raise server_closed()
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _send_all(
    sock: socket.socket,
    data: bytes,
    deadline: float | None,
    cancelled: Callable[[], bool] | None,
    idle: float | None,
) -> None:
    """Send all of ``data``; with ``cancelled`` in slices, never repeating bytes."""
    if cancelled is None:
        _io(sock, lambda: sock.sendall(data), deadline, None, None)
        return
    view = memoryview(data)
    while view:
        sent = _io(sock, partial(sock.send, view), deadline, cancelled, idle)
        view = view[sent:]


_HEX4 = re.compile(rb"[0-9a-fA-F]{4}")


def decode_length(raw: bytes) -> int:
    """Return the value of a length field: exactly four ASCII hex digits."""
    if _HEX4.fullmatch(raw) is None:
        raise protocol_error(
            "the adb server sent an invalid length", raw=raw.decode(errors="replace")
        )
    return int(raw, 16)


def _read_length(
    sock: socket.socket,
    deadline: float | None = None,
    cancelled: Callable[[], bool] | None = None,
    idle: float | None = None,
) -> int:
    """Read a length field: exactly four ASCII hex digits, nothing else."""
    return decode_length(_recv_exact(sock, 4, deadline, cancelled, idle))


_DEVICE_NOT_FOUND = re.compile(r"device '.*' not found|no devices/emulators found")


def failure(message: str, serial: str | None) -> LogprobeError:
    """Turn a FAIL message into the most specific LogprobeError."""
    details: dict[str, object] = {} if serial is None else {"serial": serial}
    if _DEVICE_NOT_FOUND.search(message):
        return LogprobeError("device_not_found", message, details)
    if message.startswith("device offline"):
        return LogprobeError("device_offline", message, details)
    if message.startswith("device unauthorized"):
        return LogprobeError("device_unauthorized", message, details)
    return LogprobeError("adb_error", message, details)


def status_is_okay(status: bytes) -> bool:
    """Tell a four-byte reply status apart: True for OKAY, False for FAIL.

    Raises:
        LogprobeError: ``adb_error`` for anything else.
    """
    if status == b"OKAY":
        return True
    if status == b"FAIL":
        return False
    raise protocol_error(
        "the adb server sent an invalid status", status=status.decode(errors="replace")
    )


def transport_request(serial: str) -> str:
    """The request that selects the device a later request talks to."""
    return f"host:transport:{serial}"


def features_request(serial: str) -> str:
    """The request that lists the adb features of a device."""
    return f"host-serial:{serial}:features"


def shell_request(command: str) -> str:
    """The request that starts ``command`` with the shell protocol v2."""
    return f"shell,v2,raw:{command}"


def _send_request(
    sock: socket.socket,
    payload: str,
    serial: str | None,
    deadline: float | None = None,
    cancelled: Callable[[], bool] | None = None,
    idle: float | None = None,
) -> None:
    """Send a request and consume the OKAY/FAIL status."""
    try:
        _send_all(sock, encode_request(payload), deadline, cancelled, idle)
    except OSError as error:
        if deadline is not None and isinstance(error, TimeoutError):
            raise
        raise connection_failed(error) from error
    if status_is_okay(_recv_exact(sock, 4, deadline, cancelled, idle)):
        return
    size = _read_length(sock, deadline, cancelled, idle)
    message = _recv_exact(sock, size, deadline, cancelled, idle)
    raise failure(message.decode(errors="replace"), serial)


def connect(
    address: ServerAddress,
    timeout: float = DEFAULT_TIMEOUT,
    deadline: float | None = None,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> socket.socket:
    """Open a connection to the adb server.

    ``timeout`` limits the connection attempt. With a ``deadline`` (a
    ``time.monotonic()`` value) the time left replaces it, and running out
    raises ``TimeoutError``. With ``cancelled``, the attempt is checked every
    ``TICK`` seconds and raises :class:`Cancelled` when the callback returns
    true.
    """
    try:
        sock = _open_numeric(
            address, timeout if deadline is None else _remaining(deadline), cancelled
        )
    except OSError as error:
        if deadline is not None and isinstance(error, TimeoutError):
            raise
        raise connect_failed(address, error) from error
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def host_query(
    address: ServerAddress,
    payload: str,
    *,
    serial: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    cancelled: Callable[[], bool] | None = None,
) -> bytes:
    """Send one ``host:`` request and return its length-prefixed reply.

    ``timeout`` limits the connection attempt, and then once more the whole
    exchange after it: a reply that trickles in byte by byte cannot keep the
    call waiting longer than that.

    Raises:
        LogprobeError: ``adb_error`` when the exchange does not finish within
            ``timeout`` seconds after connecting.
        Cancelled: If ``cancelled`` is given and returned true; the socket is
            closed before this is raised.
    """
    sock = connect(address, timeout, cancelled=cancelled)
    try:
        deadline = time.monotonic() + timeout
        _send_request(sock, payload, serial, deadline, cancelled)
        size = _read_length(sock, deadline, cancelled)
        return _recv_exact(sock, size, deadline, cancelled)
    except TimeoutError as error:
        raise server_timeout() from error
    finally:
        sock.close()


def server_version(address: ServerAddress, timeout: float = DEFAULT_TIMEOUT) -> int:
    """Return the adb server's protocol version (``host:version``)."""
    reply = host_query(address, "host:version", timeout=timeout)
    if _HEX4.fullmatch(reply) is None:
        raise protocol_error(
            "the adb server sent an invalid version",
            reply=reply.decode(errors="replace"),
        )
    return int(reply, 16)
