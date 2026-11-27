"""Opening a TCP connection to a numeric address, in slices that can be cancelled."""

from __future__ import annotations

import errno
import math
import os
import select
import socket
import sys
import time
from typing import TYPE_CHECKING

from logprobe._errors import LogprobeError

from .limits import TICK

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from .address import ServerAddress


class Cancelled(Exception):  # noqa: N818
    """A ``cancelled`` callback returned true; the call closed its own socket."""


_IN_PROGRESS = frozenset(
    {
        errno.EINPROGRESS,
        errno.EALREADY,
        errno.EWOULDBLOCK,
        errno.EINTR,
        getattr(errno, "WSAEWOULDBLOCK", errno.EWOULDBLOCK),
    }
)


def _wait_writable(sock: socket.socket, seconds: float) -> bool:
    """Wait up to ``seconds`` for ``sock`` to finish connecting or fail.

    ``select.select`` cannot be used on POSIX: it raises ``ValueError`` for a
    descriptor number of 1024 or more, which a process with many open files
    easily reaches. ``poll`` has no such limit; ``select`` is the fallback
    where ``poll`` does not exist (Windows).
    """
    if sys.platform == "win32":  # no poll; a failed connect shows in the third set
        _, writable, failed = select.select([], [sock], [sock], seconds)
        return bool(writable or failed)
    poller = select.poll()
    poller.register(sock.fileno(), select.POLLOUT | select.POLLERR)
    return bool(poller.poll(math.ceil(seconds * 1000)))


def _connect_sliced(
    sock: socket.socket,
    sockaddr: tuple[object, ...],
    limit: float,
    cancelled: Callable[[], bool],
) -> None:
    """Connect without blocking for more than ``TICK`` at a time.

    Raises:
        Cancelled: If ``cancelled()`` returned true between slices.
        TimeoutError: If the connection was not made by ``limit``
            (a ``time.monotonic()`` value).
        OSError: If the connection failed.
    """
    sock.settimeout(0.0)
    code = sock.connect_ex(sockaddr)
    if code == 0:
        return
    if code not in _IN_PROGRESS:
        raise OSError(code, os.strerror(code))
    while True:
        if cancelled():
            raise Cancelled
        left = limit - time.monotonic()
        if left <= 0:
            msg = "timed out"
            raise TimeoutError(msg)
        if _wait_writable(sock, min(TICK, left)):
            code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if code:
                raise OSError(code, os.strerror(code))
            return


def numeric_addrinfo(
    address: ServerAddress,
) -> Sequence[
    tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple[object, ...]]
]:
    """Return the socket addresses of ``address``, without any name lookup.

    The address is resolved with ``AI_NUMERICHOST | AI_NUMERICSERV``, so the
    operating system refuses any host that is not an IP literal instead of
    querying DNS, and the call never blocks.

    Raises:
        OSError: If the host is not numeric (:class:`socket.gaierror`).
    """
    # Bytes keep CPython from running its IDNA step, which would raise
    # UnicodeError (not OSError) for a long zone name.
    return socket.getaddrinfo(
        address.host.encode("ascii"),
        address.port,
        type=socket.SOCK_STREAM,
        flags=socket.AI_NUMERICHOST | socket.AI_NUMERICSERV,
    )


def _open_numeric(
    address: ServerAddress,
    timeout: float,
    cancelled: Callable[[], bool] | None = None,
) -> socket.socket:
    """Open a TCP connection to a numeric address, never looking up a name.

    Works like :func:`socket.create_connection`, but the address is resolved
    with ``AI_NUMERICHOST | AI_NUMERICSERV``, so the operating system refuses
    any host that is not an IP literal instead of querying DNS. The attempts
    run in the order the system returns; the last error is raised. With
    ``cancelled``, a pending connection attempt is checked every ``TICK``
    seconds and abandoned (its socket closed) when the callback returns true.

    Raises:
        OSError: If the host is not numeric (:class:`socket.gaierror`) or no
            connection could be made.
        Cancelled: If ``cancelled()`` returned true.
    """
    if cancelled is not None and cancelled():
        raise Cancelled
    infos = numeric_addrinfo(address)
    last_error: OSError | None = None
    for family, kind, proto, _canonname, sockaddr in infos:
        sock: socket.socket | None = None
        try:
            sock = socket.socket(family, kind, proto)
            if cancelled is None:
                sock.settimeout(timeout)
                sock.connect(sockaddr)
            else:
                _connect_sliced(sock, sockaddr, time.monotonic() + timeout, cancelled)
                sock.settimeout(timeout)
        except OSError as error:
            if sock is not None:
                sock.close()
            last_error = error
        except BaseException:
            if sock is not None:
                sock.close()
            raise
        else:
            return sock
    raise last_error or OSError("getaddrinfo returned no address")


def _can_connect(address: ServerAddress, timeout: float) -> OSError | None:
    """Try a plain TCP connection; return the error, or None on success."""
    try:
        _open_numeric(address, timeout).close()
    except OSError as error:
        return error
    return None


def unavailable(
    address: ServerAddress,
    *,
    allowed: bool | None,
    reason: str,
    error: object = None,
    extra: dict[str, object] | None = None,
) -> LogprobeError:
    """Build ``adb_server_unavailable``; None for ``allowed`` omits that detail."""
    details: dict[str, object] = {"host": address.host, "port": address.port}
    if allowed is not None:
        details["auto_start_allowed"] = allowed
    details["reason"] = reason
    if error is not None:
        details["error"] = str(error)
    if extra:
        details.update(extra)
    return LogprobeError(
        "adb_server_unavailable",
        f"cannot reach the adb server at {address.host}:{address.port} ({reason})",
        details,
    )
