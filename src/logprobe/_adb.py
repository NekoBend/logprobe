"""A minimal client for the adb server's "smart socket" protocol.

Instead of running the ``adb`` command for every operation, this module talks
to the adb server over TCP. A request is four lowercase hex digits giving the
payload length, followed by the payload. The server answers ``OKAY`` or
``FAIL`` (the latter followed by a four-digit length and a message).

The only subprocess ever started here is ``adb start-server``.
"""

from __future__ import annotations

import contextlib
import errno
import ipaddress
import math
import os
import re
import select
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from logprobe._errors import LogprobeError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from types import TracebackType

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5037
DEFAULT_TIMEOUT = 10.0
START_SERVER_TIMEOUT = 20.0
RECV_SIZE = 64 * 1024
# With a ``cancelled`` callback, no blocking wait lasts longer than this many
# seconds before the callback is asked again.
TICK = 0.25
_MAX_PAYLOAD = 0xFFFF

type ShellEvent = tuple[Literal["stdout", "stderr"], bytes]
type ShellPiece = tuple[Literal["stdout", "stderr"], memoryview, bool]

# ---------------------------------------------------------------------------
# Server address
# ---------------------------------------------------------------------------

_TCP_ADDRESS = re.compile(r"tcp:(?P<host>.*):(?P<port>[0-9]{1,5})", re.DOTALL)

# A zone is one or more dot-separated labels of letters, digits, "_" and "-"
# (an interface name such as "eth0" or "br-1.5", or a number such as "12").
_SCOPE_ID = re.compile(r"[0-9A-Za-z_-]+(\.[0-9A-Za-z_-]+)*")
_SCOPE_ID_MAX = 63
_PORT_MAX_DIGITS = 5
_ZONE_RULE = (
    "an IPv6 zone after '%' must be letters, digits, '_' and '-' in "
    "dot-separated non-empty labels, at most 63 characters in all"
)

_FORM = "tcp:HOST:PORT"
_HOST_RULE = (
    "HOST must be an IP address (IPv4 such as 127.0.0.1, or IPv6 in square "
    "brackets such as [::1]); the name 'localhost' is also accepted; other "
    "host names are not resolved, so write the IP address"
)


@dataclass(frozen=True, slots=True)
class ServerAddress:
    """Where the adb server listens, and whether that is the default.

    ``host`` is always a numeric IP address in canonical form (IPv6 without
    brackets), so connecting to it never involves a name lookup.
    """

    host: str
    port: int
    is_default: bool


def _scope_id_is_valid(scope_id: str | None) -> bool:
    """Whether an IPv6 zone is absent or a short, plain interface name or index."""
    return scope_id is None or (
        len(scope_id) <= _SCOPE_ID_MAX and _SCOPE_ID.fullmatch(scope_id) is not None
    )


def _canonical_host(text: str) -> str | None:
    """Return the canonical numeric form of ``text``, or None if not allowed.

    Allowed: an IPv4 address, an IPv6 address in square brackets (an optional
    scope id such as ``%eth0`` is kept when it is at most 63 characters of
    letters, digits, ``_`` and ``-``, in non-empty labels separated by dots),
    and ``localhost`` in any letter case, which becomes ``127.0.0.1`` without
    any name resolution.
    """
    if text.startswith("[") and text.endswith("]"):
        try:
            address = ipaddress.ip_address(text[1:-1])
        except ValueError:
            return None
        if address.version != 6 or not _scope_id_is_valid(address.scope_id):
            return None
        return str(address)
    if text.lower() == "localhost":
        return DEFAULT_HOST
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    return str(address) if address.version == 4 else None


def _has_rejected_scope_id(text: str) -> bool:
    """Whether ``text`` is a bracketed IPv6 address whose only fault is its zone."""
    if not (text.startswith("[") and text.endswith("]")):
        return False
    try:
        address = ipaddress.ip_address(text[1:-1])
    except ValueError:
        return False
    return address.version == 6 and not _scope_id_is_valid(address.scope_id)


def _parse_tcp_address(value: str) -> tuple[str, int] | str:
    """Parse ``tcp:HOST:PORT``; return ``(host, port)`` or a problem text."""
    match = _TCP_ADDRESS.fullmatch(value)
    if match is None:
        return f"must look like '{_FORM}'"
    port = int(match["port"])
    if not 1 <= port <= 65535:
        return f"must look like '{_FORM}' with a port from 1 to 65535"
    host = _canonical_host(match["host"])
    if host is None:
        problem = f"must look like '{_FORM}', where {_HOST_RULE}"
        if _has_rejected_scope_id(match["host"]):
            problem += f"; {_ZONE_RULE}"
        return problem
    return host, port


def resolve_server_address(explicit: str | None = None) -> ServerAddress:
    """Work out the adb server address.

    Order: the explicit ``tcp:HOST:PORT`` argument, the environment variable
    ``ADB_SERVER_SOCKET`` (same form), ``ANDROID_ADB_SERVER_PORT`` (port only,
    host 127.0.0.1), then 127.0.0.1:5037.

    HOST must be an IP address literal: IPv4 (``127.0.0.1``) or IPv6 in square
    brackets (``[::1]``, also with a scope id such as ``[fe80::1%eth0]``; a
    numeric zone index such as ``[fe80::1%12]`` is the portable form, because
    interface names differ between platforms). The name ``localhost`` (any
    letter case) is accepted and becomes ``127.0.0.1`` without a lookup. Every
    other host name is rejected before any network activity, so logprobe never
    sends a DNS query. (The adb command itself may accept host names; logprobe
    does not.)
    The returned address holds the canonical numeric host.

    Raises:
        TypeError: If ``explicit`` is neither None nor a string.
        ValueError: If ``explicit`` is malformed or its HOST is not allowed.
        LogprobeError: ``usage_error`` if an environment variable is malformed
            or ``ADB_SERVER_SOCKET`` has a HOST that is not allowed.
    """
    if explicit is not None:
        if not isinstance(explicit, str):
            msg = f"adb_server must be a string, not {type(explicit).__name__}"
            raise TypeError(msg)
        parsed = _parse_tcp_address(explicit)
        if isinstance(parsed, str):
            msg = f"adb_server {parsed}, got {explicit!r}"
            raise ValueError(msg)
        return ServerAddress(parsed[0], parsed[1], is_default=False)

    socket_env = os.environ.get("ADB_SERVER_SOCKET")
    if socket_env:
        parsed = _parse_tcp_address(socket_env)
        if isinstance(parsed, str):
            raise LogprobeError(
                "usage_error",
                f"ADB_SERVER_SOCKET {parsed}, got {socket_env!r}",
                {"variable": "ADB_SERVER_SOCKET"},
            )
        return ServerAddress(parsed[0], parsed[1], is_default=False)

    port_env = os.environ.get("ANDROID_ADB_SERVER_PORT")
    if port_env:
        # A port has at most 5 digits; checking the length first keeps int()
        # away from digit strings beyond Python's int conversion limit.
        if not (
            len(port_env) <= _PORT_MAX_DIGITS
            and port_env.isascii()
            and port_env.isdigit()
            and 1 <= int(port_env) <= 65535
        ):
            raise LogprobeError(
                "usage_error",
                "ANDROID_ADB_SERVER_PORT must be a port number (1-65535), "
                f"got {port_env!r}",
                {"variable": "ANDROID_ADB_SERVER_PORT"},
            )
        return ServerAddress(DEFAULT_HOST, int(port_env), is_default=False)

    return ServerAddress(DEFAULT_HOST, DEFAULT_PORT, is_default=True)


# ---------------------------------------------------------------------------
# adb executable and server start
# ---------------------------------------------------------------------------


# A PATHEXT extension that is tried: a dot, then no path separator or colon.
_EXTENSION = re.compile(r"\.[^\\/:]+")


def _which(command: str, *, windows: bool | None = None) -> str | None:
    """Like ``shutil.which``, but never relative to the current directory on Windows.

    ``shutil.which`` may try the current directory first on Windows, so a stray
    ``adb.exe`` in the working directory would be run. Here a bare command name
    is searched only in the fully qualified ``PATH`` entries (a drive and a
    root, or a UNC share): an empty entry, ``.``, ``./``, ``bin``, ``\\tools``,
    ``C:tools`` or any other entry that Windows would resolve against the
    current directory or drive is skipped. Only ``PATHEXT`` extensions without
    a path separator or colon are tried, so a candidate stays inside its
    ``PATH`` entry. A command that contains a directory part is checked as
    given. ``windows`` forces the platform for tests; the default is the real
    one.
    """
    if windows is None:
        windows = sys.platform == "win32"
    if not windows or Path(command).name != command:
        return shutil.which(command)
    extensions = [
        ext
        for ext in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";")
        if _EXTENSION.fullmatch(ext)
    ]
    if any(command.lower().endswith(ext.lower()) for ext in extensions):
        names = [command]
    else:
        names = [command + ext for ext in extensions]
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry or not Path(entry).is_absolute():
            continue
        for name in names:
            candidate = Path(entry, name)
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    return None


def find_adb(explicit: str | None = None) -> str | None:
    """Locate the ``adb`` executable, or return None.

    Order: the explicit argument, the environment variable ``LOGPROBE_ADB``,
    ``adb`` on ``PATH``, then ``platform-tools/adb`` under ``ANDROID_HOME`` and
    ``ANDROID_SDK_ROOT``. The first place that is set decides for the explicit
    argument and ``LOGPROBE_ADB``: if what they name is not an executable,
    the result is None rather than a silent fall-back to another adb.
    On Windows ``PATH`` entries and SDK variables that are not fully qualified
    paths are skipped, so no directory is resolved against the current
    directory (see `_which`; a bare name given explicitly, such as ``adb``,
    is searched the same way). The SDK path is checked as it is, with no
    ``PATHEXT`` extension added.
    """
    if explicit is not None:
        return _which(explicit)
    from_env = os.environ.get("LOGPROBE_ADB")
    if from_env:
        return _which(from_env)
    on_path = _which("adb")
    if on_path is not None:
        return on_path
    windows = sys.platform == "win32"
    name = "adb.exe" if windows else "adb"
    for variable in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        root = os.environ.get(variable)
        if root and (not windows or Path(root).is_absolute()):
            candidate = Path(root, "platform-tools", name)
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    return None


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
) -> list[tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple[object, ...]]]:
    """Return the socket addresses of ``address``, without any name lookup.

    The address is resolved with ``AI_NUMERICHOST | AI_NUMERICSERV``, so the
    operating system refuses any host that is not an IP literal instead of
    querying DNS, and the call never blocks.

    Raises:
        OSError: If the host is not numeric (:class:`socket.gaierror`).
    """
    # Bytes keep CPython from running its IDNA step, which would raise
    # UnicodeError (not OSError) for a long zone name.
    return socket.getaddrinfo(  # ty: ignore[invalid-return-type]
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


_OUTPUT_LIMIT = 2000

# Variables that make adb itself talk to, or start a server on, another
# address. logprobe never passes them on to ``adb start-server``.
_SERVER_ADDRESS_VARIABLES = (
    "ADB_SERVER_SOCKET",
    "ANDROID_ADB_SERVER_ADDRESS",
    "ANDROID_ADB_SERVER_PORT",
)


_NO_CWD_SEARCH = "NoDefaultCurrentDirectoryInExePath"


def _start_server_environment(*, windows: bool | None = None) -> dict[str, str]:
    """Environment for ``adb start-server``: the default local server only.

    On Windows ``NoDefaultCurrentDirectoryInExePath`` is set too (unless it is
    set already), so that a ``.bat`` or ``.cmd`` found as adb, which runs
    through ``cmd.exe``, does not look up the commands it runs in the current
    directory. ``windows`` forces the platform for tests.
    """
    if windows is None:
        windows = sys.platform == "win32"
    env = {
        name: value
        for name, value in os.environ.items()
        if name not in _SERVER_ADDRESS_VARIABLES
    }
    env["ADB_MDNS"] = "0"
    # Windows names are case-insensitive, and os.environ keeps them uppercase.
    if windows and _NO_CWD_SEARCH.upper() not in {name.upper() for name in env}:
        env[_NO_CWD_SEARCH] = "1"
    return env


def _output_text(data: bytes | str | None) -> str:
    """Decode captured process output and cap it at ``_OUTPUT_LIMIT`` characters."""
    if data is None:
        return ""
    text = data if isinstance(data, str) else data.decode(errors="replace")
    return text[:_OUTPUT_LIMIT]


def ensure_server(
    address: ServerAddress,
    *,
    adb: str | None,
    start_server: bool,
    timeout: float = DEFAULT_TIMEOUT,
) -> None:
    """Make sure the adb server accepts connections, starting it if allowed.

    ``adb start-server`` runs once, and only when all of these hold: the
    caller allows it, the address is the default one, the server does not
    accept a TCP connection, the adb executable is found, and the environment
    variable ``ANDROID_ADB_SERVER_ADDRESS`` is not set to a non-empty value.
    (adb reads that variable and logprobe does not; when it is set, the user's
    adb talks to another server, so logprobe does not start a local one behind
    their back.)

    The command runs with a copy of the environment from which
    ``ADB_SERVER_SOCKET``, ``ANDROID_ADB_SERVER_ADDRESS`` and
    ``ANDROID_ADB_SERVER_PORT`` are removed, so it can only start the default
    local server, and with ``ADB_MDNS=0`` added, so that the server it starts
    does not send mDNS discovery queries on the local network. On Windows
    ``NoDefaultCurrentDirectoryInExePath=1`` is added as well, unless it is set.

    Raises:
        LogprobeError: ``adb_server_unavailable`` when the server stays
            unreachable; ``details`` says why no start was attempted or why
            it did not help. When ``adb start-server`` ran but the server is
            still unreachable, ``start_server_returncode`` and
            ``start_server_output`` (stderr, else stdout, at most 2000
            characters) are included; after a timeout only the output.
    """
    error = _can_connect(address, timeout)
    if error is None:
        return
    allowed = start_server and address.is_default
    if not start_server:
        raise unavailable(
            address, allowed=allowed, reason="start_server is disabled", error=error
        )
    if not address.is_default:
        raise unavailable(
            address,
            allowed=allowed,
            reason="the server address was set explicitly, so it is not started",
            error=error,
        )
    if os.environ.get("ANDROID_ADB_SERVER_ADDRESS"):
        raise unavailable(
            address,
            allowed=False,
            reason=(
                "the environment variable ANDROID_ADB_SERVER_ADDRESS is set; "
                "adb reads it but logprobe does not use it, so the server is "
                "not started; to point logprobe at a server, set "
                "ADB_SERVER_SOCKET=tcp:IP:PORT"
            ),
            error=error,
        )
    executable = find_adb(adb)
    if executable is None:
        raise unavailable(
            address,
            allowed=allowed,
            reason="the adb executable was not found",
            error=error,
        )
    try:
        completed = subprocess.run(
            [executable, "start-server"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=START_SERVER_TIMEOUT,
            check=False,
            env=_start_server_environment(),
        )
    except (OSError, subprocess.SubprocessError) as start_error:
        extra: dict[str, object] = {}
        if isinstance(start_error, subprocess.TimeoutExpired) and start_error.stderr:
            extra["start_server_output"] = _output_text(start_error.stderr)
        raise unavailable(
            address,
            allowed=allowed,
            reason="'adb start-server' failed",
            error=start_error,
            extra=extra,
        ) from start_error
    error = _can_connect(address, timeout)
    if error is not None:
        raise unavailable(
            address,
            allowed=allowed,
            reason="the server is still unreachable after 'adb start-server'",
            error=error,
            extra={
                "start_server_returncode": completed.returncode,
                "start_server_output": _output_text(
                    completed.stderr or completed.stdout
                ),
            },
        )


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

    Raises:
        Cancelled: If ``cancelled`` is given and returned true; the socket is
            closed before this is raised.
    """
    sock = connect(address, timeout, cancelled=cancelled)
    try:
        _send_request(sock, payload, serial, None, cancelled, timeout)
        size = _read_length(sock, None, cancelled, timeout)
        return _recv_exact(sock, size, None, cancelled, timeout)
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


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    """A device as reported by the adb server.

    ``state`` is adb's own word (``device``, ``offline``, ``unauthorized``,
    ...). The other fields are None when adb did not report them.
    """

    serial: str
    state: str
    model: str | None = None
    product: str | None = None
    device: str | None = None
    transport_id: str | None = None


_INFO_KEYS = frozenset({"model", "product", "device", "transport_id"})
_PROPERTY = re.compile(r"[a-z_]+:\S+")
_NO_SERIAL = "(no serial number)"


def parse_devices(text: str) -> list[DeviceInfo]:
    """Parse the output of ``host:devices-l``.

    A line is the serial, the state, then ``key:value`` properties. The serial
    is the first token (except the literal ``(no serial number)``), the
    properties are the trailing ``key:value`` tokens, and the state is
    whatever lies between, which may contain spaces, as in ``no permissions
    (user in plugdev group; ...); see [http://...]``. Properties other than
    ``model``, ``product``, ``device`` and ``transport_id`` are dropped.
    """
    result: list[DeviceInfo] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith(_NO_SERIAL):
            serial, rest = _NO_SERIAL, line[len(_NO_SERIAL) :]
        else:
            serial, _, rest = line.partition(" ")
        tokens = rest.split()
        if not serial or not tokens:
            continue
        fields: dict[str, str] = {}
        while len(tokens) > 1 and _PROPERTY.fullmatch(tokens[-1]):
            key, _, value = tokens.pop().partition(":")
            if key in _INFO_KEYS:
                fields[key] = value
        result.append(DeviceInfo(serial, " ".join(tokens), **fields))
    return result


def list_devices(
    address: ServerAddress, timeout: float = DEFAULT_TIMEOUT
) -> list[DeviceInfo]:
    """Return every device the server knows, in any state (``host:devices-l``)."""
    reply = host_query(address, "host:devices-l", timeout=timeout)
    return parse_devices(reply.decode(errors="replace"))


def parse_features(reply: bytes) -> frozenset[str]:
    """Return the feature names in the reply to a features request."""
    return frozenset(
        name for name in reply.decode(errors="replace").strip().split(",") if name
    )


def device_features(
    address: ServerAddress,
    serial: str,
    timeout: float = DEFAULT_TIMEOUT,
    cancelled: Callable[[], bool] | None = None,
) -> frozenset[str]:
    """Return the device's feature names (``host-serial:<serial>:features``)."""
    check_token(serial, "serial")
    reply = host_query(
        address,
        features_request(serial),
        serial=serial,
        timeout=timeout,
        cancelled=cancelled,
    )
    return parse_features(reply)


SHELL_V2 = "shell_v2"


def check_shell_v2(features: frozenset[str], serial: str) -> None:
    """Raise ``adb_error`` unless ``features`` lists ``shell_v2``."""
    if SHELL_V2 not in features:
        raise LogprobeError(
            "adb_error",
            f"the device {serial} does not support the adb feature {SHELL_V2}, "
            "which logprobe needs to read logcat output",
            {"serial": serial, "missing_feature": SHELL_V2},
        )


def require_shell_v2(
    address: ServerAddress,
    serial: str,
    timeout: float = DEFAULT_TIMEOUT,
    cancelled: Callable[[], bool] | None = None,
) -> None:
    """Check that the device supports the shell protocol v2.

    Raises:
        LogprobeError: ``adb_error`` if the device does not list the
            ``shell_v2`` feature; ``details["missing_feature"]`` names it.
    """
    check_shell_v2(device_features(address, serial, timeout, cancelled), serial)


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
            LogprobeError: ``adb_error`` for an empty exit packet or for bytes
                after the exit packet.
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
                packet. Output received before it is returned first. Bytes
                after the exit packet are ignored.
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
) -> ShellResult:
    """Run a command on a device to completion and collect its output.

    ``timeout`` is one overall limit in seconds for connecting, the handshake
    and the whole command, however slowly its output trickles in. None means
    no limit on the command; connecting and the handshake then use
    ``DEFAULT_TIMEOUT``.

    When the connection ends without an exit status, the stderr of the result
    ends with the received part of a stderr packet that was cut off; its
    stdout holds only the packets that arrived whole.

    Raises:
        TimeoutError: If everything did not finish within ``timeout`` seconds
            (a `CommandTimeoutError`, with the stderr received by then, the
            received part of an unfinished stderr packet included).
        LogprobeError: As :func:`open_shell`, or ``adb_error`` on a protocol
            violation.
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
    except TimeoutError:
        if opened is not None:
            err += opened.held_stderr()
        msg = f"command did not finish within {timeout} seconds"
        raise CommandTimeoutError(msg, bytes(err)) from None
    if stream.exit_status is None:  # the connection ended inside a packet
        err += stream.held_stderr()
    return ShellResult(stream.exit_status, bytes(out), bytes(err))


_LOGCAT_FORMAT_WORDS = ("threadtime", "year", "usec", "zone", "uid")
_EPOCH = re.compile(r"[0-9]+\.[0-9]+")


def logcat_argv(*, dump: bool, tail: int | None, t: str | None) -> list[str]:
    """Build the device-side ``logcat`` command for reading entries.

    The output format is ``threadtime`` plus the ``year``, ``usec``, ``zone``
    and ``uid`` modifiers, each as its own ``-v`` option. ``dump`` adds ``-d``
    (print what the buffer holds and exit), ``tail`` adds ``-t N`` (the last N
    lines; logcat itself treats this as a dump) and ``t`` adds ``-T t`` (start
    at that time).

    Args:
        dump: Whether to add ``-d``.
        tail: A positive line count, or None.
        t: A time as epoch seconds with a fractional part, such as
            ``"1700000000.123"``, or None. A number without a dot is a line
            count to logcat, so it is rejected.

    Raises:
        TypeError: If an argument has the wrong type.
        ValueError: If ``tail`` is below 1 or ``t`` is not an epoch with a dot.
    """
    if not isinstance(dump, bool):
        msg = f"dump must be a bool, not {type(dump).__name__}"
        raise TypeError(msg)
    if tail is not None:
        if not isinstance(tail, int) or isinstance(tail, bool):
            msg = f"tail must be an int or None, not {type(tail).__name__}"
            raise TypeError(msg)
        if tail < 1:
            msg = f"tail must be at least 1, got {tail}"
            raise ValueError(msg)
    if t is not None:
        if not isinstance(t, str):
            msg = f"t must be a string or None, not {type(t).__name__}"
            raise TypeError(msg)
        if _EPOCH.fullmatch(t) is None:
            msg = (
                "t must be epoch seconds with a decimal point such as "
                f"'1700000000.000' (logcat reads a number without a dot as a line "
                f"count), got {t!r}"
            )
            raise ValueError(msg)
    argv = ["logcat"]
    for word in _LOGCAT_FORMAT_WORDS:
        argv += ["-v", word]
    if dump:
        argv.append("-d")
    if tail is not None:
        argv += ["-t", str(tail)]
    if t is not None:
        argv += ["-T", t]
    return argv
