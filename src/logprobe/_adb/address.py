"""The adb server's address: parsing ``ADB_SERVER_SOCKET`` and the port variable."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass

from logprobe._errors import LogprobeError

from .limits import DEFAULT_HOST, DEFAULT_PORT

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
