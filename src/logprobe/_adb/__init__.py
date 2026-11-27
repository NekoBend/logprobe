"""A minimal client for the adb server's "smart socket" protocol.

Instead of running the ``adb`` command for every operation, this module talks
to the adb server over TCP. A request is four lowercase hex digits giving the
payload length, followed by the payload. The server answers ``OKAY`` or
``FAIL`` (the latter followed by a four-digit length and a message).

The only subprocess ever started here is ``adb start-server``.
"""

from __future__ import annotations

from .address import ServerAddress, resolve_server_address
from .devices import (
    DeviceInfo,
    check_shell_v2,
    device_features,
    list_devices,
    parse_devices,
    parse_features,
    require_shell_v2,
)
from .limits import (
    COMMAND_OUTPUT_LIMIT,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    MAX_SHELL_PACKET,
    RECV_SIZE,
    TICK,
)
from .logcat import logcat_argv
from .protocol import (
    _send_all,
    check_token,
    connect,
    connect_failed,
    connection_failed,
    decode_length,
    encode_request,
    failure,
    features_request,
    host_query,
    server_closed,
    server_timeout,
    server_version,
    shell_request,
    status_is_okay,
    transport_request,
)
from .server import _start_server_environment, _which, ensure_server, find_adb
from .shell import (
    CLOSE_STDIN,
    CommandTimeoutError,
    ShellEvent,
    ShellResult,
    ShellStream,
    ShellV2Decoder,
    check_output,
    collect_events,
    collect_parts,
    device_command,
    open_shell,
    run_shell,
)
from .sockets import (
    Cancelled,
    _can_connect,
    _connect_sliced,
    _open_numeric,
    _wait_writable,
    numeric_addrinfo,
)

__all__ = [
    "CLOSE_STDIN",
    "COMMAND_OUTPUT_LIMIT",
    "DEFAULT_PORT",
    "DEFAULT_TIMEOUT",
    "MAX_SHELL_PACKET",
    "RECV_SIZE",
    "TICK",
    "Cancelled",
    "CommandTimeoutError",
    "DeviceInfo",
    "ServerAddress",
    "ShellEvent",
    "ShellResult",
    "ShellStream",
    "ShellV2Decoder",
    "_can_connect",
    "_connect_sliced",
    "_open_numeric",
    "_send_all",
    "_start_server_environment",
    "_wait_writable",
    "_which",
    "check_output",
    "check_shell_v2",
    "check_token",
    "collect_events",
    "collect_parts",
    "connect",
    "connect_failed",
    "connection_failed",
    "decode_length",
    "device_command",
    "device_features",
    "encode_request",
    "ensure_server",
    "failure",
    "features_request",
    "find_adb",
    "host_query",
    "list_devices",
    "logcat_argv",
    "numeric_addrinfo",
    "open_shell",
    "parse_devices",
    "parse_features",
    "require_shell_v2",
    "resolve_server_address",
    "run_shell",
    "server_closed",
    "server_timeout",
    "server_version",
    "shell_request",
    "status_is_okay",
    "transport_request",
]
