"""Finding the ``adb`` executable and starting the adb server."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .limits import DEFAULT_TIMEOUT, START_SERVER_TIMEOUT
from .sockets import _can_connect, unavailable

if TYPE_CHECKING:
    from .address import ServerAddress


# ---------------------------------------------------------------------------
# adb executable and server start
# ---------------------------------------------------------------------------


# A PATHEXT extension that is tried: a dot, then no path separator or colon.
_EXTENSION = re.compile(r"\.[^\\/:]+")


def _executable(path: Path) -> bool:
    """True when ``path`` is an executable file; an unreadable path is a miss."""
    try:
        return path.is_file() and os.access(path, os.X_OK)
    except OSError:  # before Python 3.14 is_file() can raise PermissionError
        return False


def _which(command: str, *, windows: bool | None = None) -> str | None:
    """Like ``shutil.which``, but on Windows it adds no current-directory search.

    ``shutil.which`` may try the current directory first on Windows, so a stray
    ``adb.exe`` in the working directory would be run. Here a bare command name
    is searched only in the fully qualified ``PATH`` entries (a drive and a
    root, or a UNC share): an empty entry, ``.``, ``./``, ``bin``, ``\\tools``,
    ``C:tools`` or any other entry that Windows would resolve against the
    current directory or drive is skipped. A command that contains a directory
    part is checked there only, as given. In both cases only ``PATHEXT``
    extensions without a path separator or colon are added, so a candidate
    stays in its directory. Other platforms use ``shutil.which``. ``windows``
    forces the platform for tests; the default is the real one.
    """
    if windows is None:
        windows = sys.platform == "win32"
    if not windows:
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
    if Path(command).name != command:
        return next((name for name in names if _executable(Path(name))), None)
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry or not Path(entry).is_absolute():
            continue
        for name in names:
            candidate = Path(entry, name)
            if _executable(candidate):
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
    is searched the same way), and the SDK's ``platform-tools\\adb.exe`` is
    checked as it is, with no ``PATHEXT`` extension added.
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
    for variable in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        root = os.environ.get(variable)
        if not root:
            continue
        if not windows:
            found = shutil.which(str(Path(root) / "platform-tools" / "adb"))
            if found is not None:
                return found
        elif Path(root).is_absolute():
            candidate = Path(root, "platform-tools", "adb.exe")
            if _executable(candidate):
                return str(candidate)
    return None


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
    set already), so that ``cmd.exe``, which runs a ``.bat`` or ``.cmd`` found
    as adb, does not add the current directory when it looks up a bare command
    name. (Relative entries of the ``PATH`` it inherits still apply there.)
    ``windows`` forces the platform for tests.
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
