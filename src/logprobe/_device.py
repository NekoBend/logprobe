"""Public entry points: list devices and talk to one of them."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Literal

from logprobe import _adb, _dump
from logprobe._conditions import build_condition
from logprobe._errors import LogprobeError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from logprobe._adb import DeviceInfo, ShellResult, ShellStream
    from logprobe._astream import AsyncLogStream
    from logprobe._conditions import Condition
    from logprobe._entry import LogEntry, LogLevel
    from logprobe._stream import LogStream


def _connect_server(
    adb_server: str | None, adb: str | None, *, start_server: bool
) -> _adb.ServerAddress:
    address = _adb.resolve_server_address(adb_server)
    _adb.ensure_server(address, adb=adb, start_server=start_server)
    return address


def devices(
    *,
    adb_server: str | None = None,
    adb: str | None = None,
    start_server: bool = True,
) -> list[DeviceInfo]:
    """List the devices the adb server knows, in every state adb reports.

    Args:
        adb_server: Server address as ``tcp:HOST:PORT``. HOST must be an IP
            address: IPv4 (``127.0.0.1``) or IPv6 in square brackets
            (``[::1]``); ``localhost`` is also accepted and means 127.0.0.1.
            Any other host name is rejected, because logprobe never resolves
            names (the adb command itself may accept host names; logprobe does
            not). Default: the ``ADB_SERVER_SOCKET`` (same rule) /
            ``ANDROID_ADB_SERVER_PORT`` (port on 127.0.0.1) environment
            variables, then 127.0.0.1:5037.
        adb: Path of the ``adb`` executable, used only to start the server.
        start_server: Whether ``adb start-server`` may run when the server is
            down and the address is the default one and the environment variable
            ``ANDROID_ADB_SERVER_ADDRESS`` (read by adb, not by logprobe) is
            not set to a non-empty value. It runs with a copy of the
            environment without ``ADB_SERVER_SOCKET``,
            ``ANDROID_ADB_SERVER_ADDRESS`` and ``ANDROID_ADB_SERVER_PORT``,
            plus ``ADB_MDNS=0``, so it starts only the default local server
            and that server sends no mDNS discovery queries.

    An environment variable that is set but empty counts as unset.

    Raises:
        LogprobeError: ``adb_server_unavailable`` or ``adb_error``; and
            ``usage_error`` if ``ADB_SERVER_SOCKET`` or
            ``ANDROID_ADB_SERVER_PORT`` is malformed or ``ADB_SERVER_SOCKET``
            names a host instead of an IP address.
        TypeError: If an argument has the wrong type.
        ValueError: If ``adb_server`` is not of the form ``tcp:HOST:PORT`` or
            its HOST is not an IP address (or ``localhost``).
    """
    address = _connect_server(adb_server, adb, start_server=start_server)
    return _adb.list_devices(address)


def _select(infos: list[DeviceInfo], requested: str | None) -> DeviceInfo:
    """Pick the device to use, or raise the matching LogprobeError."""
    if requested is not None:
        match = next((info for info in infos if info.serial == requested), None)
        if match is None:
            raise LogprobeError(
                "device_not_found",
                f"device {requested!r} is not attached",
                {"serial": requested, "attached": [info.serial for info in infos]},
            )
        if match.state != "device":
            code = (
                "device_unauthorized"
                if match.state == "unauthorized"
                else "device_offline"
            )
            raise LogprobeError(
                code,
                f"device {requested!r} is {match.state}, not ready",
                {"serial": requested, "state": match.state},
            )
        return match
    ready = [info for info in infos if info.state == "device"]
    if len(ready) == 1:
        return ready[0]
    if len(ready) > 1:
        serials = [info.serial for info in ready]
        raise LogprobeError(
            "multiple_devices",
            "more than one device is attached; "
            "choose one by serial or set ANDROID_SERIAL",
            {"serials": serials},
        )
    if infos:
        states = {info.serial: info.state for info in infos}
        code = (
            "device_unauthorized"
            if "unauthorized" in states.values()
            else "device_offline"
        )
        raise LogprobeError(code, "no attached device is ready", {"devices": states})
    raise LogprobeError("device_not_found", "no device is attached", {})


class Device:
    """One connected Android device, reached through the adb server.

    The server is contacted, and the device selected, when the object is
    created, so a missing or unusable device fails immediately.

    Args:
        serial: Serial of the device. Default: the ``ANDROID_SERIAL``
            environment variable, else the only device in state ``device``.
        adb_server: Server address as ``tcp:HOST:PORT``. HOST must be an IP
            address (IPv4, or IPv6 in square brackets) or ``localhost``; other
            host names are rejected, since logprobe never resolves names (adb
            itself may accept them). See :func:`devices`.
        adb: Path of the ``adb`` executable, used only to start the server.
        start_server: Whether ``adb start-server`` may run when the server is
            down and the address is the default one and the environment variable
            ``ANDROID_ADB_SERVER_ADDRESS`` (read by adb, not by logprobe) is
            not set to a non-empty value. It runs with a copy of the
            environment without ``ADB_SERVER_SOCKET``,
            ``ANDROID_ADB_SERVER_ADDRESS`` and ``ANDROID_ADB_SERVER_PORT``,
            plus ``ADB_MDNS=0``, so it starts only the default local server
            and that server sends no mDNS discovery queries.

    An environment variable that is set but empty counts as unset (this holds
    for ``ANDROID_SERIAL`` and the server address variables alike).

    Attributes:
        serial: Serial of the selected device.
        server: ``(host, port)`` of the adb server in use; host is a numeric IP.

    Raises:
        LogprobeError: ``adb_server_unavailable``, ``device_not_found``,
            ``multiple_devices``, ``device_offline``, ``device_unauthorized``
            or ``adb_error``; and ``usage_error`` if ``ADB_SERVER_SOCKET`` or
            ``ANDROID_ADB_SERVER_PORT`` is malformed or ``ADB_SERVER_SOCKET``
            names a host instead of an IP address.
        TypeError: If an argument has the wrong type.
        ValueError: If ``serial`` is empty or contains NUL or a line break, or
            ``adb_server`` is not of the form ``tcp:HOST:PORT`` or its HOST is
            not an IP address (or ``localhost``).
    """

    def __init__(
        self,
        serial: str | None = None,
        *,
        adb_server: str | None = None,
        adb: str | None = None,
        start_server: bool = True,
    ) -> None:
        if serial is not None:
            _adb.check_token(serial, "serial")
        address = _connect_server(adb_server, adb, start_server=start_server)
        requested = (
            serial if serial is not None else (os.environ.get("ANDROID_SERIAL") or None)
        )
        chosen = _select(_adb.list_devices(address), requested)
        self._address = address
        self.serial: str = chosen.serial
        self.server: tuple[str, int] = (address.host, address.port)

    def features(self) -> frozenset[str]:
        """Return the feature names the device supports (e.g. ``shell_v2``)."""
        return _adb.device_features(self._address, self.serial)

    def _require_shell_v2(self, cancelled: Callable[[], bool] | None = None) -> None:
        """Check the ``shell_v2`` feature; ``adb_error`` if it is missing."""
        _adb.require_shell_v2(self._address, self.serial, cancelled=cancelled)

    def _open_logcat(
        self,
        argv: Sequence[str],
        cancelled: Callable[[], bool] | None = None,
        deadline: float | None = None,
    ) -> ShellStream:
        """Start ``argv`` (a ``logcat`` command line) and return its output stream.

        Every wait is cut into slices of ``_adb.TICK`` seconds, and
        ``_adb.Cancelled`` is raised (the socket closed) once ``cancelled()``
        returns true. A ``deadline`` (a ``time.monotonic()`` value) limits the
        whole connection procedure; running out raises ``TimeoutError``.
        """
        return _adb.open_shell(
            self._address, self.serial, argv, deadline=deadline, cancelled=cancelled
        )

    def _run_command(
        self,
        args: Sequence[str],
        timeout: float,
        cancelled: Callable[[], bool] | None = None,
    ) -> ShellResult:
        """Run a one-shot command for the stream: ``timeout`` seconds at most.

        Every wait is cut into slices of ``_adb.TICK`` seconds and
        ``_adb.Cancelled`` is raised (the socket closed) once ``cancelled()``
        returns true. ``TimeoutError`` is raised when the time is up. Read the
        output only when ``exit_status`` is 0.
        """
        return _adb.run_shell(
            self._address,
            self.serial,
            args,
            timeout,
            cancelled,
            max_output=_adb.COMMAND_OUTPUT_LIMIT,
        )

    def shell(self, args: Sequence[str], timeout: float | None = 30.0) -> ShellResult:
        """Run a command on the device and return its exit status and output.

        When the connection ends before the device reports an exit status
        (``exit_status`` None), ``stderr`` may end with the received part of
        a stderr packet that was cut off, while ``stdout`` holds only the
        packets that arrived whole.

        Args:
            args: The program and its arguments, e.g. ``["getprop", "ro.x"]``.
            timeout: One overall limit in seconds for connecting and running
                the command (None: no limit on the command).

        Raises:
            TimeoutError: If the command does not finish in time.
            LogprobeError: ``device_not_found``, ``device_offline``,
                ``device_unauthorized``, ``adb_server_unavailable`` or
                ``adb_error``.
        """
        return _adb.run_shell(self._address, self.serial, args, timeout)

    def dump(
        self,
        where: Condition | None = None,
        *,
        tail: int | None = None,
        level: LogLevel | None = None,
        tag: str | list[str] | tuple[str, ...] | None = None,
        message: str | None = None,
        package: str | list[str] | tuple[str, ...] | None = None,
        pid: int | list[int] | tuple[int, ...] | None = None,
    ) -> list[LogEntry]:
        """Read what the device's logcat holds now and return the matching entries.

        This runs ``logcat -d`` (``-t N`` with ``tail``) once, in the format
        the stream readers use, and returns when logcat has printed everything.
        It is a snapshot: it returns no gaps and no counters, and logs the
        gaps it finds (``chatty`` notices) as a stream does. The result is
        as large as the device's log buffers; with a 2 MiB ring on API 36 that
        is about 200,000 lines, all held in memory, so pass ``tail`` or a
        condition when that matters. A final line without a line feed is
        returned too, but only when logcat finished normally.

        The wait for output is cut into 0.25 second slices, so Ctrl-C works on
        Windows as well, and the connection is closed however the call ends.
        A device that sends no byte for 30 seconds raises ``TimeoutError``;
        there is no overall limit, because a large dump may take a while.

        Args:
            where: A condition the entries must match.
            tail: Let logcat pick only the last N log records, before the
                filtering. A record of several lines gives several entries.
            level: Keep entries at this level or above.
            tag: Keep entries with this tag, or any of these tags.
            message: Keep entries whose message contains this text.
            package: Keep entries of these apps (see `Package`).
            pid: Keep entries of this process id, or any of these.

        The keyword shortcuts and ``where`` are combined with AND.

        With a condition on the app (``Package`` or ``package``), the dump
        first reads the list of every installed package with its uid (``pm
        list packages -U``, or ``dumpsys package packages`` on devices that do
        not know ``-U``; each command may take 5 seconds) and judges every line
        by that list alone: a line of an app the list does not name belongs to
        no watched package. Lines of a watched app's isolated processes (such
        as a WebView renderer, app ids 90000 to 99999) are not attributed to
        the app, and how an app installed only for a secondary user is listed
        is not verified. See `Package` for the rest of what is not promised.

        Returns:
            The entries in log order.

        Raises:
            LogprobeError: ``adb_error`` (for example the device lacks
                ``shell_v2``, or the adb server refused the request, did not
                answer or broke the protocol), ``logcat_failed`` (logcat
                exited with a non-zero status; ``details`` has ``exit_status``
                and the end of ``stderr``), ``device_lost`` (the connection
                closed without an exit status; the partial line is dropped),
                ``device_not_found``, ``device_offline``,
                ``device_unauthorized`` or ``adb_server_unavailable``;
                ``device_command_failed`` when the package list failed (a
                non-zero exit status, none at all, no usable output, or more
                than 5 seconds; ``details`` has ``serial``, ``command``,
                ``exit_status`` and ``stderr``).
            TimeoutError: If the device sent nothing for 30 seconds.
            TypeError: If an argument has the wrong type, or ``tail`` is a bool.
            ValueError: If ``tail`` is below 1 or a shortcut value is invalid.
        """
        condition = build_condition(
            where, level=level, tag=tag, message=message, package=package, pid=pid
        )
        _adb.logcat_argv(dump=True, tail=tail, t=None)  # check tail before any I/O
        return _dump.run_dump(self._address, self.serial, condition, tail)

    async def adump(
        self,
        where: Condition | None = None,
        *,
        tail: int | None = None,
        level: LogLevel | None = None,
        tag: str | list[str] | tuple[str, ...] | None = None,
        message: str | None = None,
        package: str | list[str] | tuple[str, ...] | None = None,
        pid: int | list[int] | tuple[int, ...] | None = None,
    ) -> list[LogEntry]:
        """Read what the device's logcat holds now, on asyncio; same as :meth:`dump`.

        The arguments, the result and the errors are those of :meth:`dump`;
        an invalid argument raises when the call is awaited, before any I/O.
        It uses the asyncio adb client and starts no thread. A device that
        sends no byte for 30 seconds raises ``TimeoutError``, as in
        :meth:`dump`. The output is taken in batches of about 8 KiB, and the
        event loop runs other tasks between two batches. A batch can exceed
        that by less than the part of one packet that one network read
        brought (up to 64 KiB), which is never split. Cancelling the task
        closes the connection and lets ``CancelledError`` pass.
        """
        condition = build_condition(
            where, level=level, tag=tag, message=message, package=package, pid=pid
        )
        _adb.logcat_argv(dump=True, tail=tail, t=None)  # check tail before any I/O
        # Imported here: the asyncio dump uses _astream, which imports _stream,
        # which imports this module; and so that ``import logprobe`` does not
        # import asyncio.
        from logprobe._adump import arun_dump

        return await arun_dump(self._address, self.serial, condition, tail)

    def stream(
        self,
        where: Condition | None = None,
        *,
        level: LogLevel | None = None,
        tag: str | list[str] | tuple[str, ...] | None = None,
        message: str | None = None,
        package: str | list[str] | tuple[str, ...] | None = None,
        pid: int | list[int] | tuple[int, ...] | None = None,
        since: Literal["now"] | None = None,
        on_entry: Callable[[LogEntry], object] | None = None,
        reconnect: float = 60.0,
        detect_skips: bool = False,
        buffer_lines: int = 10_000,
        buffer_bytes: int = 4 * 1024 * 1024,
    ) -> LogStream:
        """Read this device's log live; same as ``logprobe.stream([self], ...)``.

        The stream is returned without being started: use it in a ``with``
        statement or call :meth:`LogStream.start`. See :func:`logprobe.stream`
        for the arguments and the errors.
        """
        # Imported here because the stream module imports this one.
        from logprobe._stream import stream

        return stream(
            [self],
            where,
            level=level,
            tag=tag,
            message=message,
            package=package,
            pid=pid,
            since=since,
            on_entry=on_entry,
            reconnect=reconnect,
            detect_skips=detect_skips,
            buffer_lines=buffer_lines,
            buffer_bytes=buffer_bytes,
        )

    def astream(
        self,
        where: Condition | None = None,
        *,
        level: LogLevel | None = None,
        tag: str | list[str] | tuple[str, ...] | None = None,
        message: str | None = None,
        package: str | list[str] | tuple[str, ...] | None = None,
        pid: int | list[int] | tuple[int, ...] | None = None,
        since: Literal["now"] | None = None,
        reconnect: float = 60.0,
        detect_skips: bool = False,
        buffer_lines: int = 10_000,
        buffer_bytes: int = 4 * 1024 * 1024,
    ) -> AsyncLogStream:
        """Read this device's log live on asyncio; same as ``astream([self], ...)``.

        The stream is returned without being started: use it in an ``async
        with`` statement or ``await`` :meth:`AsyncLogStream.start`. See
        :func:`logprobe.astream` for the arguments and the errors.
        """
        # Imported here because the stream module imports this one, and so
        # that ``import logprobe`` does not import asyncio.
        from logprobe._astream import astream

        return astream(
            [self],
            where,
            level=level,
            tag=tag,
            message=message,
            package=package,
            pid=pid,
            since=since,
            reconnect=reconnect,
            detect_skips=detect_skips,
            buffer_lines=buffer_lines,
            buffer_bytes=buffer_bytes,
        )
