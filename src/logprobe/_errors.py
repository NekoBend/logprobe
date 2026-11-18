"""Error type and exit statuses shared by all of logprobe."""

from __future__ import annotations

#: Command-line exit status for each error code.
EXIT_STATUS: dict[str, int] = {
    "internal_error": 1,
    "usage_error": 2,
    "adb_server_unavailable": 3,
    "device_not_found": 4,
    "multiple_devices": 4,
    "device_offline": 5,
    "device_unauthorized": 5,
    # The adb server answered FAIL or broke the protocol.
    "adb_error": 20,
    # The device vanished mid-stream and did not come back in time.
    "device_lost": 21,
    # The device's logcat ended in a way that is not a known connection end.
    "logcat_failed": 22,
    # A device command needed to start the stream failed.
    "device_command_failed": 23,
    "interrupted": 130,
}


class LogprobeError(Exception):
    """An expected, reportable failure (device missing, server down, ...).

    Mistakes in how the library is called raise ``TypeError`` or
    ``ValueError`` instead.

    Args:
        code: Fixed snake_case name of the failure, a key of ``EXIT_STATUS``.
        message: Human-readable description; this is also ``str(error)``.
        details: Extra machine-readable facts about the failure.

    Attributes:
        code: The failure name.
        message: The description.
        details: The extra facts (empty when there are none).
    """

    def __init__(
        self,
        code: str,
        message: str,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details: dict[str, object] = {} if details is None else dict(details)

    def __reduce__(
        self,
    ) -> tuple[type[LogprobeError], tuple[object, ...], dict[str, object]]:
        """Support ``pickle`` and ``copy``, which would otherwise lose fields.

        The instance ``__dict__`` travels as state, so attributes added later
        (such as the ``__notes__`` of ``add_note()``) survive as well.
        """
        return (LogprobeError, (self.code, self.message, self.details), self.__dict__)

    def __repr__(self) -> str:
        if self.details:
            return f"LogprobeError({self.code!r}, {self.message!r}, {self.details!r})"
        return f"LogprobeError({self.code!r}, {self.message!r})"


#: How many lines of a device command's stderr an error keeps (the last ones).
STDERR_LINES = 20


def command_failed(
    serial: str,
    argv: list[str],
    exit_status: int | None,
    stderr: bytes = b"",
    *,
    outcome: str | None = None,
) -> LogprobeError:
    """The ``device_command_failed`` error for a device command that failed.

    ``outcome`` says what went wrong when the exit status does not (a timeout,
    output that could not be read). ``details`` has ``serial``, ``command``,
    ``exit_status`` and ``stderr`` (its last `STDERR_LINES` lines).
    """
    if outcome is None:
        outcome = f"did not succeed (exit status {exit_status})"
    tail = stderr.decode("utf-8", "replace").splitlines()[-STDERR_LINES:]
    return LogprobeError(
        "device_command_failed",
        f"the command {' '.join(argv)!r} on {serial} {outcome}",
        {
            "serial": serial,
            "command": argv,
            "exit_status": exit_status,
            "stderr": tail,
        },
    )
