"""Fast, light, simple Android logcat parsing."""

from typing import TYPE_CHECKING

from ._adb import DeviceInfo
from ._conditions import (
    And,
    Anr,
    Condition,
    Crash,
    Level,
    Message,
    Not,
    Or,
    Package,
    Pid,
    Tag,
    Tid,
    Uid,
)
from ._device import Device, devices
from ._entry import LogEntry, LogLevel
from ._errors import LogprobeError
from ._export import export_logs
from ._read import parse_lines, read_file
from ._records import DeviceSummary, Gap, StreamSummary
from ._stream import LogStream, stream

if TYPE_CHECKING:
    from ._astream import AsyncLogStream, astream

__all__ = [
    "And",
    "Anr",
    "AsyncLogStream",
    "Condition",
    "Crash",
    "Device",
    "DeviceInfo",
    "DeviceSummary",
    "Gap",
    "Level",
    "LogEntry",
    "LogLevel",
    "LogStream",
    "LogprobeError",
    "Message",
    "Not",
    "Or",
    "Package",
    "Pid",
    "StreamSummary",
    "Tag",
    "Tid",
    "Uid",
    "astream",
    "devices",
    "export_logs",
    "parse_lines",
    "read_file",
    "stream",
]

# The asyncio stream is imported when one of these names is first used, so that
# ``import logprobe`` does not import asyncio.
_ASYNC_NAMES = frozenset({"AsyncLogStream", "astream"})

# The installed package's version, read from its metadata when first used, so
# that ``import logprobe`` does not import importlib.metadata.
__version__: str

# Hidden from type checkers: they see the names through the import and the
# annotation above, and a visible __getattr__ would make them accept any
# misspelt name.
if not TYPE_CHECKING:

    def __getattr__(name: str) -> object:
        if name in _ASYNC_NAMES:
            from . import _astream

            value = getattr(_astream, name)
        elif name == "__version__":
            from importlib.metadata import PackageNotFoundError, version

            try:
                value = version(__name__)
            except PackageNotFoundError:  # run from a source tree, not installed
                value = "0+unknown"
        else:
            msg = f"module {__name__!r} has no attribute {name!r}"
            raise AttributeError(msg)
        globals()[name] = value
        return value

    def __dir__() -> list[str]:
        # TYPE_CHECKING is imported for the checks above, not offered.
        names = globals().keys() - {"TYPE_CHECKING"}
        return sorted(names | _ASYNC_NAMES | {"__version__"})
