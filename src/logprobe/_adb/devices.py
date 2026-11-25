"""The device list and the features of one device."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from logprobe._errors import LogprobeError

from .limits import _MAX_PAYLOAD, DEFAULT_TIMEOUT
from .protocol import check_token, features_request, host_query

if TYPE_CHECKING:
    from collections.abc import Callable

    from .address import ServerAddress


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


def _usable_serial(serial: str) -> bool:
    """True when ``serial`` from a device list can be used in a request.

    Not: a NUL character, which the request check refuses; bytes that were not
    UTF-8 (kept as surrogate escapes by `list_devices`), which no request could
    send back unchanged; or a length that makes the longest request with it
    exceed the request limit. (Line breaks cannot occur: the reply is split
    into lines first.)
    """
    if "\0" in serial:
        return False
    try:
        size = len(features_request(serial).encode())
    except UnicodeEncodeError:
        return False
    return size <= _MAX_PAYLOAD


def _readable(text: str) -> str:
    """``text`` with surrogate escapes (bytes that were not UTF-8) as U+FFFD."""
    return text.encode(errors="surrogateescape").decode(errors="replace")


def parse_devices(text: str) -> list[DeviceInfo]:
    """Parse the output of ``host:devices-l``.

    A line is the serial, the state, then ``key:value`` properties. The serial
    is the first token (except the literal ``(no serial number)``), the
    properties are the trailing ``key:value`` tokens, and the state is
    whatever lies between, which may contain spaces, as in ``no permissions
    (user in plugdev group; ...); see [http://...]``. Properties other than
    ``model``, ``product``, ``device`` and ``transport_id`` are dropped.
    A line whose serial could not be sent back to the server in a request is
    skipped (`_usable_serial`).
    """
    result: list[DeviceInfo] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith(_NO_SERIAL):
            serial, rest = _NO_SERIAL, line[len(_NO_SERIAL) :]
        else:
            serial, _, rest = line.partition(" ")
        tokens = rest.split()
        if not serial or not tokens or not _usable_serial(serial):
            continue
        fields: dict[str, str] = {}
        while len(tokens) > 1 and _PROPERTY.fullmatch(tokens[-1]):
            key, _, value = tokens.pop().partition(":")
            if key in _INFO_KEYS:
                fields[key] = _readable(value)
        result.append(DeviceInfo(serial, _readable(" ".join(tokens)), **fields))
    return result


def list_devices(
    address: ServerAddress, timeout: float = DEFAULT_TIMEOUT
) -> list[DeviceInfo]:
    """Return every device the server knows, in any state (``host:devices-l``)."""
    reply = host_query(address, "host:devices-l", timeout=timeout)
    # Bytes that are not UTF-8 stay recognizable (surrogate escapes), so that
    # a serial holding them is skipped rather than sent back changed.
    return parse_devices(reply.decode(errors="surrogateescape"))


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
