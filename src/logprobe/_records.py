"""Records that describe what a stream could not deliver, and how it ended.

A ``Gap`` marks a place where log lines may be missing or repeated. A
``DeviceSummary`` counts what one device's stream read and delivered, and a
``StreamSummary`` collects the summaries of all devices.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from ._errors import LogprobeError

GAP_SCHEMA = "logprobe.gap/1"
SUMMARY_SCHEMA = "logprobe.summary/1"

GapReason = Literal["ring_rotated", "continuity_unknown", "device_reported"]
GapCause = Literal["released", "disconnected", "stalled", "notice"]
FlushState = Literal["not_requested", "done", "timed_out", "failed", "cancelled"]

_INCOMPLETE_FLUSH = frozenset({"timed_out", "failed", "cancelled"})


@dataclass(frozen=True, slots=True)
class Gap:
    """A place in a device's stream where lines may be missing or repeated.

    Attributes:
        serial: The device the gap belongs to.
        reason: ``ring_rotated`` (lines read before a reconnect were not
            replayed in time, so the device probably no longer has them),
            ``continuity_unknown`` (it could not be verified that the new
            connection continues the old one; lines may be missing or
            repeated) or ``device_reported`` (the device itself reported
            dropped lines).
        cause: How the connection ended (``released``, ``disconnected``,
            ``stalled``), or ``notice`` for ``device_reported``.
        detected_at: By the host clock (aware UTC): when the ``chatty``
            notice was read, or, for the other reasons, when the reconnect was
            planned.
        start_at: Roughly where in the device's time the gap lies, by the
            device clock; a hint, not a guaranteed bound. None when unknown.
        lost: The number of lost lines, when the device says so.
    """

    serial: str
    reason: GapReason
    cause: GapCause
    detected_at: datetime
    start_at: datetime | None
    lost: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """The gap as a dict that ``json.dumps`` accepts.

        Always present: ``schema`` (``"logprobe.gap/1"``), ``serial``,
        ``reason``, ``cause`` and ``detected_at``. ``start_at`` and ``lost``
        are present only when not None. Datetimes are ``isoformat()`` strings.
        """
        data: dict[str, Any] = {
            "schema": GAP_SCHEMA,
            "serial": self.serial,
            "reason": self.reason,
            "cause": self.cause,
            "detected_at": self.detected_at.isoformat(),
        }
        if self.start_at is not None:
            data["start_at"] = self.start_at.isoformat()
        if self.lost is not None:
            data["lost"] = self.lost
        return data


@dataclass(frozen=True, slots=True)
class DeviceSummary:
    """What one device's stream read and delivered.

    Attributes:
        serial: The device.
        started_at: When the stream started.
        ended_at: When it ended; None while it is still running.
        lines: Physical lines read, including lines the condition removed
            (replayed duplicates and markers excluded).
        entries: Entries that passed the condition and were handed to the
            output queue, including those that a kill or an exception of
            ``on_entry`` dropped before they were delivered.
        unparsed: Lines that could not be parsed, including lines the
            condition removed afterwards.
        truncated: Lines that were cut short at the line length limit,
            including lines the condition removed afterwards.
        gaps: Number of gaps reported.
        lost: Total of the lost-line counts that are known.
        reconnects: Number of reconnections.
        unattributed: Lines for which the owning app could not be determined.
        flush: Outcome of the flush request: ``not_requested``, ``done``,
            ``timed_out``, ``failed`` or ``cancelled``.
        error: The error that ended this device (its reader, or the start
            while this device was being prepared or connected), or None. A
            device that was only stopped because another device failed has
            None; iteration, ``join()`` and the ``with`` exit raise the
            stream's error.

    Summaries that carry an error compare equal only when they share the
    same error object, because ``LogprobeError`` compares by identity;
    compare ``error.code``, ``error.message`` and ``error.details`` instead.
    """

    serial: str
    started_at: datetime
    ended_at: datetime | None
    lines: int
    entries: int
    unparsed: int
    truncated: int
    gaps: int
    lost: int
    reconnects: int
    unattributed: int
    flush: FlushState
    error: LogprobeError | None

    @property
    def complete(self) -> bool:
        """True when nothing is known to be missing, uncertain or failed.

        That means no gaps, no unattributed lines, no unparsed lines, no
        truncated lines, a flush that did not time out, fail or get
        cancelled, and no error. It describes what the stream read: entries
        that a kill, an early exit or a failing ``on_entry`` dropped do not
        make it False.
        """
        return (
            self.gaps == 0
            and self.unattributed == 0
            and self.unparsed == 0
            and self.truncated == 0
            and self.flush not in _INCOMPLETE_FLUSH
            and self.error is None
        )

    def to_dict(self) -> dict[str, Any]:
        """The summary as a dict that ``json.dumps`` accepts.

        The counts are always written, even when 0, as are ``flush`` and
        ``complete``. ``ended_at`` is written only once the stream has
        ended, and ``error`` only when there is one, as
        ``{"code": ..., "message": ...}``. Datetimes are ``isoformat()``
        strings.
        """
        data: dict[str, Any] = {
            "schema": SUMMARY_SCHEMA,
            "serial": self.serial,
            "started_at": self.started_at.isoformat(),
            "lines": self.lines,
            "entries": self.entries,
            "unparsed": self.unparsed,
            "truncated": self.truncated,
            "gaps": self.gaps,
            "lost": self.lost,
            "reconnects": self.reconnects,
            "unattributed": self.unattributed,
            "flush": self.flush,
            "complete": self.complete,
        }
        if self.ended_at is not None:
            data["ended_at"] = self.ended_at.isoformat()
        if self.error is not None:
            data["error"] = {
                "code": self.error.code,
                "message": self.error.message,
            }
        return data


@dataclass(frozen=True, slots=True)
class StreamSummary:
    """The summaries of all devices of a stream.

    Attributes:
        devices: One summary per device.
    """

    devices: tuple[DeviceSummary, ...]

    @property
    def complete(self) -> bool:
        """True when every device's summary is complete."""
        return all(device.complete for device in self.devices)

    def to_dict(self) -> list[dict[str, Any]]:
        """One summary dict per device, in order.

        Each element is a complete summary record, so serialize them as one
        JSON line per device.
        """
        return [device.to_dict() for device in self.devices]
