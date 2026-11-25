"""The argument list of the ``logcat`` command."""

from __future__ import annotations

import re

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
