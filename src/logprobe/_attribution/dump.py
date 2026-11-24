"""The verdict of each line of a dump, against one list."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .owners import _APP_ID_MODULUS, _FIRST_APP_ID, _owner_maps, _system_uid_text

if TYPE_CHECKING:
    from collections.abc import Callable

    from .._conditions import Condition
    from .._entry import LogEntry


def dump_judge(
    condition: Condition, uids: dict[str, int], serial: str = ""
) -> tuple[Callable[[list[LogEntry]], list[LogEntry]], list[tuple[int, str]]]:
    """The filter a dump applies, from the list read just before it.

    The verdict is two-valued: an app id that no watched package has in the
    list belongs to none (a dump takes no second list). Delivered entries get
    their display package in ``package``.

    Args:
        condition: The dump's condition (it has a `Package` term).
        uids: Package name to uid, as `Listed` holds it.
        serial: The device's serial, for the messages.

    Returns:
        The filter (a list of entries in, the kept entries out) and the
        messages, as ``(logging level, text)``: an INFO for each watched
        package that is not installed, a WARNING for each that runs under a
        system uid.
    """
    names = condition._package_names()  # noqa: SLF001
    app_ids = {name: uid % _APP_ID_MODULUS for name, uid in uids.items()}
    watched, owners, display = _owner_maps(names, app_ids)
    messages: list[tuple[int, str]] = [
        (
            logging.INFO,
            f"{name} is not installed on {serial}; the dump has no lines of it",
        )
        for name in sorted(names - watched.keys())
    ]
    messages.extend(
        (logging.WARNING, _system_uid_text(serial, name, app_id))
        for name, app_id in watched.items()
        if app_id < _FIRST_APP_ID
    )

    def member(entry: LogEntry, wanted: frozenset[str]) -> bool:
        uid = entry.uid
        if uid is None:
            return False
        found = owners.get(uid % _APP_ID_MODULUS)
        return found is not None and not wanted.isdisjoint(found)

    judge = condition._compile_membership(member)  # noqa: SLF001

    def keep(entries: list[LogEntry]) -> list[LogEntry]:
        kept: list[LogEntry] = []
        for entry in entries:
            if judge(entry):
                uid = entry.uid
                if uid is not None:
                    name = display.get(uid % _APP_ID_MODULUS)
                    if name is not None:
                        object.__setattr__(entry, "package", name)
                kept.append(entry)
        return kept

    return keep, messages
