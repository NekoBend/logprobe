"""App ids, and which watched packages own them."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .._entry import LogEntry


# Uids are app_id + 100000 * user. App ids from 10000 up to (excluding) 20000
# are those of installed apps; the ranges around them hold system services,
# sandboxes and isolated processes (90000 and up) that no list names.
_APP_ID_MODULUS = 100_000
_FIRST_APP_ID = 10_000
_LAST_APP_ID = 20_000


def _owner_maps(
    names: Iterable[str], app_ids: dict[str, int]
) -> tuple[dict[str, int], dict[int, frozenset[str]], dict[int, str]]:
    """The watched names that are installed, and the owners and display per app id.

    ``app_ids`` maps every installed package to its app id. The display
    package of an app id is the first of its watched owners by name.
    """
    watched = {name: app_ids[name] for name in sorted(names) if name in app_ids}
    owners: dict[int, list[str]] = {}
    for name, app_id in watched.items():
        owners.setdefault(app_id, []).append(name)
    return (
        watched,
        {key: frozenset(value) for key, value in owners.items()},
        {key: value[0] for key, value in owners.items()},
    )


def _system_uid_text(serial: str, name: str, app_id: int) -> str:
    return (
        f"{serial}: {name} runs under the system uid {app_id}: every process of "
        "that uid is taken as belonging to it"
    )


def _no_owner(_entry: LogEntry, _names: frozenset[str]) -> bool:
    return False
