"""How often and how long a stream lists the installed packages."""

from __future__ import annotations

#: Least time between the starts of two lists of one device.
LIST_INTERVAL = 0.5
#: How often the list is taken again, to notice a reinstall; also how long a
#: device stays without a usable list after a list failed.
RECHECK_INTERVAL = 30.0
#: Longest time a read waits for a list before it is judged without one
#: (the wait for ``LIST_INTERVAL``, the command and the reader's other waits
#: since its bytes arrived all count). The regular list (every
#: `RECHECK_INTERVAL`, run while the reader goes on reading) has the time of
#: any other device command instead; a read that waits for it still waits at
#: most this long.
LIST_WAIT = 2.0
#: The least time a read's list needs: a read starts a list only when at
#: least this many seconds of its `LIST_WAIT` are left; otherwise its lines
#: are judged without a list. A list that was started and then cut by a time
#: limit counts as failed.
LIST_MIN_TIME = 1.0
