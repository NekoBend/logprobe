"""Default addresses, timeouts and size limits of the adb client."""

from __future__ import annotations

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5037
DEFAULT_TIMEOUT = 10.0
START_SERVER_TIMEOUT = 20.0
RECV_SIZE = 64 * 1024
# With a ``cancelled`` callback, no blocking wait lasts longer than this many
# seconds before the callback is asked again.
TICK = 0.25
_MAX_PAYLOAD = 0xFFFF
# The largest shell protocol packet accepted from the adb server; a longer
# declared length is a protocol error. The whole-packet reader holds a packet
# until it is complete, so this bounds what one packet can make it hold. The
# largest packets seen from adbd were 64-80 KiB (API 24 and 36 emulators).
MAX_SHELL_PACKET = 16 * 1024 * 1024
# The most output (stdout and stderr together) that a command logprobe runs
# itself may produce: the package lists, getprop, date and the markers. The
# largest such output seen was `dumpsys package packages`: about 0.95 MB for
# 254 packages on an API 36 emulator. It is checked per whole packet, so the
# reader may hold up to one more packet (``MAX_SHELL_PACKET``) meanwhile.
COMMAND_OUTPUT_LIMIT = 64 * 1024 * 1024
