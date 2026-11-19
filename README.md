# logprobe

[![ci](https://github.com/NekoBend/logprobe/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/NekoBend/logprobe/actions/workflows/ci.yml) [![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE) [![python](https://img.shields.io/badge/python-3.12%2B-blue)](#requirements)

A fast, light Android logcat library for Python: read device logs live or as a
snapshot, parse saved logcat files, filter entries and export them.

**Status: alpha.** The API may change without notice until a stable release.
See [Known gaps](#known-gaps). Bug reports and questions are welcome as
[GitHub issues](https://github.com/NekoBend/logprobe/issues). Pull requests are
not accepted while logprobe is in alpha. To report a security vulnerability, see
[SECURITY.md](SECURITY.md).

## What it does

- Takes a snapshot of a device's log (`Device.dump`, `Device.adump`), or streams
  the live log of one or more devices, blocking (`stream`) or on asyncio
  (`astream`).
- A live stream reconnects after a dropped connection and resumes where it
  stopped. Where it can tell that lines may be missing or repeated, it reports
  a `Gap` record; some losses cannot be detected. With
  `detect_skips=True` it can also report lines that an older logd drops
  without notice when the consumer falls behind. Its own reconnect can itself
  lose lines, and some of those losses go unreported: in one API 24 test the
  stream lost lines with the option and none without it.
- Parses logcat text in the `threadtime`, `brief`, `process`, `tag` and `raw`
  formats, from files (`read_file`) or any iterable of lines (`parse_lines`).
- Filters entries with conditions such as
  `(Level >= "W") & Tag("ActivityManager")`.
- Filters a device's lines by app (`Package(...)` or `package=`): it finds the
  app of each line from its uid and the device's list of installed packages,
  and sets `LogEntry.package`.
- Writes entries as JSON Lines, JSON, CSV or plain text (`export_logs`).
- Talks to the adb server over its socket protocol; it does not run
  `adb logcat`. It uses only the standard library, and `import logprobe` does
  not import asyncio.

## Known gaps

- Filtering by app neither attributes nor counts the lines of a watched app's
  isolated processes, such as a WebView renderer. How an app installed only
  for another user is listed is not verified. A stream counts the other lines
  it could not attribute in its summary, with the exceptions listed under
  [Package](docs/conditions.md#package).
- The tests use a fake adb server and logcat output recorded on Android 7.0
  (API 24) and API 36 emulators. Physical devices and other Android versions
  are untested.
- On Android 8 and 9, an isolated-process uid printed as a name (`u0_i0` to
  `u9_i9`) is read as a number 9000 too low, because a log line does not say
  which Android release printed it. `LogEntry.uid_raw` keeps the printed name.

## Requirements

- Python 3.12 or later. CI tests Python 3.12, 3.13 and 3.14 on Linux and
  Windows; macOS is untested.
  The regular CI does not test the free-threaded build (3.14t). In a one-off
  check in November 2026 (commit 7f41576), 155 test cases chosen for thread
  and timing races passed in each of 50 runs on CPython 3.14.10 with the GIL
  disabled, on Linux and on Windows.
- An adb server. When no server answers at the default address
  (127.0.0.1:5037), logprobe may run `adb start-server`; the conditions are in
  [Starting the adb server](docs/connecting.md#starting-the-adb-server). Pass
  `start_server=False` to prevent this.
- A device whose adb daemon supports shell protocol v2 (the `shell_v2`
  feature; Android 7.0, the oldest version tested, has it). logprobe runs every
  device command with it.
  Dumps and streams check for it first and raise `LogprobeError` with code
  `adb_error` when it is missing.

Reading log files needs no adb server and no device.

## Installation

logprobe is not on PyPI. Install it from GitHub with pip or uv:

```sh
pip install "git+https://github.com/NekoBend/logprobe"
uv add "git+https://github.com/NekoBend/logprobe"
```

`logprobe.__version__` gives the installed version (`0+unknown` when no
installed package metadata is found, as in a source tree that is not installed).

## Quick start

Take a snapshot of what the device's log holds now (here: the entries at level
W or above among its last 1,000 log records):

```python
import logprobe

device = logprobe.Device()  # the device in ANDROID_SERIAL, else the only ready one
for entry in device.dump(tail=1000, level="W"):
    print(entry.logged_at, entry.level, entry.tag, entry.message)
```

Follow the live log. The stream starts when the `with` block is entered and
stops when it is left:

```python
import logprobe

with logprobe.stream(["emulator-5554"], level="E") as live:
    for entry in live:
        print(entry.serial, entry.tag, entry.message)
```

The same on asyncio. Creating a `Device` talks to the adb server and blocks, so
do it before the event loop runs:

```python
import asyncio
import logprobe


async def main(device: logprobe.Device) -> None:
    async with device.astream(tag="ActivityManager") as live:
        async for entry in live:
            print(entry.logged_at, entry.message)


device = logprobe.Device()
asyncio.run(main(device))
```

Parse saved logcat text (both readers are lazy) and export entries. The export
is atomic and returns the number of entries written:

```python
import sys
from logprobe import export_logs, parse_lines, read_file

for entry in parse_lines(sys.stdin, format="brief"):
    print(entry.level, entry.tag, entry.message)

# logcat.txt was saved with `adb logcat -v threadtime`
count = export_logs(read_file("logcat.txt"), "logcat.jsonl")
```

## Filtering with conditions

Build conditions from `Level`, `Tag`, `Message`, `Pid`, `Tid`, `Uid`,
`Package`, `Crash` and `Anr`, and combine them with `&`, `|` and `~`. Pass one
as `where`. The keyword shortcuts (`level`, `tag`, `message`, `package`, `pid`)
are combined with `where` using AND. A condition can also be called on a single
entry:

```python
import logprobe
from logprobe import Crash, Level, Message, Tag, read_file

where = ((Level >= "W") & Tag("ActivityManager")) | Crash()
hits = [entry for entry in read_file("logcat.txt") if where(entry)]
entries = logprobe.Device().dump(Message.matches(r"ANR|timeout"), tag="ActivityManager")
```

See [docs/conditions.md](docs/conditions.md) for every condition and its rules.

## Errors

Expected failures, such as a missing device or an unreachable adb server, raise
`logprobe.LogprobeError`. It has a fixed `code` to test in your code, a readable
`message`, and a `details` dict with extra facts (for example the serials of
the attached devices). Common codes are `adb_server_unavailable`,
`device_not_found`, `multiple_devices`, `device_offline`, `device_unauthorized`
and `device_lost`.
Invalid arguments raise `TypeError` or `ValueError` instead, and misusing a
stream (for example starting it twice) raises `RuntimeError`.
See [docs/errors.md](docs/errors.md) for every code.

## Documentation

- [docs/connecting.md](docs/connecting.md): adb server address, devices, shell
  commands.
- [docs/streams.md](docs/streams.md): snapshots, live streams, reconnects, gaps,
  summaries, asyncio.
- [docs/conditions.md](docs/conditions.md): conditions, operators, keyword
  shortcuts.
- [docs/entries.md](docs/entries.md): `LogEntry`, file formats, timestamps,
  export formats.
- [docs/errors.md](docs/errors.md): `LogprobeError` and every error code.

## Development

The project uses [uv](https://docs.astral.sh/uv/). From the repository root:

```sh
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run ty check
```

The tests need no device: they run against a fake adb server. Benchmarks are
described in [bench/README.md](bench/README.md).

## License

MIT. See [LICENSE](LICENSE).
