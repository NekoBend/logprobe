# Changelog

All notable changes to logprobe are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[PEP 440](https://peps.python.org/pep-0440/). While logprobe is in alpha, any
release may change the API.

## [0.1.0a1] - 2026-11-20

The first tagged release. It contains everything since the repository was made
public on 2026-11-18; the items below are the changes after that first public
commit that a user can see.

### Added

- `detect_skips=True` on `logprobe.stream`, `logprobe.astream`,
  `Device.stream` and `Device.astream`. On devices whose logd skips the lines
  of a slow reader without notice (API 25 and below, and API 30), the reader
  closes and reopens its connection when its queue stays full, so the loss can
  be reported as a `Gap` with the cause `stalled`. Off by default; without it
  no extra device command runs. (#1)
- Filtering by app now works on devices: `Package(...)` conditions and the
  `package=` shortcut in `Device.dump`, `Device.adump`, `logprobe.stream` and
  `logprobe.astream`, which set `LogEntry.package`. Until now they raised
  `NotImplementedError`. The app of a line comes from its uid and the device's
  list of installed packages (`pm list packages -U`, or
  `dumpsys package packages` on Android 7). (#3)
- `logprobe.__version__`. It is read from the installed package's metadata
  when first used; a source tree that is not installed gives `0+unknown`. (#10)
- Gaps are also logged on the `logprobe` logger: the first gap of each reason
  on a device is a WARNING, later ones are counted, and one WARNING at the end
  of the device's read gives the counts. (#15)

### Fixed

- The asyncio stream no longer drops the rest of a network read when it ends
  between two batches of that read (a plain `stop()`, a flush that ended, a
  late start marker). Except on a kill, both streams now process every
  complete line of the reads they took and deliver the matching entries, up
  to a pending flush marker. (#2)
- A flush ends as `timed_out`, not `done`, when its budget cut a package-list
  command short (seen on Windows with Python 3.12). (#9)
- A flush ends as `timed_out` when a reconnect handshake passes a deadline set
  by the flush budget, instead of failing the stream with an adb error (seen
  on Windows with Python 3.12). (#16)
- On Windows, the search for the `adb` executable no longer resolves relative
  `PATH` entries (such as `./` or `bin`) or a relative `ANDROID_HOME` or
  `ANDROID_SDK_ROOT` against the current directory, skips `PATHEXT` entries
  that hold a path separator, and runs `adb start-server` with
  `NoDefaultCurrentDirectoryInExePath=1` unless that is set already. (#20)
- A chatty notice whose count has more than 18 digits is read as an ordinary
  line instead of raising, and a device list line whose serial holds a NUL,
  bytes that are not UTF-8, or more than a request can carry is skipped. (#21)
- Limits on what an adb server that breaks the protocol can make logprobe
  hold or wait for: a shell packet that declares more than 16 MiB is an
  `adb_error`, the commands logprobe runs itself stop with an `adb_error` past
  64 MiB of output (`Device.shell` keeps no limit), and the `timeout` of a
  host query (device list, features, server version) covers the whole
  exchange instead of each receive. A dump still has no overall limit (see
  #24). (#22)
- A reconnect no longer fails when a delivered line has a time without a
  zone; such lines are not matched on resume, so they can be delivered again,
  even when `since="now"` had skipped them before the reconnect.
  The asyncio stream counts bytes that complete no line as data when it
  decides whether the connection went quiet. (#23)

### Changed

- The README states the tested Python versions and platforms, and the package
  metadata has matching classifiers. (#14)
- The repository has a security policy, `SECURITY.md`, which says how to
  report a vulnerability. (#12)
- The `detect_skips` documentation says that the option's own reconnect can
  lose lines, and that some of those losses go unreported. (#18)
- The dump documentation says that a dump keeps the matching entries until
  logcat exits and has no overall deadline, so an adb server or device that
  ignores `-t` can make it grow without limit.
  The README says that CI does not test the free-threaded build (3.14t) and
  gives the result of a one-off check on it. (#24)

[0.1.0a1]: https://github.com/NekoBend/logprobe/releases/tag/v0.1.0a1
