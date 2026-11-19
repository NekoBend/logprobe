# Errors

logprobe raises `LogprobeError` for expected failures that are not your
program's fault: the adb server is down, the device is missing, the
connection was lost. Mistakes in how the library is called raise the usual
Python exceptions instead (`TypeError`, `ValueError` and others; see
[Other exceptions](#other-exceptions)).

## LogprobeError

```python
import logprobe

try:
    device = logprobe.Device()
except logprobe.LogprobeError as error:
    print(error.code)  # "multiple_devices"
    print(error.message)  # human-readable text, also str(error)
    print(error.details)  # {"serials": ["emulator-5554", "R58M123ABC"]}
```

| Attribute | Type | Meaning |
| --- | --- | --- |
| `code` | `str` | A fixed snake_case name of the failure. Match on this. |
| `message` | `str` | A description for people. It is also `str(error)`. Do not parse it. |
| `details` | `dict[str, object]` | Machine-readable facts about the failure. Empty when there are none. |

The keys in `details` depend on the code and on where the error was raised;
the sections below list them. Read them with `details.get(...)`, because not
every key is present in every case.

`LogprobeError` can be pickled and copied with all three attributes.

## Codes

| Code | Short meaning |
| --- | --- |
| [`usage_error`](#usage_error) | An environment variable that logprobe reads is malformed. |
| [`adb_server_unavailable`](#adb_server_unavailable) | logprobe cannot connect to the adb server. |
| [`device_not_found`](#device_not_found) | The device is not attached, or no device is attached. |
| [`multiple_devices`](#multiple_devices) | No serial was given and more than one device is ready. |
| [`device_offline`](#device_offline-and-device_unauthorized) | The device is attached but not ready. |
| [`device_unauthorized`](#device_offline-and-device_unauthorized) | The device has not authorized this computer for USB debugging. |
| [`adb_error`](#adb_error) | The adb server refused a request, broke the protocol, or did not answer. |
| [`device_lost`](#device_lost) | The connection to the device ended and did not come back. |
| [`logcat_failed`](#logcat_failed) | logcat on the device ended with an error. |
| [`device_command_failed`](#device_command_failed) | A device command that `since="now"`, or the package list of a dump, needs failed. |
| [`internal_error`](#internal_error) | A stream reader failed unexpectedly: a bug in logprobe. |

### `usage_error`

Raised by `devices()` and `Device(...)` when `ADB_SERVER_SOCKET` is not of
the form `tcp:HOST:PORT`, names a host instead of an IP address (`localhost`
is accepted), or when
`ANDROID_ADB_SERVER_PORT` is not a port number from 1 to 65535. It is raised
before any network activity.

| Key | Value |
| --- | --- |
| `variable` | The name of the malformed variable. |

A malformed `adb_server` argument raises `ValueError` instead. See
[connecting.md](connecting.md#the-adb-server-address).

### `adb_server_unavailable`

Raised when logprobe cannot open a TCP connection to the adb server:

- by `devices()` and `Device(...)`, when the server does not accept a
  connection and it is not started, or starting it did not help;
- by any later call, when the server stopped accepting connections.

| Key | Value |
| --- | --- |
| `host` | The server's IP address. |
| `port` | The server's port. |
| `auto_start_allowed` | Whether logprobe was allowed to start the server. Present only for the first case above. |
| `reason` | Why the server is unreachable, as text: start_server is disabled, the address was set explicitly, `ANDROID_ADB_SERVER_ADDRESS` is set, the adb executable was not found, `adb start-server` failed, or the server is still unreachable after it ran. For a later call: the server stopped accepting connections. |
| `error` | The underlying error, as text: the connection error, or why `adb start-server` failed. |
| `start_server_returncode` | The exit status of `adb start-server`, when it ran and the server is still unreachable. |
| `start_server_output` | What `adb start-server` printed, at most 2000 characters. When it ran and the server is still unreachable: its stderr, else its stdout. When it timed out: its stderr, if it wrote any. |
| `serial` | The device, when a running stream ended with this error. |

The rules for when logprobe starts the server are in
[connecting.md](connecting.md#starting-the-adb-server).

### `device_not_found`

Raised when the device cannot be found:

- by `Device(...)`, when the requested serial is not attached;
- by `Device()` without a serial, when no device is attached;
- by any call that reaches the device, when the adb server answers that the
  device is not found (for example, it was unplugged after the `Device` was
  created).

| Key | Value |
| --- | --- |
| `serial` | The requested serial, or for a later call the `Device`'s serial. Absent when `Device()` without a serial found no device. |
| `attached` | The serials that are attached. Only when `Device(...)` had a serial (the argument or `ANDROID_SERIAL`). |

When `Device()` without a serial finds no device attached, `details` is empty.

A running stream does not raise this code when its device disappears. It
tries to reconnect and, when that fails, ends with
[`device_lost`](#device_lost).

### `multiple_devices`

Raised by `Device()` without a serial when more than one device is in state
`device`. Pass a serial, or set `ANDROID_SERIAL`.

| Key | Value |
| --- | --- |
| `serials` | The serials of the ready devices. |

### `device_offline` and `device_unauthorized`

Raised when the device is attached but cannot be used:

- by `Device(...)`, when the requested serial is in a state other than
  `device`. The code is `device_unauthorized` for state `unauthorized` and
  `device_offline` for every other state;
- by `Device()` without a serial, when devices are attached but none is
  ready. The code is `device_unauthorized` if any of them is unauthorized,
  else `device_offline`;
- by any call that reaches the device, when the adb server answers that the
  device is offline or unauthorized.

| Key | Value |
| --- | --- |
| `serial` | The device. Absent when `Device()` without a serial found no ready device. |
| `state` | adb's state word. Only when `Device(...)` had a serial (the argument or `ANDROID_SERIAL`). |
| `devices` | A dict of serial to state for every attached device. Only when `Device()` had no serial. |

### `adb_error`

Raised when the adb server answered in a way logprobe cannot use:

- The server refused a request with a message that is not one of the device
  errors above. `message` is the server's own text.
- The device does not report the `shell_v2` feature, which logprobe needs to
  read logcat output. Raised by `Device.dump()`, `Device.adump()` and when a
  stream starts.
- The server or device broke the protocol: an invalid status, an invalid
  length, a broken shell packet, or a shell packet that declares more than
  16 MiB.
- A command that logprobe runs itself (the package list, `getprop`, `date`,
  the start marker) wrote more than 64 MiB of output. `Device.shell()` has no
  such limit. A flush marker command that fails this way raises nothing: it
  counts as not having run, as when the connection is lost (see
  [streams.md](streams.md)).
- Sending to or receiving from the server failed, the server closed the
  connection in the middle of a reply, or the server did not answer within
  10 seconds. For a query to the server itself (the device list, a device's
  features), the 10 seconds after connecting also cover the whole reply.
- A stream could not start because the adb server did not answer in time.
- A running stream gave up reconnecting and the last attempt failed in one
  of these ways, or with a timeout.

| Key | Value |
| --- | --- |
| `serial` | The device, when the server refused a request about a device or the device lacks `shell_v2`. Always present when a running stream ended with this error; a protocol error has it only then. |
| `missing_feature` | `"shell_v2"`, when the device lacks it. |
| `status` | The invalid status the server sent. |
| `raw` | The invalid length field the server sent. |
| `length` | The declared length of a shell packet over the limit. |
| `command`, `limit` | The command whose output passed the limit, and the limit in bytes. |

Many `adb_error` cases have only `serial`, or no details at all.

### `device_lost`

The connection to the device ended without a normal end, and logprobe could
not get it back.

- `Device.dump()` and `Device.adump()` raise it when the connection closed
  before logcat reported its exit status. No entries are returned.
- A stream ends with it when its device's connection was lost or logcat
  ended, and the reconnect budget is used up (or `reconnect=0`). See
  [streams.md](streams.md).

| Key | Value |
| --- | --- |
| `serial` | The device. |
| `exit_status` | Streams only: the exit status of the last connection, or `None`. Absent when the stream gave up after reconnect attempts that failed before a connection existed; the error of the last attempt is then the `__cause__`. |

### `logcat_failed`

logcat on the device exited with an error.

- `Device.dump()` and `Device.adump()` raise it when logcat exits with a
  non-zero status.
- A stream ends with it when the first connection exits with a status from 1
  to 127 before any standard output (other than logd's cut-off), when logcat keeps failing until the reconnect budget is used up (or at
  once with `reconnect=0`), or when logd keeps cutting the reader off within
  a second of connecting (three or more times in a row) until the budget is
  used up (or after the third time with `reconnect=0`). See
  [streams.md](streams.md).

| Key | Value |
| --- | --- |
| `serial` | The device. |
| `exit_status` | logcat's exit status. |
| `stderr` | The end of what logcat wrote to standard error. From a dump it is one string (the last 2000 bytes). From a stream it is a list of lines (the last 20). |

### `device_command_failed`

Raised in two places:

- A stream with `since="now"` runs `date +%s` on each device and writes a
  start marker with the device's `log` command. It raises this code when it
  starts, if one of these commands exits with a non-zero status, ends without
  an exit status, does not finish within 5 seconds, or `date` does not print
  a time; and while it runs, if the start marker does not come back within 10
  seconds of connecting.
- `Device.dump()` and `Device.adump()` with a `Package` term or `package=`
  take the device's package list before `logcat -d`. They raise this code when
  the list fails: its command exits with a non-zero status, ends without an
  exit status, prints no usable list, or does not finish within 5 seconds.
  `command` is the last command run (`pm list packages -U` or
  `dumpsys package packages`).

A stream's package list never raises it. After a list that fails, the device
gets no new list for 30 seconds: the last list that succeeded still decides
the app ids it names, and the lines it cannot decide are counted as
`unattributed`. When the first list fails, every line of an app id from 10000
to 19999 whose verdict depends on its app is counted, also one logged before
the device clock read at the start (see
[streams.md](streams.md#filter-by-app-extra-commands-and-messages)).

| Key | Value |
| --- | --- |
| `serial` | The device. |
| `command` | The command, as a list of strings. |
| `exit_status` | Its exit status, or `None`. |
| `stderr` | The last lines it wrote to standard error, as a list of strings. |

A flush marker that cannot be written (`stop(flush=...)`) is not an error.
It shows in the stream's summary instead.

### `internal_error`

A stream's reader failed with an unexpected exception. This is a bug in
logprobe. The stream ends with this error, and the original exception is its
`__cause__`.

| Key | Value |
| --- | --- |
| `serial` | The device whose reader failed. |

## Where errors are raised

| Call | `LogprobeError` codes |
| --- | --- |
| `devices()` | `usage_error`, `adb_server_unavailable`, `adb_error` |
| `Device(...)` | `usage_error`, `adb_server_unavailable`, `device_not_found`, `multiple_devices`, `device_offline`, `device_unauthorized`, `adb_error` |
| `device.features()`, `device.shell()` | `adb_server_unavailable`, `device_not_found`, `device_offline`, `device_unauthorized`, `adb_error` |
| `device.dump()`, `await device.adump()` | the codes of `shell()`, plus `logcat_failed`, `device_lost` and `device_command_failed` |
| `stream.start()` or entering the `with` block | the codes of `shell()`, plus `device_command_failed` |
| iterating, `join()`, leaving the `with` block | `device_lost`, `logcat_failed`, `adb_server_unavailable`, `adb_error`, `device_command_failed`, `internal_error` |

`stream()` and `astream()` themselves raise the codes of `Device(...)` when a
device is given as a serial string, because that string becomes
`Device(serial)`.

A stream that fails while it runs delivers the entries already queued and
then raises the error. `join()` and the end of the `with` block raise the
same error object again. When one device fails, the whole stream ends. A
`LogprobeError` that logprobe raises for a running stream always has
`details["serial"]`. After a failed start, `join()` raises the start error
again. See [streams.md](streams.md).

## TimeoutError

The built-in `TimeoutError` is raised, not a `LogprobeError`, when a time
limit you can see in the API runs out:

- `device.shell(args, timeout=...)`: the command did not finish within
  `timeout` seconds.
- `device.dump()` and `device.adump()`: the device sent no byte for 30
  seconds. There is no limit on the whole dump.
- `stream.join(timeout=...)`: the stream did not end in time. The stream
  keeps running.

In other places, a timeout while connecting to the adb server becomes
`adb_server_unavailable`, and a server that stops answering becomes
`adb_error`.

## Other exceptions

| Exception | When |
| --- | --- |
| `TypeError` | An argument has the wrong type. A `bool` is rejected where logprobe checks for a number, for example `tail`, `reconnect`, `buffer_lines`, `buffer_bytes` and `stop(flush=...)`. |
| `ValueError` | An argument has a bad value: a malformed `adb_server`, an empty serial, a `tail` below 1, an out-of-range stream option, an empty device list or a repeated serial. |
| `RuntimeError` | A stream is misused: started twice, iterated or joined before it started, iterated twice at once, iterated when `on_entry` was given, or `join()` was called from inside `on_entry`. |

An exception raised by your `on_entry` callback stops the stream, and
`join()` and the end of the `with` block raise it as it is, unless the stream
had already failed with another error. If the body of the `with` block raised
its own exception, that exception goes on and the stream's error is logged.

With `Device.adump()`, cancelling the task closes the connection and lets
`asyncio.CancelledError` pass unchanged.
