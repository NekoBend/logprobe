# Connecting to devices

logprobe talks to the adb server directly over TCP, using the same protocol
as the `adb` command. It does not run `adb` for each operation. The only
process it ever starts is `adb start-server`, and only under the conditions
described below.

This page covers how logprobe finds the adb server, how it picks a device,
and the small device API (`devices()`, `Device`, `features()`, `shell()`).
Reading logs is described in [streams.md](streams.md); errors are described in
[errors.md](errors.md).

## The adb server address

`devices()` and `Device(...)` take an `adb_server` argument. logprobe uses
the first of these that is set:

1. The `adb_server` argument, as `tcp:HOST:PORT`.
2. The environment variable `ADB_SERVER_SOCKET`, in the same form.
3. The environment variable `ANDROID_ADB_SERVER_PORT`: a port number on
   127.0.0.1.
4. The default, 127.0.0.1:5037.

An environment variable that is set but empty counts as unset.

HOST must be an IP address. logprobe never resolves host names, so it never
sends a DNS query. Accepted forms:

| HOST | Example |
| --- | --- |
| IPv4 address | `tcp:127.0.0.1:5037` |
| IPv6 address in square brackets | `tcp:[::1]:5037` |
| IPv6 address with a zone | `tcp:[fe80::1%12]:5037`, `tcp:[fe80::1%eth0]:5037` |
| `localhost`, in any letter case | `tcp:localhost:5037` (means 127.0.0.1) |

A zone after `%` may hold letters, digits, `_` and `-`, in non-empty labels
separated by dots, at most 63 characters in all. A numeric zone index is the
portable form, because interface names differ between platforms. PORT must
be from 1 to 65535.

Any other host name is rejected before any network activity, even if the
`adb` command itself would accept it. Write the IP address instead.

A bad address is reported differently depending on where it came from:

- A malformed `adb_server` argument raises `ValueError`. A value that is not
  a string raises `TypeError`.
- A malformed `ADB_SERVER_SOCKET` or `ANDROID_ADB_SERVER_PORT` raises
  `LogprobeError` with code `usage_error`. `details["variable"]` names the
  variable.

When `ADB_SERVER_SOCKET` is set, `ANDROID_ADB_SERVER_PORT` is not read.

## Starting the adb server

When the server does not accept a connection, logprobe may run
`adb start-server` once. It does so only when all of these hold:

- `start_server` is `True` (the default).
- The address is the default one: no `adb_server` argument, and neither
  `ADB_SERVER_SOCKET` nor `ANDROID_ADB_SERVER_PORT` is set.
- The environment variable `ANDROID_ADB_SERVER_ADDRESS` is not set to a
  non-empty value. adb reads this variable as the server's address; logprobe
  does not use it as an address, it only checks whether it is set. When it is
  set, your `adb` talks to another server, so logprobe does not start a local
  one. To point logprobe at that server, set `ADB_SERVER_SOCKET=tcp:IP:PORT`.
- The `adb` executable is found.

`adb start-server` runs with a copy of your environment without
`ADB_SERVER_SOCKET`, `ANDROID_ADB_SERVER_ADDRESS` and
`ANDROID_ADB_SERVER_PORT`, and with `ADB_MDNS=0` added. So it can only start
the default local server, and that server sends no mDNS discovery queries.
The command may take up to 20 seconds.

logprobe looks for the `adb` executable in this order:

1. The `adb` argument of `devices()` or `Device(...)`.
2. The environment variable `LOGPROBE_ADB`.
3. `adb` on `PATH`. On Windows the current directory is not searched.
4. `platform-tools/adb` under `ANDROID_HOME`, then under `ANDROID_SDK_ROOT`.

If the `adb` argument or `LOGPROBE_ADB` names something that is not an
executable, logprobe does not fall back to another adb: the server is not
started.

If the server stays unreachable, `LogprobeError` with code
`adb_server_unavailable` is raised. Its `details["reason"]` says why no start
was attempted, or why it did not help. See [errors.md](errors.md#adb_server_unavailable).

Only `devices()` and `Device(...)` may start the server. A stream given a
serial string, by `stream()` or by `astream()`, creates a `Device` with the
default arguments, so that may start it too. A stream that reconnects never
starts it, and `Device.adump()` and a started asyncio stream never start it.

## Listing devices

`logprobe.devices()` returns every device the adb server knows, in every
state adb reports:

```python
import logprobe

for info in logprobe.devices():
    print(info.serial, info.state, info.model)
```

It takes the keyword arguments `adb_server`, `adb` and `start_server`
described above.

Each item is a `DeviceInfo`, a frozen dataclass:

| Field | Type | Meaning |
| --- | --- | --- |
| `serial` | `str` | The device serial. A device without one is listed as `(no serial number)`. |
| `state` | `str` | adb's own word: `device` (ready), `offline`, `unauthorized`, and so on. It may contain spaces, as in `no permissions (...)`. |
| `model` | `str \| None` | The `model:` value adb reports, or `None`. |
| `product` | `str \| None` | The `product:` value, or `None`. |
| `device` | `str \| None` | The `device:` value, or `None`. |
| `transport_id` | `str \| None` | The `transport_id:` value, or `None`. |

Only a device in state `device` can be used.

## Device

`logprobe.Device` is one connected device:

```python
import logprobe

device = logprobe.Device()  # the only ready device
device = logprobe.Device("emulator-5554")  # a device by serial
device = logprobe.Device(adb_server="tcp:192.168.1.20:5037")
```

The signature is
`Device(serial=None, *, adb_server=None, adb=None, start_server=True)`.

The adb server is contacted, and the device is chosen, when the object is
created. A missing or unusable device fails at once.

A `Device` holds no open connection. Each method call that talks to the
device opens its own connection to the adb server and closes it when done.
`device.stream()` and `device.astream()` connect only when the stream starts.

### Choosing the device

With a serial (the `serial` argument, else the `ANDROID_SERIAL` environment
variable):

| Situation | Result |
| --- | --- |
| The serial is attached in state `device` | That device. |
| The serial is not attached | `device_not_found`; `details` has `serial` and `attached` (the list of attached serials). |
| The serial is in state `unauthorized` | `device_unauthorized`; `details` has `serial` and `state`. |
| The serial is in any other state | `device_offline`; `details` has `serial` and `state`. |

Without a serial:

| Situation | Result |
| --- | --- |
| Exactly one device is in state `device` | That device, whatever the other devices' states. |
| More than one device is in state `device` | `multiple_devices`; `details["serials"]` lists them. |
| Devices are attached, but none is ready | `device_unauthorized` if any of them is unauthorized, else `device_offline`; `details["devices"]` maps each serial to its state. |
| No device is attached | `device_not_found`, with empty `details`. |

A `serial` argument that is not a string raises `TypeError`. An empty serial,
or one that contains NUL or a line break, raises `ValueError`.

### Attributes

| Attribute | Meaning |
| --- | --- |
| `serial` | The serial of the chosen device. |
| `server` | `(host, port)` of the adb server in use. The host is a numeric IP address; an IPv6 address has no brackets. |

### Errors when creating a Device

`Device(...)` raises `LogprobeError` with one of these codes:
`adb_server_unavailable`, `device_not_found`, `multiple_devices`,
`device_offline`, `device_unauthorized`, `adb_error`, or `usage_error` for a
malformed environment variable. See [errors.md](errors.md).

## Device features

`device.features()` returns the adb feature names the device reports, as a
`frozenset[str]`:

```python
if "shell_v2" not in device.features():
    print("this device cannot be read by logprobe")
```

logprobe reads logcat output through the adb shell protocol v2, so the
device must report the `shell_v2` feature. `Device.dump()`, `Device.adump()`
and starting a stream check this first. A device without it fails with
`LogprobeError` code `adb_error`, and `details["missing_feature"]` is
`"shell_v2"`. logprobe does not check the Android version itself.

## Running a command

`device.shell(args, timeout=30.0)` runs one command on the device and waits
for it to finish:

```python
result = device.shell(["getprop", "ro.build.version.sdk"])
if result.exit_status == 0:
    print(result.stdout.decode().strip())
```

`args` is a sequence of strings: the program, then its arguments. logprobe
quotes each argument for the device shell, so shell syntax such as pipes or
`$VAR` is passed to the program as plain text. A single string instead of a
sequence raises `TypeError`. An empty sequence, an empty program name, or an
argument that contains NUL or a line break raises `ValueError`. An empty
argument after the program is allowed.

The result has three attributes:

| Attribute | Type | Meaning |
| --- | --- | --- |
| `exit_status` | `int \| None` | The command's exit status, or `None` if the connection dropped before the device reported one. |
| `stdout` | `bytes` | What the command wrote to standard output. |
| `stderr` | `bytes` | What the command wrote to standard error. |

A non-zero exit status is not an error: check `exit_status` yourself. When
`exit_status` is `None`, the output may be incomplete: it holds only the
packets that arrived whole before the connection dropped.

`timeout` is one overall limit in seconds for connecting and running the
command, however slowly its output arrives. If the command does not finish
in time, `TimeoutError` is raised. With `timeout=None` the command itself has
no limit; each step of connecting still waits at most 10 seconds.

`shell()` uses the shell protocol v2 but does not check for `shell_v2` first.
It may raise `LogprobeError` with code `device_not_found`, `device_offline`,
`device_unauthorized`, `adb_server_unavailable` or `adb_error`.

## Other Device methods

- `device.dump(...)` and `await device.adump(...)` read what the device's log
  holds now and return a list of entries.
- `device.stream(...)` and `device.astream(...)` read the log live. They are
  the same as `logprobe.stream([device], ...)` and
  `logprobe.astream([device], ...)`.

See [Take a snapshot](streams.md#take-a-snapshot-with-dump-and-adump) for
`dump` and `adump`, [streams.md](streams.md) for streams, and
[conditions.md](conditions.md) for filtering.

## asyncio

Creating a `Device` is blocking: it talks to the adb server and may start it.
`devices()`, `features()` and `shell()` are blocking too. In an async
program, create the `Device` objects before the event loop runs, and pass
them to `astream()` instead of serial strings. A serial string passed to
`astream()` becomes `Device(serial)`, which blocks.

`Device.adump()` and a started asyncio stream use an asyncio adb client. They
start no thread and no process, and they never start the adb server.

## Environment variables

| Variable | Read by | Effect |
| --- | --- | --- |
| `ADB_SERVER_SOCKET` | logprobe | Server address as `tcp:HOST:PORT`, used when no `adb_server` argument is given. |
| `ANDROID_ADB_SERVER_PORT` | logprobe | Server port on 127.0.0.1, used when neither `adb_server` nor `ADB_SERVER_SOCKET` is given. |
| `ANDROID_ADB_SERVER_ADDRESS` | adb; logprobe only checks whether it is set | When set, logprobe does not run `adb start-server`. |
| `ANDROID_SERIAL` | logprobe | The device serial, used when `Device()` gets no `serial`. |
| `LOGPROBE_ADB` | logprobe | Path of the `adb` executable, used to start the server. |
| `ANDROID_HOME`, `ANDROID_SDK_ROOT` | logprobe | Where to look for `platform-tools/adb` when `adb` is not on `PATH`. |

An empty value counts as unset for all of them.
