# Snapshots and live streams

A snapshot (`Device.dump`, `Device.adump`) returns what a device's log holds
now. A live stream reads logcat from one or more devices as lines arrive. It
reconnects by itself when a connection drops, skips the replayed lines it
recognises, and reports what it could not deliver as `Gap` records and in a
summary. This page explains how to take a snapshot, and how to start, read,
stop and check a stream, with the blocking API (`logprobe.stream`,
`Device.stream`) and the asyncio API (`logprobe.astream`, `Device.astream`).

It assumes you can already create a `Device` (see [connecting.md](connecting.md)).
Conditions are covered in [conditions.md](conditions.md), entry fields in
[entries.md](entries.md) and error codes in [errors.md](errors.md).

## Take a snapshot with dump and adump

```python
# Methods of Device:
def dump(
    where=None, *, tail=None, level=None, tag=None, message=None, package=None, pid=None
) -> list[LogEntry]: ...
async def adump(
    where=None, *, tail=None, level=None, tag=None, message=None, package=None, pid=None
) -> list[LogEntry]: ...
```

`device.dump()` runs `logcat -d` once on the device, in the same format as a
stream, and returns when logcat has printed everything. `await device.adump()`
does the same on asyncio. Both return a `list` of entries in log order, all held
in memory. A full log buffer can hold hundreds of thousands of lines, so pass
`tail` or a condition when that matters.

- `tail=N` makes logcat on the device pick its last N log records; the
  condition and the shortcuts filter those afterwards.
  `dump(tail=1000, level="W")` returns the entries at level W or above among
  the last 1,000 records, not the last 1,000 warnings. A record whose message
  has several lines gives one entry per line, so the list can hold more than
  N entries.
- `where` and the shortcuts are those of a stream; see
  [conditions.md](conditions.md).
- A snapshot returns no gaps and no summary; it logs the gaps it finds (a
  `chatty` notice), as described under [Gaps](#gaps-where-lines-may-be-missing-or-repeated).
  A `chatty` notice is returned as an ordinary entry. logprobe's own marker
  lines are left out.
- A final line without a line feed is returned only when logcat exited
  normally.
- With a `Package` term or `package=`, the dump first takes one list of the
  device's installed packages (`pm list packages -U`, or
  `dumpsys package packages`; each command may take 5 seconds) and judges
  every line by it; see [conditions.md](conditions.md#package). An INFO names
  each watched package that is not installed, and a WARNING each that runs
  under a system uid.
- `adump()` starts no thread and never starts the adb server. Invalid arguments
  raise when it is awaited. Cancelling the task closes the connection.

Errors:

- Before any I/O: `TypeError` for a wrong type (a bool is not a valid `tail`),
  and `ValueError` for `tail` below 1 or a bad shortcut value.
- `LogprobeError` with code `adb_error` (for example the device lacks
  `shell_v2`, or the adb server refused the request, did not answer or broke
  the protocol; see [errors.md](errors.md#adb_error)), `logcat_failed` (logcat
  exited with a non-zero status; `details` has `exit_status`, and `stderr` as
  text decoded from its last 2000 bytes), `device_lost` (the connection closed
  before logcat reported its exit status; no entries are returned),
  `device_not_found`, `device_offline`, `device_unauthorized` or
  `adb_server_unavailable`. With a `Package` term, `device_command_failed`
  when the package list failed: a non-zero exit status, none at all, no
  usable output, or a command that took more than 5 seconds (see
  [errors.md](errors.md#device_command_failed)).
- `TimeoutError` when the device sends no byte for 30 seconds once logcat
  runs. There is no limit on the whole dump.

## Create a stream, then start it

`logprobe.stream(devices, ...)` reads several devices in one stream.
`device.stream(...)` is the same as `logprobe.stream([device], ...)`. Both
return a `LogStream` that is not started yet. Start it with a `with` block (or
call `start()`), then iterate it:

```python
import logprobe

device = logprobe.Device()
with device.stream(level="W") as stream:
    for entry in stream:
        print(entry.logged_at, entry.tag, entry.message)
```

The arguments are the same for both functions, except that `devices` exists
only on `logprobe.stream`:

| Argument | Default | Meaning |
| --- | --- | --- |
| `devices` | required | `Device` objects or serial strings; at least one, no serial twice. |
| `where` | `None` | A condition; only entries that match it are delivered. |
| `level`, `tag`, `message`, `package`, `pid` | `None` | Shortcuts, combined with `where` by AND. See [conditions.md](conditions.md). |
| `since` | `None` | `None` starts with the backlog the device still holds; `"now"` skips it. |
| `on_entry` | `None` | A callback for every entry, called on a consumer thread (blocking API only). |
| `reconnect` | `60.0` | Reconnect budget in seconds, per device. See [Reconnect and resume](#reconnect-and-resume). |
| `detect_skips` | `False` | Also detect lines that an older logd skips without notice when the consumer falls behind. See [Detect skipped lines with `detect_skips`](#detect-skipped-lines-with-detect_skips). |
| `buffer_lines` | `10_000` | Most lines queued for the consumer, over all devices (at least 1). |
| `buffer_bytes` | `4 * 1024 * 1024` | The same limit in bytes of logcat output (at least 65536). |

A serial string becomes `Device(serial)` with the default server settings, so
creating the stream contacts the adb server (and may start it) and may raise
`LogprobeError` for a missing or unusable device. To use another adb server,
pass `Device` objects.

Wrong arguments fail when the stream is created: `TypeError` for a wrong type
(a bool is not a number), and `ValueError` for a value out of range, an empty
`devices`, a malformed serial string or a repeated serial.

`start()` runs on the calling thread. It checks each device in turn (the device
must support the `shell_v2` feature, otherwise `adb_error`; with `detect_skips`
it also reads the device's API level; with a condition on the app it takes the
device's package list, see
[Filter by app](#filter-by-app-extra-commands-and-messages)), opens one logcat
connection per device, and then starts one reader thread per device, plus a
consumer thread when `on_entry` is given. When a step fails, everything that
was opened is closed and the `LogprobeError` is raised. A stream is used once:
a second `start()` raises `RuntimeError`, also after a failed start.

Each device runs `logcat` with its default buffers, in the `threadtime` format
with the `year`, `usec`, `zone` and `uid` modifiers.

## Read entries by iterating or with a callback

There are two ways to consume a stream. You choose one when you create it.

Iterate it with `for entry in stream`. The entries are handed over on your
thread. Only one iteration can run at a time. The loop ends when every device
has ended and the queue is empty. If the stream failed, the error is raised
after the queued entries were delivered.

Or pass `on_entry`. A consumer thread then calls it for every entry, one at a
time, and the stream cannot be iterated (`RuntimeError`). The callback must
return. If it raises, including `SystemExit`, the stream is killed, the entries
still queued are dropped, and `join()` raises that exception. So does the end
of the `with` block, unless the body raised its own exception (see
[Leaving the `with` block](#leaving-the-with-block)). If the stream had already
failed with another error, that error is raised instead.

```python
import time


def handle(entry):
    print(entry.serial, entry.tag, entry.message)


with device.stream(tag="ActivityManager", on_entry=handle) as stream:
    time.sleep(10)
print(stream.summary.complete)
```

Entries of one device come in the order the device logged them. Entries of
different devices are not reordered. Every entry has the `serial` of its
device.

## Stop, flush or kill a stream

A stream runs until you end it or it fails. These calls end it:

| Call | Effect |
| --- | --- |
| `stop()` | The readers notice at their next check (at least every 0.25 seconds while they wait for data), process every complete line of the network reads they took, deliver the matching entries (up to the device's pending flush marker, if it is among them) and end. Once a reader sees the stop, it starts no further read; a read already under way may still bring lines, and those are handled the same way. Output not read, and a line whose end has not arrived (unless it was already cut at the 64 KiB line limit), are not delivered. To end after everything logged so far, use `stop(flush=...)`. |
| `stop(flush=seconds)` | Each device ends at a marker line written into its log after the call. See below. |
| `kill()` | The readers end at their next check and queue nothing more. Queued entries are dropped. |
| `join(timeout=None)` | Waits for the stream to end and returns its `StreamSummary`. |

`stop()` and `kill()` never block, and you can call them from any thread, from
a signal handler, any number of times. After `kill()` returns, no new entry is
handed to the consumer, except one that another thread was already handing
over. A `stop()` before `start()` makes the stream end at once without
connecting, and without an error.

After `stop()` you keep iterating until the loop ends by itself:

```python
with device.stream(tag="ActivityManager") as stream:
    for entry in stream:
        if "Start proc" in entry.message:
            stream.stop()  # the loop delivers what is queued, then ends
```

`join()` raises `TimeoutError` when `timeout` passes; the stream keeps running.
It raises the error that ended the stream, the same object every time, or the
exception that `on_entry` raised. It raises `RuntimeError` before `start()` and
when called from inside `on_entry`. Without `on_entry`, the readers can end
only when the queue is consumed or the stream is stopped.

### Leaving the `with` block

What happens at the end of the `with` block depends on how you consume the
stream:

- Iterated stream: if the loop ran to its end, the block waits for the readers.
  If you leave earlier (with `break`, `return` or an exception), the stream is
  killed and the queued entries are dropped. In both cases, when the body
  raised nothing, the block raises the stream's error, if there is one.
- Stream with `on_entry`: the block calls `stop()`, unless you already called
  `stop()` or `stop(flush=...)`, and waits until the queued entries were given
  to the callback. A pending flush is waited for. If the body raised, the block
  calls `stop()` in any case, which ends a pending flush as a `stop()` does
  (`cancelled`, or `done` on a device whose marker was already read).
- An exception from the body goes on unchanged. If the stream failed with a
  different error meanwhile, that error is logged.
- Ctrl-C kills the stream. All waits are cut into 0.25 second slices, so
  Ctrl-C works while waiting, also on Windows.

An error raised by the loop is raised again by the end of the block (it is the
same object), so catch it around the whole block:

```python
try:
    with logprobe.stream([device]) as stream:
        for entry in stream:
            ...
except logprobe.LogprobeError as error:
    print(error.code, error.details.get("serial"))
```

### Flush: end after the lines logged so far

`stop(flush=seconds)` writes a marker line into each device's log, and each
device's reader ends at its marker. The marker is written after the call, so
lines logged shortly after it can be included, and each device has its own
cutoff. The connections stay open until then, and the stream ends by itself.
A device's flush ends as `done` when its reader saw the marker. At that
moment the last matching entries before it may still wait for room in the
queue, so keep consuming until the stream ends (a `kill()` can still drop
them). Gaps still apply: a
`Gap` before the marker means lines may be missing. `seconds` is a budget. Writing the marker,
receiving, processing and reconnecting use it up. Time a reader spends waiting
for room in a full queue does not count, so a slow consumer does not use it up.

The marker is an ordinary log line with the tag `logprobe` and the message
`flush-` followed by 32 hex digits. Other readers of the device log, such as
`adb logcat`, see it. logprobe never delivers or counts its own marker lines,
also ones that earlier runs left in the log.

How each device's flush ended is in `summary.devices[i].flush`:

| Value | Meaning |
| --- | --- |
| `done` | The marker came back. |
| `timed_out` | The budget ran out. |
| `failed` | The marker could not be written: the command exited with an error. |
| `cancelled` | A `stop()`, `kill()` or a failure of the stream came first. |
| `not_requested` | No flush was requested, the flush is still pending, or the device had ended before the request. |

A flush that did not end as `done` makes the summary incomplete. The stream
raises nothing for it. Other rules:

- `stop(flush=...)` does nothing after a `stop()` or an earlier
  `stop(flush=...)`. Before `start()` it is the same as `stop()`.
- A `stop()` while a flush is pending ends it as `cancelled`, unless its marker
  is in the output the readers took; then it ends `done`.
- A consumer that does not take entries holds a flush up until a `stop()` or
  `kill()`.
- It takes the queue's lock for a moment, so do not call it from a signal
  handler.
- `flush` must be a positive, finite number: `TypeError` for another type (a
  bool is not a number), `ValueError` for NaN, infinity, zero or a negative
  value.

## Gaps: where lines may be missing or repeated

A `Gap` marks a place in a device's stream where lines may be missing or
repeated. Plain iteration skips gaps. `stream.items()` yields them in place,
where the stream noticed them, together with the entries:

```python
with device.stream() as stream:
    for item in stream.items():
        if isinstance(item, logprobe.Gap):
            print("gap on", item.serial, item.reason, item.cause, item.lost)
        else:
            print(item.message)
```

A `Gap` has these fields:

| Field | Meaning |
| --- | --- |
| `serial` | The device the gap belongs to. |
| `reason` | `ring_rotated`, `continuity_unknown` or `device_reported` (below). |
| `cause` | `released` (logd cut the reader off), `disconnected` (the connection was lost, or logcat ended or failed), `stalled` (the reader closed the connection itself, see [`detect_skips`](#detect-skipped-lines-with-detect_skips)) or `notice` (for `device_reported`). |
| `detected_at` | Host clock, aware UTC: when the `chatty` notice was read, or, for the other reasons, when the reconnect was planned (before the new connection opened). |
| `start_at` | Roughly where in the device's time the gap lies; a hint, not a bound. `None` when unknown. |
| `lost` | The number of lost lines when the device says so, else `None`. |

The reasons mean:

- `ring_rotated`: lines read before a disconnect had not come back when the
  resume check ended, so the device probably no longer has them. Lines after
  them may be missing too. The number is not known (it can be 0). If those
  lines do come back later, they are delivered a second time.
- `continuity_unknown`: the stream could not verify that the new connection
  continues the old one. Lines may be missing or repeated.
- `device_reported`: an Android 7 device wrote a `chatty` notice that it dropped
  lines. `lost` holds the count. The notice line is also delivered as an entry
  (if it matches the condition), and the gap comes right before it.

Gaps are not filtered by the condition. `gap.to_dict()` returns a dict that
`json.dumps` accepts, with `"schema": "logprobe.gap/1"`.

Gaps are also logged on the `logprobe` logger, so that they are seen without
`items()`: the first gap of each reason on a device is a WARNING, later ones of
that reason are only counted, and when the device's read ends one WARNING gives
those counts (none when there were no later gaps), also when the read ended
with an error or a stop. A dump (`Device.dump`, `Device.adump`) logs its gaps
the same way, also when it fails or is cancelled. The messages are logged on
the thread of the device's reader (the event loop for an asyncio stream or
`adump`), so a slow logging handler slows the read; use a queue-based handler
(`logging.handlers.QueueHandler`) for a slow destination.

## Reconnect and resume

When the connection to a device ends (the adb server restarted, the cable was
pulled, logd cut the reader off, or logcat exited), the stream connects again.
It starts the new connection one second before the newest line it had read,
and drops the replayed lines it recognises, so that usually nothing is missing
or repeated (the limits are listed below). Each reconnect adds 1 to
`reconnects` in the summary and is logged as a warning. If the stream cannot
verify the result, it reports at most one gap for that disconnect.

How a connection ended decides what happens next:

| The connection | What the stream does | Error when it gives up |
| --- | --- | --- |
| was cut off by logd (exit status 1 and logcat's "unexpected EOF" message) | Reconnects at once. This is not a failure, unless three connections in a row each end within one second of opening. | `logcat_failed` |
| was closed by the reader itself after waiting a whole second for room (`detect_skips`), before an exit status arrived | Waits until the queue is at most half full, then reconnects. This is not a failure and never counts as a quick end. | none |
| was lost: closed without an exit status | Counts a failure and retries. | `device_lost` |
| ended with exit status 0, or 128 or higher (a signal) | Counts a failure and retries. The first such retry after the start, and the first after each stable connection, is immediate. | `device_lost` |
| failed with another status before any standard output, on the first connection | Ends the stream at once. | `logcat_failed` |
| failed with another non-zero status | Counts a failure and retries. | `logcat_failed` |

Each device has its own budget of `reconnect` seconds, shared by its
failures. The budget counts from the first failure after the last stable
connection: a connection that stayed open for 10 seconds after its first
standard output is stable and resets the budget and the waits. The waits
between attempts are 1, 2, 4, 8, 16 and then 30 seconds, never longer than the
budget that is left.
The budget is checked when a failure happens, so it is not a strict deadline:
an attempt that starts just before it runs out can still connect afterwards. A
reconnect attempt that fails before a connection exists also counts. When the
budget is used up after such attempts, the error depends on the last attempt:
`adb_server_unavailable` or `adb_error` as raised, `device_lost` when the
device was not found, offline or unauthorized, and `adb_error` for anything
else (for example a timeout or a broken connection).

- `reconnect=math.inf` never runs out of budget. A first connection that
  fails before any standard output (see the table), a late start
  marker or a broken shell protocol still end the stream.
- `reconnect=0` does not recover a lost connection, an ended logcat or a failed
  logcat. Connections that logd cut off are still resumed, and three in a row
  that each end within one second end the stream with `logcat_failed`.
  Connections the reader closed itself (`detect_skips`) before an exit status
  arrived are always resumed. When a read holds both the stall and logcat's
  exit status, the exit status decides, as in the table.
- When different failures share one budget, the failure that finds the budget
  used up decides the error.
- Reconnecting never starts the adb server.

The resume check keeps the most recent lines (up to 2 MiB or 20,000 lines) to
recognise replayed lines. A gap is reported only when the check can tell, so
some losses go unreported:

- Lines that reached logd more than one second after their timestamp (or after
  the device clock stepped back), when logd leaves them out of the replay.
- Lines lost from a buffer in which no line was read during the last second
  before the disconnect, and deletions in the middle of a ring that remove only
  unread lines (logd pruning a chatty source, another tool running
  `logcat -c`).
- Lines an older logd skipped without a notice while the reader was slow: all
  of them without `detect_skips`; with it, those skipped before the reader had
  waited a whole second for room (see
  [Detect skipped lines](#detect-skipped-lines-with-detect_skips)).
- Lines that do not parse: a replayed one is delivered twice without a gap.

It may also report too much: `ring_rotated` when the ring dropped only lines
that had been read or when the replay came more than one second late (the
late lines are then delivered a second time), and
`continuity_unknown` with repeated lines when logd replays from before the
resume point and the kept lines no longer cover it.

## Skip the backlog with `since="now"`

By default a stream starts with the backlog the device still holds. With
`since="now"`, `start()` reads each device's clock (`date +%s`), writes a start
marker line into its log and connects. The stream drops every line up to that
marker and delivers what comes after it. A line logged in the same second as
the start may still come before or after the marker.

The start marker has the tag `logprobe` and the message `start-` followed by
32 hex digits, in the device's main log buffer. Other readers of the device log
see it.

The summary counts what was read before the marker in `lines`, `unparsed`,
`truncated` and `gaps` too; `entries` counts only entries after the marker.
So a line before the marker that does not parse still makes the summary
incomplete. After a reconnect, a replayed line without a time (one that does
not parse, or one whose time has no zone) cannot be matched, so it is
delivered on replay, even when the start marker had caused it to be skipped.

`start()` fails with `device_command_failed` when one of these commands exits
with a non-zero status, ends without an exit status, does not finish within 5
seconds, or `date` does not print a time. The same code ends the stream when the
marker does not come back within 10 seconds of connecting. Its `details` has
`serial`, `command`, `exit_status` and `stderr`. A device or adb server that
cannot be reached raises its own code instead (see [errors.md](errors.md)).

## Filter by app: extra commands and messages

With a `Package` term or the `package=` shortcut, a stream finds the app of
each line from its uid and the device's list of installed packages. How the
verdict is reached, and which lines are counted as `unattributed`, is in
[conditions.md](conditions.md#package). This section lists what the stream
runs on each device and what it logs.

`start()` runs these commands on each device, after the API level check and
before the start marker of `since="now"`:

- `date +%s`, with `since=None`, to tell the backlog from new lines. When it
  fails or takes more than 5 seconds, an INFO says so and the stream goes on
  without that clock.
- One package list: `pm list packages -U`, or `dumpsys package packages` when
  `pm` prints that it does not know `-U` or prints no usable list. The list
  has 5 seconds in all. When it fails (a non-zero exit status, none at all, no
  usable output, or no time left), the stream starts anyway, and the device has
  no list for 30 seconds: every line of an app id from 10000 to 19999 whose
  verdict depends on its app is counted as `unattributed` then, also one
  logged before the clock read by `date +%s`.

An adb error in either command fails `start()`.

While reading, the stream takes the list again:

- every 30 seconds, in the background: on a short-lived helper thread
  `logprobe-list-<serial>` in the blocking stream, on a task of that name in
  the asyncio stream. It has 5 seconds, and the reader goes on reading
  meanwhile. `stop()`, `kill()` and `stop(flush=...)` return without waiting
  for it, but a line before the flush marker that needs a list makes the
  reader wait for it within the flush budget; when the budget runs out first,
  the flush ends `timed_out`. `join()` of the blocking stream waits for the
  helper thread, which checks every 0.25 seconds of blocking I/O whether the
  reader ended and may take longer while it parses the output; use
  `join(timeout=...)` for a deadline.
- for a read with a line that needs a list, at most once in 0.5 seconds.
  Reading that device pauses for at most 2 seconds.

A list that fails while reading, an adb error included, does not end the
stream, and the device gets no new list for 30 seconds: the last list that
succeeded still decides the app ids it names, and the lines it cannot decide
are counted as `unattributed`.

The stream logs these messages per device, through the `logprobe` loggers:

| Level | When |
| --- | --- |
| WARNING | The first list of the device that failed (once): the command and what went wrong. |
| WARNING | The first line of the device that had to be judged without knowing its app (once), with the cause. |
| WARNING | A watched package runs under a system uid, so every process of that uid is taken as its own (once per package). |
| WARNING | A list shows that a watched package has a new uid or is no longer installed, and lines judged with its old uid since the last list are counted (an INFO when there are none). |
| WARNING | A watched package appeared under a uid whose lines were judged before it was known; the message gives the count. |
| INFO | After the first list that succeeded: a watched package that is not installed (once per package). |
| INFO | The device clock could not be read. |

## Check the summary

`stream.summary` is a `StreamSummary` with one `DeviceSummary` per device in
`summary.devices`, in the order given. `join()` returns the same. While the
stream runs the summary may be slightly old; once the readers ended it is
exact.

| Field | Meaning |
| --- | --- |
| `serial` | The device. |
| `started_at`, `ended_at` | When the stream started, and when this device's reader ended (`None` while it runs). |
| `lines` | Lines read, including lines the condition removed (replayed lines and markers excluded). |
| `entries` | Entries that matched the condition and were passed on for delivery, without those before a start marker or after a flush marker. Entries that a kill, an early exit or a failing `on_entry` dropped are counted too. |
| `unparsed` | Lines that could not be parsed. |
| `truncated` | Lines cut short at the line length limit (64 KiB). |
| `gaps`, `lost` | Gaps reported, and the total of the known lost-line counts. |
| `reconnects` | Connections made after the first. |
| `unattributed` | With a condition on the app, lines whose app could not be determined, plus lines that may have been judged with an outdated package list (see [conditions.md](conditions.md#package)); 0 without one. |
| `flush` | How the flush ended (see above). |
| `error` | The error that ended this device, or `None`. |

`complete` is `True` when nothing is known to be missing, uncertain or failed:
no gaps, no unparsed, truncated or unattributed lines, a flush that is not
`timed_out`, `failed` or `cancelled`, and no error. `StreamSummary.complete` is
`True` when every device is complete.

`complete` describes what the stream read, not what your code received. After
`kill()`, an early exit from the `with` block, a failing `on_entry` or Ctrl-C
it can be `True` although queued entries were dropped. Count the entries you
received if you need to know.

`summary.to_dict()` returns one dict per device (schema
`"logprobe.summary/1"`), ready to write as one JSON line each. Summaries that
carry an error compare equal only when they share the same error object;
compare `error.code`, `error.message` and `error.details` instead.

## Back-pressure: a slow consumer makes the readers wait

All devices of a stream share one queue. When it is full, the readers wait;
logprobe drops nothing. `buffer_lines` limits the queued entries, and
`buffer_bytes` limits the logcat output bytes they were read from. Those bytes
include lines the condition removed from the same read; a read from which
nothing is queued counts nothing. A gap, and the end of each device, count as
one more line and 256 more bytes. A batch of entries is let in whenever the
queue is below both limits, so the queue can go over a limit by less than one
batch (at most 2,048 entries, plus their gaps).
After a stop, the limits no longer apply.

While a reader waits, it does not read its connection, but the device keeps
logging. If the reader falls far behind, the device's logd may cut it off or
skip lines. When logd cuts it off, the stream reconnects and resumes as
described above, and reports what it can detect as a gap. Skipped lines are
detected, in part, only with `detect_skips` (below).

## Detect skipped lines with `detect_skips`

On API levels 25 and below and on 30, logd may skip lines of a reader that does
not keep up, without any notice, instead of cutting it off. Without
`detect_skips` the stream cannot tell. Pass `detect_skips=True` when you read
such a device and your consumer may fall behind. It is off by default because
it costs a device command at the start and a reconnect whenever the queue stays
full.

```python
with device.stream(detect_skips=True) as stream:
    for item in stream.items():
        if isinstance(item, logprobe.Gap) and item.cause == "stalled":
            print("lines may be missing on", item.serial)
```

With `detect_skips=True`:

- `start()` reads each device's API level once (`getprop ro.build.version.sdk`).
- On API levels 25 and below and on 30, the reader closes its connection itself
  once it has waited a whole second for room in the queue since it last read
  from the device. A WARNING says so. It then waits until the queue is at most
  half full (in lines and in bytes), and connects again as after any other
  disconnect. A gap with the cause `stalled` is reported when the replay check
  finds lines missing or cannot verify that the new connection continues the
  old one; lines lost in a log buffer from which nothing was read in the last
  second before the stall can go unreported. The wait counts as waiting for room, so it does not use up
  the budget of `stop(flush=...)`.
- Closing the connection can itself cost lines: unread lines that the log
  buffer on the device overwrites before the new connection replays them are
  lost. They are reported as a gap with the cause `stalled` where the gap check
  can tell; the losses listed as unreported under
  [Reconnect and resume](#reconnect-and-resume) stay unreported. In one test on
  an API 24 emulator, the test wrote about 1.5 times the capacity of the
  256 KiB main buffer while the consumer was paused, with the queue limited to
  100 lines; the stream lost lines this way with the option and none without
  it.
- Other API levels cut a slow reader off themselves, which the stream always
  detects, so the option is ignored for them. An INFO message says so.
- A device whose API level cannot be read (the command fails, prints no number
  or a number of more than four digits, or takes longer than 5 seconds) is
  treated as an older one, and a WARNING says so. An adb error while reading
  it fails `start()` as the other start steps do.
- logd's behaviour was measured on emulators at API levels 24, 26, 28 to 32
  and 36. Levels 25, 27, 33 to 35 and above 36 were not; 25 is treated as
  older, the others as newer.

Not detected, even with the option:

- Lines logd skipped before the reader had waited a whole second.
- Lines skipped while the reader never waits a whole second in all for room
  between two reads from the device (a slow consumer that still takes lines
  often enough).

With several devices, a device that closed its connection this way connects
again only once the queue is half empty. While the other devices keep it
fuller than that (they log more than a slow consumer takes), it stays
disconnected, and lines that its own log buffer on the device overwrites
meanwhile are lost. They are reported as a gap when it connects again where the
gap check can tell; the losses listed as unreported under
[Reconnect and resume](#reconnect-and-resume) stay unreported.

## Several devices in one stream

```python
with logprobe.stream(["emulator-5554", "emulator-5556"], level="E") as stream:
    for entry in stream:
        print(entry.serial, entry.tag, entry.message)
```

`start()` checks and connects all devices; if one fails, nothing is left open.
While the stream runs, a device that fails ends the whole stream: the other
devices are stopped, the entries already queued are delivered, and then the
first error is raised. `error.details["serial"]` names the device. In the
summary, that device has the error, and a device that was only stopped has
`error=None`.

## Use streams on asyncio

`logprobe.astream` and `Device.astream` take the same arguments as the blocking
functions, except `on_entry`, and return an `AsyncLogStream`. The entries,
gaps, summaries and errors are the same.

```python
import asyncio
import logprobe


async def main(device):
    async with device.astream(tag="ActivityManager") as stream:
        async for entry in stream:
            print(entry.message)


device = logprobe.Device()  # blocking: create it before the loop runs
asyncio.run(main(device))
```

The differences:

- The stream reads every device on a task of the running event loop. It starts
  no thread, process or executor, and it never starts the adb server. One
  stream lives on the loop that was running when it was started.
- `astream()` is not a coroutine, but a serial string becomes `Device(serial)`,
  which blocks and may start the adb server. Create the `Device` objects
  before the loop runs and pass them.
- `start()` and `join()` are coroutines. `stop()` and `kill()` are plain
  methods that never block.
- Leaving `async with` after the loop ran to its end waits for the readers.
  Leaving it any other way (break, exception,
  cancellation) kills the stream, also during a pending flush. After
  `stop(flush=...)`, keep iterating until the loop ends. When the body raised
  nothing, the block raises the stream's error, if there is one.
- `stop(flush=...)` takes effect at once on the loop's thread. From another
  thread it is handed to the loop. If the loop is closed it does nothing. Do not
  call it from a signal handler.
- A cancelled `__anext__` (for example under `asyncio.timeout`) loses nothing.
  It ends that iteration, the stream keeps running, and you can start a new
  `async for`.
- Cancelling the task that awaits `start()` closes everything and ends the
  stream early. `CancelledError` goes on, and `join()` then returns the summary
  without an error.

## Errors that end a running stream

Iteration, `join()` and the end of the `with` block raise the error that ended
the stream. The codes are described in [errors.md](errors.md):

| Code | When |
| --- | --- |
| `device_lost` | The device did not come back within the reconnect budget, or `reconnect=0` and the connection was lost or logcat ended. |
| `logcat_failed` | logcat failed before any standard output on the first connection, or kept failing or being cut off quickly (with `reconnect=0`, one failure is enough). `details` has `stderr`. |
| `adb_server_unavailable`, `adb_error` | The last reconnect attempt failed that way, or (`adb_error`) the adb server broke the shell protocol. |
| `device_command_failed` | The start marker of `since="now"` did not come back within 10 seconds. |
| `internal_error` | A reader failed unexpectedly. |

Each has `serial` in `details`. The stream also logs warnings with the
standard `logging` module, through child loggers of the `logprobe` logger:
each reconnect, and lines that logcat wrote to its standard error (at most 10
lines a second, each cut to 1,024 bytes).

## Limits

- While a stream takes a package list at the start or for a read, it does not
  read that device. An older logd may skip lines then, and `detect_skips` does
  not see it.
- The threading rules of the blocking stream are verified on CPython with the
  global interpreter lock. The free-threaded build is not verified.
