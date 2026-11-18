# Log entries and log files

Every log line logprobe reads becomes a `LogEntry`. This page describes its
fields, the logcat text formats `read_file()` and `parse_lines()` accept,
how timestamps and uids are read, and how `export_logs()` writes entries
to a file.

## LogEntry

`LogEntry` is a frozen dataclass. Assigning to a field raises
`dataclasses.FrozenInstanceError`; use `dataclasses.replace()` to make a
changed copy. Entries compare equal field by field and are hashable.

| Field | Type | Meaning |
|---|---|---|
| `logged_at` | `datetime` | When the line was logged. See [Timestamps](#timestamps). |
| `pid` | `int` | Process id; `0` when the format has none. |
| `tid` | `int` | Thread id; `0` when the format has none. |
| `level` | `LogLevel` | `"V"`, `"D"`, `"I"`, `"W"`, `"E"` or `"F"`. |
| `tag` | `str` | The tag without logcat's padding; empty when the format has none. |
| `message` | `str` | The message. Only the separator after the tag is removed; leading whitespace (such as `"\tat ..."`) and trailing spaces stay. |
| `raw` | `str` | The line as read, without its line terminator. |
| `uid` | `int \| None` | The uid from a `-v uid` column. See [uid and uid_raw](#uid-and-uid_raw). |
| `uid_raw` | `str \| None` | The `-v uid` column as printed. |
| `serial` | `str \| None` | The adb serial of the device the line came from; `None` for lines read from a file or given as text. |
| `package` | `str \| None` | The app package the line belongs to. Not implemented yet: `None` in every entry logprobe reads. |
| `parsed` | `bool` | `False` when the line was not recognised. See [Unparsed lines](#unparsed-lines). |
| `truncated` | `bool` | `True` when the line was longer than the line limit. See [Truncated lines](#truncated-lines). |

The constructor does not validate its arguments. Entries made by logprobe
always have the types above; if you build entries yourself, you are
responsible for passing them.

`LogLevel` is a type alias for `Literal["V", "D", "I", "W", "E", "F"]`,
from verbose to fatal. Use it in type hints:

```python
from logprobe import LogEntry, LogLevel


def worst(entries: list[LogEntry]) -> LogLevel:
    return max((e.level for e in entries), key="VDIWEF".index)
```

### Entries from a device

Dumps and streams ask the device for the `threadtime` format with the
`year`, `usec`, `zone` and `uid` modifiers. So an entry from a device has:

- a timezone-aware `logged_at` with microseconds, in the device's UTC
  offset, for every line that parses; an unparsed line (`parsed=False`) has
  the naive host time instead (see [Unparsed lines](#unparsed-lines));
- `uid_raw` filled when the device prints a uid, and `uid` when logprobe
  can read it (see [uid and uid_raw](#uid-and-uid_raw));
- `serial` set to the device's serial.

Lines from a device are cut at 65,536 bytes (see
[Truncated lines](#truncated-lines)).

## Reading logcat text

```python
import io
import logprobe

# A file, read lazily.
for entry in logprobe.read_file("logcat.txt"):
    print(entry.logged_at, entry.level, entry.tag, entry.message)

# Text you already have in memory.
text = "11-18 10:15:02.123  1234  1250 I ActivityManager: Start proc\n"
entries = list(logprobe.parse_lines(io.StringIO(text)))
```

```python
def read_file(
    path, *, format="threadtime", year=None, max_line_bytes=65536
) -> Iterator[LogEntry]: ...
def parse_lines(lines, *, format="threadtime", year=None) -> Iterator[LogEntry]: ...
```

Both return an iterator and parse one line at a time, so a large file is
never held in memory. Each call places yearless dates on its own, from `year`
or its reference moment (see [Yearless dates](#yearless-dates)), so one call
does not affect another.

- `format` is the `adb logcat -v` format of the input; see
  [Formats](#formats). Any other value raises `ValueError`.
- `year` is the year of the first line that has no year, unless a line with
  a printed year comes before it; see [Yearless dates](#yearless-dates). It
  must be an `int` in 1..9999.
- `max_line_bytes` (`read_file` only) is the longest line kept whole, in
  bytes. It must be at least 4096.

Arguments are checked when you call the function, not at the first
`next()`. `read_file` opens the file at the first `next()` (an `OSError`
from opening or reading the file is raised by `next()`, not by the call),
reads it in one pass and closes it when the iterator is exhausted or
closed.

### Formats

| `format` | Line shape | What the entry gets |
|---|---|---|
| `"threadtime"` (default) | `<time> [<uid>] <pid> <tid> <level> <tag>: <message>` | time, `pid`, `tid`, tag, and the uid when present |
| `"brief"` | `<level>/<tag>([<uid>:]<pid>): <message>` | no time, `tid=0` |
| `"process"` | `<level>([<uid>:]<pid>) <message>  (<tag>)` | no time, `tid=0` |
| `"tag"` | `<level>/<tag>: <message>` | no time, `pid=0`, `tid=0` |
| `"raw"` | `<message>` | the line as the message; level `I`, `pid=0`, `tid=0`, empty tag |

Entries of formats without a time get the host time at parsing; see
[Timestamps](#timestamps).

**threadtime** accepts these time columns, each with 3 to 9 fraction digits
(logcat prints 3, 6 with `-v usec` or 9 with `-v nsec`). Digits beyond
microseconds are truncated.

| Time column | logcat option | `logged_at` |
|---|---|---|
| `MM-DD hh:mm:ss.fff` | default | naive, year resolved as described below |
| `YYYY-MM-DD hh:mm:ss.fff` | `-v year` | naive |
| either of the above, then ` +hhmm` | `-v zone` | aware, with that offset |
| `<seconds>.fff` | `-v epoch` | aware, UTC (or the `-v zone` offset if present) |

A `-v uid` column between the time and the pid is read into `uid_raw` and
`uid`. The tag ends at the first `": "` after the level, so a tag may
contain spaces or be empty. `-v printable` and `-v descriptive` change only
the message and parse normally. `-v color` wraps lines in escape codes,
which are not recognised: such lines become unparsed entries.

`-v monotonic` prints seconds since boot in the epoch column. Such a line
parses as that many seconds after 1970-01-01 UTC, which is not the moment
it was logged.

**brief**: the tag ends at the first `(<digits>): ` or `(<uid>:<digits>): `
in the line, because brief output cannot tell a tag's own parentheses from
the pid column. A tag that itself contains `( <digits>): ` is split there.
Tags with other parentheses, such as `Foo(Bar)`, parse as expected.

**process**: when the line ends with `)`, the tag is the text after the
last `  (` (two spaces and a parenthesis) up to that `)`. A line without it
parses with an empty tag.

**brief** and **process** also read lines printed with `-v uid`. A blank
uid column leaves `uid` and `uid_raw` as `None`. **tag** and **raw** never
have a uid.

### How lines are read

- A line ends at LF. CR characters at the end of a line are stripped, so
  CR LF files read like LF files. A CR inside a line stays in its message.
- `read_file` skips a UTF-8 BOM at the start of the file and decodes each
  line as UTF-8; an undecodable byte becomes U+FFFD.
- logcat's buffer dividers (`--------- beginning of main`,
  `--------- switch to crash`) are skipped in every format, `raw` included.
- A line the format does not describe becomes an unparsed entry (see
  below). Empty lines are not skipped: in every format but `raw` they
  become unparsed entries with an empty message.
- At the end of a `read_file` (or when its iterator is closed early), one
  WARNING on the logger `logprobe.read` reports the number of unparsed lines
  and another the number of truncated lines, each only when there were any.
  Many unparsed lines usually mean the wrong `format`.

`parse_lines` takes an iterable of `str`, one item per line. A single `str`
or `bytes` value raises `TypeError` (it would be read one character at a
time). Good inputs are `io.StringIO(text)`, `text.split("\n")`,
`sys.stdin` (except on Windows, where it also splits at a bare CR), or a
file opened with `newline="\n"`. Note that
`text.split("\n")` gives a final empty string, and so an empty unparsed
entry, when the text ends with LF. Do not use `str.splitlines()`: it also
splits at a bare CR, U+2028 and other characters, which cuts one log line
into several entries. For the same reason, a file opened with `open()` and
its default `newline` setting (or `newline=""`) also splits at a bare CR.

## Timestamps

| Source of the line | `logged_at` |
|---|---|
| A device (dump or stream), parsed line | aware, device UTC offset |
| `threadtime` with `-v zone` | aware, the printed offset |
| `threadtime` with `-v epoch` | aware, UTC, or the printed offset with `-v zone` |
| `threadtime` without `-v zone` or `-v epoch` | naive device-local time |
| `brief`, `process`, `tag`, `raw` | naive host-local time when the line was parsed |
| Unparsed lines | naive host-local time when the line was parsed |

logprobe never converts a time to the host's time zone. An aware
`logged_at` has the offset the line printed, or UTC for `-v epoch` without
`-v zone`. Python cannot compare a naive datetime with an aware
one, so do not mix entries from different sources in one sort without
normalising `logged_at` first.

Lines without a timestamp are dated with the host clock when they are
read, so reading the same file twice gives them different timestamps.

### Yearless dates

The default `threadtime` time has no year. logprobe places each such date in
a year:

- **The first yearless line**, when no line with a printed year came before
  it, goes into `year` when you pass it. Without `year`, it gets the latest
  year that puts it no later than two days after a reference
  moment: the file's modification time for `read_file` (the host clock if
  that time cannot be used), and the host clock for `parse_lines`.
- **Every later line** gets the year, out of the previous dated line's year
  and the years just before and after it, that puts it nearest to that
  line. A run that crosses New Year therefore moves into the new year, and
  an older line that follows stays in the old one.
- A line that prints its year (`-v year`) also becomes the reference for
  the yearless lines after it.
- `02-29` is placed in a nearby leap year.
- A date that is invalid in every candidate year (such as `02-30`) does not
  parse; the line becomes an unparsed entry.

```python
lines = [
    "12-31 23:59:59.000  1  1 I T: a",
    "01-01 00:00:01.000  1  1 I T: b",
]
[e.logged_at.year for e in logprobe.parse_lines(lines, year=2025)]
# [2025, 2026]
```

## uid and uid_raw

With `-v uid`, logcat prints each line's uid either as a number or, when the
name has at most 5 characters, as a name. `uid_raw` keeps the column exactly
as printed; `uid` is its number:

| `uid_raw` | `uid` |
|---|---|
| a number, such as `"10123"` | that number; `None` above 2**32 - 1 |
| a short platform name, such as `"root"`, `"radio"`, `"shell"` | its fixed id (0, 1001, 2000) |
| `"u<user>_a<n>"`, such as `"u0_a5"` | `user * 100000 + 10000 + n` (10005) |
| `"u<user>_i<n>"`, such as `"u0_i3"` | `user * 100000 + 90000 + n` (90003) |
| any other name (for example a vendor name) | `None` |
| blank or absent | `None`, and `uid_raw` is `None` too |

Android 7.0 prints only short platform names; app uids appear as numbers.
Android 8.0 and later also print app and isolated-process names.

Known limitation: on Android 8 and 9, an isolated-process uid printed as a
name (`u0_i0` to `u9_i9`) is read 9000 too low, because those releases count
isolated uids from 99000 and later releases from 90000, and a line does not
say which release printed it. `uid_raw` keeps the printed name, so you can
correct it yourself if you know the device's release.

## Unparsed lines

A line the chosen format does not describe is not dropped. It becomes an
entry with:

- `parsed=False`;
- `message` and `raw` set to the whole line (without its terminator);
- `level="I"`, `pid=0`, `tid=0`, an empty `tag`, no uid;
- `logged_at` set to the host time at parsing;
- `serial` set as for any other entry of that source.

[Conditions](conditions.md) see unparsed entries like any other entry, so a
level or tag filter usually removes them. To find them in a file:

```python
bad = [e.raw for e in logprobe.read_file("logcat.txt") if not e.parsed]
```

## Truncated lines

A line longer than the line limit keeps only its first bytes and gives an
entry with `truncated=True`. The rest of that line is discarded, and the
next line is read as usual, so one long line never becomes two entries. When
the cut falls inside a multi-byte character, the text ends before that
character (at most 3 bytes are dropped) rather than with U+FFFD.

The limit is `max_line_bytes` for `read_file` (default 65,536, at least
4096) and 65,536 bytes for dumps and streams. `parse_lines` takes strings
and never truncates.

## Converting entries

### to_dict and to_json

`entry.to_dict()` returns a dict that `json.dumps` accepts:

```python
{
    "schema": "logprobe.entry/1",
    "logged_at": "2026-11-18T10:15:02.123456+09:00",
    "level": "E",
    "tag": "AndroidRuntime",
    "message": "FATAL EXCEPTION: main",
    "pid": 4321,
    "tid": 4321,
    "parsed": True,
    "truncated": False,
    "uid": 10005,
    "uid_raw": "u0_a5",
}
```

- Always present: `schema` (`"logprobe.entry/1"`), `logged_at`, `level`,
  `tag`, `message`, `pid`, `tid`, `parsed` and `truncated`, even when they
  are `0` or `False`.
- The number after the slash in `schema` (here, and in `logprobe.gap/1` and
  `logprobe.summary/1`) changes only when a change breaks readers (a key
  removed or renamed, or a type or meaning changed), also during the alpha.
  Adding keys, or new values of keys such as a gap's `cause` and `reason`,
  does not change it, so readers should ignore keys they do not know and
  accept values they do not know.
- Present only when not `None`: `serial`, `uid`, `uid_raw` and `package`.
- `raw` is left out. For an unparsed line, `message` already holds the
  whole line.
- `logged_at` is `datetime.isoformat()`: with a UTC offset when the
  datetime is aware, without one when it is naive.

`entry.to_json()` returns the same data as one compact JSON string, with
non-ASCII characters written as they are, except these, which are written
as `\uXXXX` escapes (a JSON decoder reads back the same text): the C1
controls U+0080 to U+009F, U+2028, U+2029, and the bidirectional controls
U+061C, U+200E, U+200F, U+202A to U+202E and U+2066 to U+2069.

### json_payload

`entry.json_payload()` returns the first JSON object or array found in the
message, or `None`:

```python
entry.message  # 'upload done {"files": 3, "ok": true}'
entry.json_payload()  # {'files': 3, 'ok': True}
```

The search starts at the first `{` or `[`. After an invalid candidate it goes
on from where decoding failed, so brackets before that point are not tried.
After a candidate nested too deeply it goes on at the next bracket. So the
result can be a value that follows, or is nested inside, a rejected candidate.
The search has fixed limits on the work it does, so a hostile message cannot
make it slow. A message that needs more work gives `None`, never an exception.
Each call searches again; keep the result if you need it more than once.

## export_logs

```python
def export_logs(entries, destination, *, format="jsonl", indent=None) -> int: ...
```

Writes entries to a file and returns how many were written. `entries` may be
any iterable, including a long iterator: it is read while the file is
written. The format comes only from `format`, never from the file name:
`export_logs(entries, "out.csv")` writes JSON Lines.

```python
import logprobe
from logprobe import Level

entries = logprobe.read_file("logcat.txt")
errors = filter(Level >= "E", entries)
count = logprobe.export_logs(errors, "errors.jsonl")
```

| `format` | Output |
|---|---|
| `"jsonl"` (default) | JSON Lines: one compact `to_dict()` object per LF-terminated line. |
| `"json"` | One JSON array of `to_dict()` objects; compact, or indented with `indent=N`. |
| `"csv"` | A header row and one row per entry, CRLF-terminated. |
| `"text"` | Each entry's `raw` line, LF-terminated. |

- All text is UTF-8, with no newline translation on any platform. A lone
  surrogate (possible in strings given to `parse_lines`) is written as an
  escape such as `\ud800`. A JSON decoder reads it back, but in `"csv"` and `"text"`
  it is plain text that cannot be told from a real backslash.
- `"json"` and `"jsonl"` escape the same characters as `to_json()`, so a
  JSON Lines record stays on one line also for readers that treat U+0085,
  U+2028 or U+2029 as line ends. They do not contain `raw`.
- `"csv"` columns are the `LogEntry` fields in order: `logged_at`, `pid`,
  `tid`, `level`, `tag`, `message`, `raw`, `uid`, `uid_raw`, `serial`,
  `package`, `parsed`, `truncated`. `logged_at` is written as in
  `to_dict()`, booleans as `True` and `False`, and `None` as an empty
  cell. A string cell whose first non-whitespace character is `=`, `+`, `-` or
  `@` gets a leading `'`, so a spreadsheet does not run it as a formula.
  CSV is meant for spreadsheets, not for reading back.
- `"text"` writes what `read_file` reads: read the file back with the
  format the lines were in. Dividers are not in it, and truncated lines are
  written as truncated.
- An empty input gives `[]` for `"json"`, an empty file for `"jsonl"` and
  `"text"`, and only the header for `"csv"`.

The write is all or nothing. logprobe writes a temporary file named
`.logprobe-<hex>.tmp` in the destination's directory (for a symlink, the
directory of the file it points to) and then replaces the destination with
it. On an error before the replace, including an exception raised by
`entries` or a keyboard interrupt, the destination is left untouched and
the temporary file is removed when possible. An interrupt that lands right
after the replace is raised with the new file already in place. Further
details:

- If the destination is a symlink, the link stays and the file it points to
  is replaced.
- A replaced file keeps its permission bits where the file system lets
  logprobe set them; a new file gets the default permissions.
- The file is not synced to disk, so a power failure can lose the write.
- A process that is killed outright can leave the temporary file behind.

Errors:

- `ValueError`: unknown `format`, a negative `indent`, or `indent` given
  for a format other than `"json"`. Checked before anything is read or
  created.
- `TypeError`: `indent` is not an `int` (with `format="json"`), or an item
  is not a `LogEntry`.
- `OSError`: the destination is read-only, a directory, a special file or a
  symlink loop; its directory does not exist or cannot be written; or
  Windows refuses the replace because another process has the file open.
