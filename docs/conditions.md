# Filtering with conditions

A condition is a small, immutable test over a `LogEntry`. You build it from
components such as `Level` and `Tag`, combine components with `&`, `|` and
`~`, and pass the result to a dump or a stream. Only the entries that match
are returned or delivered.

```python
import logprobe
from logprobe import Level, Tag, Message

important = (Level >= "W") & Tag("ActivityManager", "WindowManager")

device = logprobe.Device()
for entry in device.dump(important):
    print(entry.level, entry.tag, entry.message)
```

A condition is also a plain callable: `condition(entry)` returns `True` or
`False`. Use that to filter entries you read from a file:

```python
crashes = logprobe.Crash()
for entry in filter(crashes, logprobe.read_file("logcat.txt")):
    print(entry.logged_at, entry.message)
```

## Where conditions are accepted

These take a condition as their `where` argument, and the keyword
shortcuts described [below](#keyword-shortcuts). `where` is the first
argument of the `Device` methods, and the second, after the devices, of
`logprobe.stream()` and `logprobe.astream()`:

- `Device.dump()` and `Device.adump()`
- `logprobe.stream()` and `Device.stream()`
- `logprobe.astream()` and `Device.astream()`

`read_file()` and `parse_lines()` do not filter. Filter their output with
the condition itself, as in the example above.

A condition sees every entry, including entries for lines that did not
parse (`parsed=False`). Such an entry has level `I`, an empty tag and pid 0,
so `Level >= "W"` or a `Tag(...)` test without an empty name removes it. See
[entries.md](entries.md#unparsed-lines).

## Combining conditions

| Expression | Class | Matches when |
|---|---|---|
| `a & b` | `And(a, b)` | every operand matches |
| `a \| b` | `Or(a, b)` | at least one operand matches |
| `~a` | `Not(a)` | the operand does not match |

```python
from logprobe import And, Or, Not, Level, Tag, Pid

noisy = Tag("chatty", "SurfaceFlinger")
cond = (Level >= "I") & ~noisy & (Pid(1234) | Tag("MyApp"))

# The same condition with the classes:
cond = And(Level >= "I", Not(noisy), Or(Pid(1234), Tag("MyApp")))
```

Rules you can rely on:

- Operands are evaluated in written order, and evaluation stops at the first
  decisive one: `And` stops at the first operand that does not match, `Or`
  at the first that matches. Put cheap, selective tests first.
- `And` and `Or` flatten operands of their own kind:
  `And(And(a, b), c)` holds `a, b, c`. The flattened operands are available
  as the `conditions` property; `Not` exposes its operand as `condition`.
- `And()` and `Or()` need at least one operand (`ValueError`). Every operand
  must be a condition; a function or lambda is refused with `TypeError`.
- A condition has no truth value. `a and b`, `a or b`, `not a` and
  `if a:` raise `TypeError`. Use `&`, `|` and `~`.
- `And`, `Or` and `Not` may nest at most 32 levels deep. When you build a
  condition in Python, an `And` directly inside an `And`, or an `Or` inside
  an `Or`, is flattened and does not count; a `Not` inside a `Not` does. A
  deeper condition raises `ValueError`. Long flat chains are fine. For the
  JSON form, see [JSON form](#json-form).
- `a & b` copies the operands of `a`, so building a long chain one operator
  at a time takes quadratic time. For many terms, write `And(*terms)` or
  `Or(*terms)`, and use `Tag(*names)` instead of many `Tag` terms.

## Components

### Level

`Level` is compared with a level letter: `V`, `D`, `I`, `W`, `E` or `F`.
The order is `V < D < I < W < E < F`.

| Condition | Matches |
|---|---|
| `Level >= "W"` | W, E and F |
| `Level > "W"` | E and F |
| `Level <= "D"` | V and D |
| `Level < "D"` | V |
| `Level == "E"` | E only |
| `Level != "V"` | everything but V |

The level must be one upper-case letter from that list; anything else
raises `ValueError` (or `TypeError` when it is not a string). A comparison
that no level can satisfy, such as `Level < "V"`, is valid and never
matches.

`Level == "E"` returns a condition, not a bool, so do not use it in an `if`.

### Tag

`Tag(*names)` matches when the entry's tag is exactly one of the names.
The comparison is case-sensitive and whole-string. At least one name is
required, and every name must be a `str`.

```python
Tag("ActivityManager")
Tag("ActivityManager", "WindowManager", "PackageManager")
```

The tag is compared without logcat's padding. Formats without a tag
(`raw`) and unparsed lines have an empty tag, which matches `Tag("")`.

### Message

`Message.contains(text)` matches when `text` occurs anywhere in the message.
The test is case-sensitive.

`Message.matches(pattern)` matches when the regular expression `pattern`
is found anywhere in the message (`re.search`, not anchored). The pattern is
compiled once, when the condition is made; an invalid pattern raises
`ValueError`. Use inline flags for options:

```python
from logprobe import Message

Message.contains("Displayed ")
Message.matches(r"(?i)timeout after \d+ ms")
Message.matches(r"^Start proc")  # anchor explicitly when you need to
```

### Pid, Tid, Uid

`Pid(*pids)`, `Tid(*tids)` and `Uid(*uids)` match when the entry's `pid`,
`tid` or `uid` is one of the given integers. At least one value is
required; each must be an `int` (a `bool` is refused) with a magnitude below
2**63.

Formats without a process or thread id give `0` for that field, so `Pid(0)`
and `Tid(0)` match those entries. `uid` is `None` unless the line has a
`-v uid` column with a value logprobe can read; an entry without a uid never
matches `Uid(...)`. On Android 8 and 9, a uid printed as an isolated-process
name is read 9000 too low; see [entries.md](entries.md#uid-and-uid_raw).

### Crash

`Crash()` and `Crash(package=...)` match the lines Android logs when an app
crashes. They read only the tag, level and message, so they work the same on
live streams, dumps and files.

Without `package`, `Crash()` matches the Java crash line: tag
`AndroidRuntime`, level `E`, and a message that contains `FATAL EXCEPTION`
(normally `FATAL EXCEPTION: <thread>`). It does not match native crashes.

With `package`, `Crash(package=name)` matches the line that names the
crashed process:

- a Java crash: tag `AndroidRuntime`, level `E`, message starting with
  `Process: <name>, PID: <pid>`;
- a native crash: tag `DEBUG`, level `F`, message starting with
  `pid: <pid>, tid: <tid>, name: <thread>  >>> <name> <<<`.

`<name>` matches when it equals `package` or starts with `package + ":"`
(a secondary process of the app). So `com.example.app` matches
`com.example.app` and `com.example.app:remote`, but not
`com.example.application`. `package` may itself be a process name such as
`com.example.app:remote`; it then also matches processes whose names
continue it after a `:`.

```python
from logprobe import Crash

Crash()  # any app, Java crashes
Crash(package="com.example.app")  # Java and native crashes of one app
Crash(package="com.example.app:remote")  # one process of that app
```

Note that `Crash()` and `Crash(package=...)` match different lines of the
same Java crash: the first matches the `FATAL EXCEPTION` line, the second the
`Process:` line that follows it.

`package` must be a package name (dot-separated segments of ASCII letters,
digits and `_`, each starting with a letter), optionally followed by
`:`-separated process parts made of ASCII letters, digits, `_`, `.` and `$`.
Anything else raises `ValueError`; a value that is not a `str` or `None`
raises `TypeError`.

### Anr

`Anr()` matches the line Android logs when an app does not respond: tag
`ActivityManager`, level `E`, and a message that starts with `ANR in`.

`Anr(package=name)` additionally reads the process name after the prefix
(`ANR in <name> (<component>)`). The name ends at a space, a `(` or the end
of the message, and it matches by the same rule as for `Crash`: equal to
`package`, or starting with `package + ":"`. `package` accepts the same
values as for `Crash`.

```python
from logprobe import Anr

Anr()
Anr(package="com.example.app")
```

The system server logs this line, not the app. Use `Anr(package=app)` to
find an app's ANRs; an app-based test such as `Package(app) & Anr()` would
not find them.

### Package

`Package(*names)` matches an entry whose `package` is one of the given app
packages. An entry without a package (`None`) never matches. Each name must
be a plain package name (dot-separated segments of ASCII letters, digits and
`_`, each starting with a letter); a process name such as
`com.example.app:remote` raises `ValueError`.

```python
from logprobe import Package

device.dump(Package("com.example.app"), level="W")
device.dump(package=["com.example.app", "com.example.helper"])
```

`Device.dump()`, `Device.adump()`, `stream()` and `astream()` (and the
`Device.stream()` / `Device.astream()` methods) accept a `Package` term
anywhere in the condition, and the `package=` shortcut. They find the app of
each line from its uid and set `entry.package` on the entries they deliver.
Only the names of `Package` terms are watched. Entries from `read_file()` and
`parse_lines()` have no package, so `Package(...)` never matches them.

How the app of a line is found:

- At the start, the dump or stream reads one list of every installed package
  with its uid per device: `pm list packages -U`, or
  `dumpsys package packages` when `pm` prints that it does not know `-U` (as
  on Android 7) or prints no usable list. A stream remembers a device that
  does not know `-U` and runs `dumpsys` directly for its later lists.
- A dump judges every line by that one list, read before `logcat -d`: a line
  whose uid the list does not name belongs to no watched package.
- A stream with `since=None` reads the device clock once (`date +%s`) just
  before the first list. A line logged before that clock whose uid the list
  does not name belongs to an app that was removed before the list.
- A stream takes the list again every 30 seconds in the background, to notice
  a reinstall, and goes on reading meanwhile: the lines read while it runs
  are judged with the previous list, and the new one applies from the next
  network read on, or from a read that waits for it.
- A line needs a list when its verdict depends on its app (below), its app
  id is from 10000 to 19999, the latest list does not name that app id, the
  line was logged at or after that clock (or there is no clock), and the app
  id is not the old uid of a watched app (see the counted lines below). A read
  with such a line makes the stream take a new list before it delivers the
  read (when the 30-second list runs, the read waits for it first); while the
  device has no usable list, a read starts no list. Reading that device
  pauses for at most 2 seconds, counted from when the read's bytes arrived.
  Two lists start at least 0.5 seconds apart, and a read starts a list only
  when at least 1 second of its 2 seconds is left. An app id that a list taken
  after its read did not name either needs no list until a list names it.
- Packages that share a uid match each other's lines; `entry.package` is
  then the first watched package by name.
- A watched package that runs under a system uid (below 10000) matches every
  process of that uid, and a WARNING says so.
- The app id is the uid modulo 100000, so the lines of other users of the
  device (secondary users) are matched by app id.
- A line without a uid belongs to no watched package.

A line's verdict depends on its app when a term without packages does not
settle it: under `Package(a) | Tag("x")`, a line tagged `x` is delivered
whatever its app, and it never needs a list.

A stream counts in its device summary's `unattributed` the lines whose app
it could not check, which makes the summary incomplete (`complete` is
`False`). A dump has no summary and counts nothing. The stream counts:

- a line that needs a list, when the device has no usable list (the last
  list failed; the next one comes 30 seconds later), or when the list for its
  read did not come within the 2 seconds. Such a line is judged as if no
  package owned it.
- a line whose verdict depends on its app, when the list taken for its read
  does not name its app id either and it was logged at or after the clock read
  before the first list (any such line with `since="now"` or when that clock
  could not be read): a watched app may have been installed and removed while
  the stream was behind the device, and no list could check it. This
  over-counts. The lines of an app that is not watched, installed and removed
  meanwhile, count too, and so do the lines of an app id that no list ever
  names (perhaps an app installed only for another user) for as long as the
  stream runs.
- the lines judged with a list that a newer list shows was outdated: when a
  watched app got a new uid (a reinstall) or was removed, the lines of its old
  uid since the previous list; when a watched app turns up under a uid whose
  lines were judged as not its own (a uid freed and given again, an app that
  appeared after its lines, or one that joined a shared uid), those lines.
  Here every line of that uid counts, whether or not the condition had to ask
  about its package, and a WARNING with the count comes with the newer list.
- after a list shows that a watched app got a new uid or was removed, every
  line of the old uid (a system uid too, whatever else the condition asks),
  until a successful list that started 30 seconds or more after that one, or
  one that shows a watched app under that uid: they may be late lines of the
  app.

In the first two cases only lines whose verdict depends on their app are
counted: a line that a term without packages excludes (`Tag("other")` under
`Package(A) & Tag("keep")`) would not be delivered whether or not it is A's.
No line is counted twice. The summary, the messages and the extra device
commands are described in
[streams.md](streams.md#filter-by-app-extra-commands-and-messages).

Not promised:

- Telling apart packages that share a uid.
- Attributing the lines of an app's isolated processes (app ids 90000 to
  99999, for example a WebView renderer) to the app.
- Attributing an app installed only for a secondary user: how such an app is
  listed is not verified.
- Lines of a removed app in the backlog belong to no watched package. A step
  back of the device clock can make lines of a newly installed app look older
  than the clock read before the first list; they are then judged as belonging
  to no watched package, and counted only if the next list shows a watched
  package under their uid.
- A watched app that no list ever names (installed after one list and removed
  before the list taken for a read of its lines) is not attributed: its lines
  are judged as if no package owned them, and counted as above unless they
  look older than that clock.
- A dump judges by the list read just before it.
- A stream does not read a device while it takes the list at the start (at
  most 5 seconds) or for a read. An older logd may skip lines then, and
  `detect_skips` does not see it.
- The asyncio stream judges a network read in parts of about 8 KiB; the
  blocking stream judges the whole network read (in parts above 2,048 lines).
  When a later part of a network read waits for a list, the asyncio stream
  has judged the earlier parts with the previous list, where the blocking
  stream judges the whole read with the new one. The two may then deliver
  different lines and count different lines as unattributed; each counts
  every line it judged with a list that the newer one shows was outdated.

`Crash(package=...)` and `Anr(package=...)` read the message text, not the
uid, and do not need a package list.

## Keyword shortcuts

The functions that accept `where` also accept these keywords. Each one adds
a term, and all terms and `where` are combined with AND.

| Keyword | Same as | Accepts |
|---|---|---|
| `level="W"` | `Level >= "W"` | one level letter |
| `tag="A"` | `Tag("A")` | a `str` |
| `tag=["A", "B"]` | `Tag("A", "B")` | a list or tuple of `str` |
| `pid=123` | `Pid(123)` | an `int` |
| `pid=[1, 2]` | `Pid(1, 2)` | a list or tuple of `int` |
| `message="text"` | `Message.contains("text")` | one `str` |
| `package="a.b"` | `Package("a.b")` | a `str` |
| `package=["a.b", "c.d"]` | `Package("a.b", "c.d")` | a list or tuple of `str` |

```python
# These two calls select the same entries.
device.dump(Message.contains("Displayed"), level="I", tag="ActivityManager")
device.dump((Level >= "I") & Tag("ActivityManager") & Message.contains("Displayed"))
```

The shortcut terms come first and `where` last. Conditions have no side
effects, so the order affects only speed.

Invalid values raise when the function is called (for `Device.adump()`,
when it is awaited), before any I/O:
`TypeError` for a wrong type (for example a function as `where`, or a
`bool` as a pid) and `ValueError` for a bad value (an unknown level, an
empty list).

## Other things a condition can do

- **Equality and hashing.** Conditions compare by value and are hashable.
  The order of values inside `Tag`, `Pid`, `Tid`, `Uid` and `Package` does
  not matter: `Tag("a", "b") == Tag("b", "a")`. Duplicates are dropped.
- **Readable repr.** `repr((Level >= "W") & Tag("A"))` is
  `((Level >= 'W') & Tag('A'))`.
- **Copying and pickling.** Copies return the same object; conditions can be
  pickled.
- **`compile()`** returns a plain function `entry -> bool`. It is built once
  and cached; calling the condition uses it too.
- **`fields()`** returns the names of the `LogEntry` fields the condition
  reads, for example `frozenset({"level", "tag"})`.
- **`packages()`** returns the package names the condition depends on: those
  of `Package`, and of `Crash` and `Anr` with a `package` (the part before
  the first `:`).

### JSON form

`condition.to_json()` returns a JSON-compatible dict, and
`Condition.from_json(obj)` builds a condition from one. Use it to store
filters in configuration files.

```python
from logprobe import Condition

cond = Condition.from_json(
    {
        "all": [
            {"level": "W"},
            {"tag": ["ActivityManager", "WindowManager"]},
            {"not": {"message_matches": "(?i)debug"}},
        ]
    }
)
```

Every object has exactly one key:

| Key | Value | Condition |
|---|---|---|
| `all` | non-empty list of objects | `And` |
| `any` | non-empty list of objects | `Or` |
| `not` | one object | `Not` |
| `level` | level letter | `Level >= ...` |
| `level_gt`, `level_le`, `level_lt`, `level_eq`, `level_ne` | level letter | `Level >`, `<=`, `<`, `==`, `!=` |
| `tag`, `package` | non-empty list of strings | `Tag(...)`, `Package(...)` |
| `pid`, `tid`, `uid` | non-empty list of integers | `Pid(...)`, `Tid(...)`, `Uid(...)` |
| `message` | string | `Message.contains(...)` |
| `message_matches` | string | `Message.matches(...)` |
| `crash`, `anr` | object, with an optional `package` key | `Crash(...)`, `Anr(...)` |

Note that `tag` and the other member keys always take a list, even for one
value. A malformed object raises `ValueError`; the message names the path of
the bad element, such as `$.all[0].tag`. `all`, `any` and `not` may nest at
most 32 levels deep, and here every level counts, also an `all` directly
inside an `all`.
