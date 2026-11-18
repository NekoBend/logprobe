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

### Package (not implemented yet)

`Package(*names)` is meant to match entries that belong to one of the
given app packages, by comparing `entry.package`. It is not usable yet:

- Entries that logprobe reads always have `LogEntry.package` set to `None`
  for now, so `Package(...)` called on them never matches. It does test the
  field of an entry you build yourself.
- `Device.dump()`, `Device.adump()`, `stream()` and `astream()` (and the
  `Device.stream()` / `Device.astream()` methods) raise
  `NotImplementedError` when the condition contains a `Package` term
  anywhere, or when you pass the `package=` shortcut.

You can construct it. Each name must be a plain package name
(dot-separated segments of ASCII letters, digits and `_`, each starting with
a letter); a process name such as `com.example.app:remote` raises
`ValueError`.

To select an app's crashes and ANRs today, use `Crash(package=...)` and
`Anr(package=...)`, which read the message text and do not need
`entry.package`.

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
| `package=...` | `Package(...)` | not implemented yet: raises `NotImplementedError` |

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
