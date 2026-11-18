# Benchmarks

Tooling for developers; it is not part of the installed package and uses only
the standard library. CI runs the benchmark's tests with small inputs; the full
benchmark is run by hand. Run everything from the repository root, inside
the project's environment (`uv run`, as below): `logprobe` is imported from
`src/`.

## Rows

    uv run python -m bench.stream_bench                 # every row
    uv run python -m bench.stream_bench transport feeder delivery memory
    uv run python -m bench.stream_bench burst --repeat 3 --json

| row | measures |
|---|---|
| `transport` | fake server (separate process) -> socket -> `ShellV2Decoder` |
| `feeder` | `Feeder.feed` over bytes in memory, no I/O |
| `delivery` | chunks of 500 entries through `Outbox` to a consumer thread |
| `memory` | memory per entry (tracemalloc) and resident memory of a full queue |
| `throughput` | `for entry in Device.stream()` over a 200,000-line backlog |
| `burst` | 10,000 and 50,000 lines at the default settings, the expected entry count checked |
| `slow-burst` | the same with a consumer spending 20 us per entry |
| `async-throughput` | `async for` over `Device.astream()` with a 200,000-line backlog, the entry count checked |
| `async-lag` | a task that wakes every millisecond records how late it ran during a 50,000-line burst of 60-byte lines (`--burst-lines`, the last value); the gate is a maximum of 10 ms and a p99 of 5 ms |
| `multi` | two fake devices in one `logprobe.stream`; once the expected total has arrived, the number of entries per serial must equal each device's backlog (correctness only, the rate is recorded, no speed gate). As in the other stream rows, a run ends when the expected number of entries has arrived, so entries after it are not read |
| `async-multi` | the same with `logprobe.astream` and `async for` (correctness only, the rate is recorded, no speed gate) |

Options: `--lines`, `--burst-lines`, `--slow-us`, `--repeat` (default 5; each
timed row prints the median and the range, the `memory` row measures once),
`--packing` (`line`, or `bytes:N`) and `--json` (one object per run).

## The fake adb server

`bench/fake_adb.py` is a small adb server that runs in its own process, so its
work does not share the interpreter lock of the client. It answers the requests
logprobe's client makes (`host:version`, `host:devices-l`, features,
`host:transport:`, `shell,v2,raw:`) and sends the lines of `bench/corpus.py` as
shell protocol v2 packets, then an exit packet (or, with `--hold`, nothing: the
connection stays open, as a live device's does; the stream rows use that). Start it by hand with
`uv run python -m bench.fake_adb --kind live --lines 200000`; it prints its port as JSON.

`bench/corpus.py` builds the lines, deterministically: the recorded live-format
lines of `tests/fixtures/device` (`live`), `dense` lines of 60 bytes,
`multibyte` lines and short `broken` lines.

## Results

`bench/BASELINE.md` holds the recorded results.
