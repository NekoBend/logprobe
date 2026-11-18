# Stream benchmark: baseline

Recorded on 2026-11-18 with `uv run python -m bench.stream_bench` (every row),
on the library code of this tree. Each timed row ran five times; the tables
show the median of the five runs and, in brackets, the minimum and maximum. The
memory figures are single measurements.

## Machine

- Linux x86_64 in a container, CPython 3.14.4, 13th Gen Intel Core i9-13900HX,
  32 logical CPUs.
- Other work ran on the same machine, so the numbers are indicative. Compare
  runs made on the same machine close together in time; the min..max spread
  shows how much a single run varies.

## How it was run

    uv run python -m bench.stream_bench
    uv run python -m bench.stream_bench async-lag --packing bytes:16000
    uv run python -m bench.stream_bench async-lag --packing bytes:60000

[README.md](README.md) describes the rows and the options.

## Setup of the stream rows

| | |
|---|---|
| transport | fake adb server in its own process, loopback TCP, shell protocol v2 packets, one line per packet |
| line format | live format (`-v threadtime -v year -v usec -v zone -v uid`) |
| corpus | 200,000 lines cycled from the 1,194 live-format lines recorded on API 24 and 36 emulators (856 distinct, 136 bytes on average with the line feed, 27 MB) |
| consumer | `for entry in stream` on the calling thread (`async for` in the async rows) |
| settings | the defaults: a buffer of 10,000 lines or 4 MiB, back-pressure, no drops |
| backlog end | the fake server keeps the connection open after the backlog (`--hold`, no exit packet); a row stops once the expected number of entries has arrived, or after 2 s without an entry |

## Results: components

| row | variant | delivered/expected | lines/s (median; min..max) |
|---|---|---:|---:|
| transport | live | 200,000/200,000 | 2,244,115 (2,201,969..2,281,251) |
| feeder | 64 KiB reads | 200,000/200,000 | 359,177 (343,977..367,696) |
| feeder | one line per read | 200,000/200,000 | 222,182 (220,086..224,662) |
| delivery | 500-entry chunks | 1,000,000/1,000,000 | 11,315,865 (11,132,709..11,425,516) |

- transport (the recorded live-format corpus, 200,000 lines, one line per
  packet): server process, socket and `ShellV2Decoder` only (28.1 MB of shell
  protocol v2 data per run, 200,001 packets). About 0.45 us per line.
- feeder: `Feeder.feed` alone, bytes already in memory, no I/O, parsing and
  entry construction included. About 2.8 us per line with 64 KiB reads, so a
  stream that parses on one thread cannot pass about 359,000 lines/s here. With
  one line per call, which is how a reader that passes on each packet as it
  arrives feeds it, the cost is 4.5 us per line.
- delivery: 0.088 us per line (0.088..0.090). The consumer thread iterates the
  chunks the way a blocking `for` over a stream does: for every entry it reads
  the queue's kill flag and checks the type of the element. A consumer that does
  work per entry sits on top of this figure. The producer and the consumer share
  one interpreter lock, as they do in a stream.

## Results: memory

tracemalloc, 20,000 lines of each kind parsed by `Feeder` and kept; the figures
are bytes still allocated per entry after the parse, without the list that holds
the entries. RSS growth is the growth of a fresh process after filling
`Outbox(10_000, 4 MiB)` (the defaults of `Device.stream()`) to its limit, with
the feeder still alive (it keeps a history of up to 2 MiB / 20,000 lines).

| lines | input per line | memory per entry | per input byte | queue when full (lines / charged input) | RSS growth |
|---|---:|---:|---:|---:|---:|
| recorded live corpus | 135.4 B | 634 B | 4.7 | 10,482 / 1.38 MiB | 8.8 MiB |
| dense, 60 bytes | 60.0 B | 429 B | 7.2 | 10,922 / 0.63 MiB | 7.2 MiB |
| multi-byte-heavy (Japanese, an emoji in every fourth line) | 200.5 B | 879 B | 4.4 | 10,133 / 1.94 MiB | 11.7 MiB |
| short broken lines (2 to 11 bytes with the line feed) | 4.2 B | 213 B | 51.2 | 10,240 / 0.04 MiB | 4.7 MiB |

- The fixed size of one `LogEntry` beyond what grows with its input is about
  339 bytes. It is the intercept of a straight line fitted through the memory
  of an entry against the input size, for ASCII live-format lines with messages
  of 0, 100, 400, 1,600 and 6,400 bytes; its slope is 2.0 bytes per input byte
  (the `raw` string and the `message` string each hold a copy).
- Non-ASCII text costs more per character than ASCII (two bytes per character
  when all characters are in the Basic Multilingual Plane, four when the line
  holds an emoji), but Japanese text has three input bytes per character, so the
  cost per input byte stays near the corpus's. Short broken lines are the worst
  case: an entry of 213 bytes for 4 bytes of input.
- At the defaults the line limit (10,000), not the byte limit (4 MiB), ends
  every one of these fills. The byte limit would hold back lines longer than
  about 420 bytes on average.
- Every figure in this table, traced or RSS, is a single measurement.

## Results: streams

| row | what | gate | lines/s (median; min..max) | result |
|---|---|---|---:|---|
| throughput | `for` over `Device.stream()`, 200,000-line backlog | expected entry count | 257,372 (256,646..278,697) | 200,000/200,000 in every run |
| burst, 10,000 lines | default settings | expected entry count | 251,715 (246,408..263,790) | 10,000/10,000 in every run |
| burst, 50,000 lines | default settings | expected entry count | 256,970 (254,219..261,604) | 50,000/50,000 in every run |
| slow-burst, 10,000 lines | the consumer spends 20 us per entry | expected entry count | 40,918 (40,638..41,356) | 10,000/10,000 in every run |
| slow-burst, 50,000 lines | the same | expected entry count | 40,988 (40,865..41,037) | 50,000/50,000 in every run |
| async-throughput | `async for` over `Device.astream()`, 200,000-line backlog | expected entry count | 218,446 (215,255..219,213) | 200,000/200,000 in every run |
| async-lag | 50,000 lines of 60 bytes (`dense`), a task that wakes every millisecond | expected entry count; lag of at most 10 ms, p99 of at most 5 ms | 249,716 (246,370..254,424) | 50,000/50,000 in every run; maximum lag 4.39 ms (2.97..4.53), p99 4.63 ms (3.09..4.82): passes |

- Runs vary a lot on this machine. Further runs of the two throughput rows
  on the same day, with the same library code, gave medians from 257,372 to
  286,834 lines/s (throughput) and from 218,446 to 248,892 lines/s
  (async-throughput).
- A lossless slow-burst run is bounded by its consumer: at 20 us per entry no
  stream can pass 50,000 lines/s, and these rows reach about 82 % of that.
- The entry-count gates check that the expected number of entries arrived,
  not the identity of each line. The results above are what the driver
  reported; a failed gate does not change its exit status.
- The lag is how late a task that sleeps 1 ms at a time woke up: the event
  loop's time at the wake-up minus the time it was due. It includes everything
  that ran on the loop in between. The maximum is the largest value of a run.
  The p99 is `statistics.quantiles(lags, n=100)[98]`, whose default exclusive
  method can give a value above the largest observed one (as in the row above).
  The driver prints these figures; the lag gate is read from them and does not
  change its exit status.
- The asyncio stream stops taking output for a step once it holds 8 KiB,
  yields after every read, and the iteration yields once per chunk it takes
  from the queue.
- The lag during a reconnect is not measured. The fake adb server sends the
  whole corpus on every connection and cannot cut one in the middle of a burst,
  so a reconnect would measure a replay, not a reconnect.

## Results: several devices

Two fake devices (`bench-0001` with 100,000 lines, `bench-0002` with 50,000)
are read in one stream (`logprobe.stream` and `logprobe.astream`). The gate is
correctness only: once the expected total has arrived, the count of entries
per serial must equal that device's backlog. The backlogs differ, so a
systematic mix-up (one device's entries given the other's serial, or every
entry given one serial) changes the counts; a balanced swap, as many entries
each way, would not. As in the other stream rows, a run ends when the expected
number of entries has arrived, so entries after it (a duplicate, for example)
are not read. There is no speed gate; the rate is recorded.

| row | lines | lines/s (median; min..max) | result |
|---|---:|---:|---|
| multi | 100,000 + 50,000 | 250,163 (235,126..262,275) | 150,000/150,000 in every run |
| async-multi | 100,000 + 50,000 | 196,856 (194,491..205,719) | 150,000/150,000 in every run |

## Packing

The server sends one line per shell protocol packet by default (`--packing
line`): the benchmark assumes that a device sends about one line per packet.
`--packing bytes:N` packs whole lines into a packet until it holds at least N
bytes (N up to 60,000; the last packet can be shorter). Every row above that
reads from the fake server (transport and the stream rows) uses one line per
packet; the two runs below do not.

The part of one packet that one network read brings (up to 64 KiB) is fed in one
step, so the 8 KiB step limit keeps steps small only when packets are small. It
does not set a time bound on the lag. The lag measured with one line per packet
is in the async-lag row above; with larger packets it was:

| packing | lines/s (median; min..max) | maximum lag (median; min..max) | p99 lag (median; min..max) | gate |
|---|---:|---:|---:|---|
| `bytes:16000` | 328,177 (312,168..337,742) | 3.89 ms (2.74..4.55) | 4.22 ms (2.77..5.54) | passes on the median; at least one run's p99 was above 5 ms |
| `bytes:60000` | 324,075 (320,059..356,423) | 8.81 ms (8.19..9.68) | 9.10 ms (8.60..10.54) | the p99 gate of 5 ms fails |

## Reading the numbers

- The server builds every byte before it listens and sends in large slices, so
  its cost to the client is the kernel's copy. The transport row shows that the
  socket and the packet decoder are not what limits a stream (2.2 million
  lines/s against a feeder at 359,000).
- Time of the stream rows runs from `start()` (entering the `with`) to the last
  entry received; the fake server's start-up is excluded.
- Every row takes well under a minute.
