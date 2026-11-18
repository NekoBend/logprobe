# Device recordings

These files are recordings from Android emulators: API 24 (Android 7.0) and
API 36, both `google_apis` images on x86_64. Each file holds the commands that
were run (`argv`; most on the device, a few on the emulator host), the output
they produced (`stdout`, `stderr`), and the facts derived from that output.

The recorded data is kept verbatim. This includes the marker strings that
were written into the device log during recording, so that those lines could
be found again: the messages `lp-mark-...` and `lp-tags-...` (tag
`logprobe`); `lp-lw-...`, `lp-burst-...`, `lp-st-...` and `lp-ch-...`
(written through `logwrapper`, so with the tags `echo` and `sh`); and the
class name `com.example.logprobe.NoSuchFragment` in the commands of the crash
recording.
Do not rename them; they are part of what the device printed.

The tests use the files as ground truth for the real logcat output formats.
`tests/device_facts.py` loads them (one directory per API level,
`<KEY>_<slug>.json`, looked up by the key before the first underscore), and
`tests/test_parser_recordings.py` checks that the parsers read the recorded
lines as the facts say.
