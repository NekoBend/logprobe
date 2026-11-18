# Security policy

## Reporting a vulnerability

Report a vulnerability privately through GitHub: on this repository's
**Security** tab, choose **Report a vulnerability**. Please do not open a
public issue for it.

## Supported versions

logprobe is an alpha with no release yet. Fixes go into `main`. Once an alpha
release exists, the latest one is supported too.

## What counts as a vulnerability

Examples of what to report:

- logprobe sends a device command of its own that the documentation does not
  list, or text from a log line, a device or an adb server reply changes the
  program or the arguments of a device command in a way they are not meant to
  change. Intended: `Device.shell()` runs the command the caller gives it,
  with each argument quoted, and logcat's `-T` time comes from the device's
  clock or from the last line read, after it is checked.
- logprobe connects to anything other than the adb server it was given (or
  the default one), or resolves a host name for it.
- logprobe starts a local process other than the executable selected as
  `adb`, or starts that executable with anything but `start-server`.
- `export_logs` writes or deletes a file other than its resolved destination
  and the temporary file it creates next to it.
- A crafted log line, log file or adb server reply makes logprobe hang, use
  memory far beyond what the operation needs, or run code.

A crash or wrong output with a plausible security impact also belongs here.
Other crashes and wrong output are ordinary bugs: please report them as
issues.

There is no promised response time.
