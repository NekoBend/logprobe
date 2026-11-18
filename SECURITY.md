# Security policy

## Reporting a vulnerability

Report a vulnerability privately through GitHub: on this repository's
**Security** tab, choose **Report a vulnerability**. Please do not open a
public issue for it.

## Supported versions

logprobe is an alpha. Fixes go into `main` and the latest alpha release only.

## What counts as a vulnerability

Examples of what to report:

- logprobe sends a command to a device that the caller did not ask for, or
  lets text from a log line, a device or a caller reach a device command.
- logprobe connects to anything other than the adb server it was given (or
  the default one), or resolves a host name for it.
- logprobe runs a program on the computer other than the `adb` executable it
  found or was given (it runs `adb start-server` only).
- logprobe overwrites or deletes a file on the computer other than the
  destination the caller passed to `export_logs`.
- A crafted log line, log file or adb server reply makes logprobe hang, use
  unbounded memory, or run code.

A crash or wrong output without such an effect is an ordinary bug: please
report it as an issue.

There is no promised response time.
