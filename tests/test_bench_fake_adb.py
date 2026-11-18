"""Tests for the benchmark's fake adb server and the pieces around it."""

from __future__ import annotations

import json
import struct
import time
from types import SimpleNamespace

import pytest

import logprobe
from bench import stream_bench
from bench.corpus import build_lines
from bench.fake_adb import FakeAdbProcess, pack_packets, parse_packing
from logprobe import _adb

SERIAL = "bench-0001"


def decode(stream: bytes) -> tuple[list[bytes], int | None]:
    """The stdout payloads (one per packet) and the exit status of a byte stream."""
    decoder = _adb.ShellV2Decoder()
    pieces, status, error = decoder.feed_pieces(stream)
    assert error is None
    return [bytes(piece) for _kind, piece, _ends in pieces], status


def test_one_line_per_packet_by_default():
    lines = build_lines("live", 50)
    stream, packets = pack_packets(lines)
    payloads, status = decode(stream)
    assert payloads == lines
    assert status == 0
    assert packets == 51  # the exit packet counts
    assert stream.endswith(struct.pack("<BI", 3, 1) + b"\x00")


def test_byte_packing_keeps_whole_lines_and_reaches_the_size():
    lines = build_lines("live", 400)
    stream, packets = pack_packets(lines, "bytes:4096")
    payloads, status = decode(stream)
    assert status == 0
    assert b"".join(payloads) == b"".join(lines)
    assert packets == len(payloads) + 1
    assert all(len(p) >= 4096 for p in payloads[:-1])
    assert all(len(p) < 4096 + 400 for p in payloads)
    assert all(p.endswith(b"\n") for p in payloads)


def test_empty_backlog_is_just_the_exit_packet():
    stream, packets = pack_packets([])
    assert decode(stream) == ([], 0)
    assert packets == 1


@pytest.mark.parametrize(
    "text", ["lines", "bytes", "bytes:0", "bytes:x", "bytes:60001"]
)
def test_bad_packing_is_refused(text):
    with pytest.raises(ValueError, match="packing"):
        parse_packing(text)


@pytest.fixture(scope="module")
def server():
    with FakeAdbProcess("live", 300, "bytes:1024", SERIAL) as srv:
        yield srv


def test_the_client_lists_the_device_and_reads_the_backlog(server):
    device = logprobe.Device(SERIAL, adb_server=server.address)
    assert device.serial == SERIAL
    assert "shell_v2" in device.features()
    address = _adb.resolve_server_address(server.address)
    with _adb.open_shell(
        address, SERIAL, _adb.logcat_argv(dump=False, tail=None, t=None), timeout=5
    ) as shell:
        data = b""
        while (event := shell.read()) is not None:
            assert event[0] == "stdout"
            data += event[1]
    assert data == b"".join(build_lines("live", 300))
    assert shell.exit_status == 0


def test_other_shell_commands_get_an_empty_success(server):
    device = logprobe.Device(SERIAL, adb_server=server.address)
    result = device.shell(["getprop", "ro.build.version.sdk"])
    assert (result.exit_status, result.stdout) == (0, b"")


def test_the_server_is_a_separate_process_that_stops_with_its_owner():
    with FakeAdbProcess("dense", 10) as srv:
        process = srv._process
        assert process is not None
        assert process.pid > 0
    assert process.poll() is not None
    assert process.returncode == 0  # it stopped by itself, it was not killed


def test_rows_that_need_the_stream_skip_when_it_is_missing(monkeypatch, capsys):
    monkeypatch.delattr(logprobe.Device, "stream", raising=False)
    assert stream_bench.main(["throughput", "burst", "slow-burst"]) == 0
    out = capsys.readouterr().out
    assert out.count("skipped: stream API not available") == 3


def test_the_async_rows_deliver_every_line_and_the_lag_row_reports_the_lag(capsys):
    args = ["async-throughput", "async-lag", "--lines", "600", "--burst-lines", "600"]
    assert stream_bench.main([*args, "--repeat", "1", "--json"]) == 0
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [r["row"] for r in records] == ["async-throughput", "async-lag"]
    assert all(r["delivered"] == r["expected"] == 600 for r in records)
    assert {"max_lag_ms", "p99_lag_ms"} <= records[1]["extra"].keys()


def test_the_async_rows_skip_when_the_async_stream_is_missing(monkeypatch, capsys):
    monkeypatch.delattr(logprobe.Device, "astream", raising=False)
    assert stream_bench.main(["async-throughput", "async-lag"]) == 0
    assert capsys.readouterr().out.count("skipped: stream API not available") == 2


def test_the_multi_rows_deliver_every_line_with_the_right_serial(capsys):
    args = ["multi", "async-multi", "--lines", "1200", "--repeat", "1", "--json"]
    assert stream_bench.main(args) == 0
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [r["row"] for r in records] == ["multi", "async-multi"]
    assert all(r["delivered"] == r["expected"] == 900 for r in records)
    assert all(r["extra"]["complete"] is True for r in records)


def test_a_serial_mix_up_in_the_multi_row_is_reported(monkeypatch, capsys):
    real = logprobe.stream
    other = {"bench-0001": "bench-0002", "bench-0002": "bench-0001"}

    class Swapped:
        """The real stream, with the entries of each device marked as the other's."""

        def __init__(self, devices):
            self.inner = real(devices)
            self.stop = self.inner.stop
            self.kill = self.inner.kill

        def __enter__(self):
            self.inner.__enter__()
            return self

        def __exit__(self, *exc_info):
            return self.inner.__exit__(*exc_info)

        def __iter__(self):
            for entry in self.inner:
                yield SimpleNamespace(serial=other[str(entry.serial)])

    monkeypatch.setattr(logprobe, "stream", Swapped)
    assert stream_bench.main(["multi", "--lines", "400", "--repeat", "1"]) == 0
    out = capsys.readouterr().out
    assert "delivered 300/300" in out
    assert "100% delivery: NO" in out


@pytest.mark.parametrize("row", ["multi", "async-multi"])
@pytest.mark.parametrize("timeout", [None, 0.3])
def test_the_multi_rows_stop_a_stream_that_never_delivers_the_last_line(
    monkeypatch, capsys, row, timeout
):
    class Expecting(FakeAdbProcess):
        """A server that is told to expect one more line than it serves."""

        def __enter__(self):
            super().__enter__()
            if self.serial == "bench-0002":
                self.lines += 1
            return self

    monkeypatch.setattr(stream_bench, "FakeAdbProcess", Expecting)
    # Only the watchdog can end the run: the settle stop, or the run timeout.
    monkeypatch.setattr(
        stream_bench, "SETTLE_SECONDS", 0.5 if timeout is None else 30.0
    )
    if timeout is not None:
        monkeypatch.setattr(stream_bench, "RUN_TIMEOUT", timeout)
    assert stream_bench.main([row, "--lines", "400", "--repeat", "1"]) == 0
    out = capsys.readouterr().out
    # How many lines arrived before the watchdog fired depends on how fast the
    # stream started, so only the outcome is checked.
    assert "/301; 100% delivery: NO" in out
    assert ("TIMED OUT in 1 of 1" in out) == (timeout is not None)


def test_the_multi_rows_give_each_device_a_line_even_for_a_tiny_size(capsys):
    assert stream_bench.main(["multi", "--lines", "1", "--repeat", "1"]) == 0
    out = capsys.readouterr().out
    assert "2+1 lines" in out
    assert "delivered 3/3" in out


def test_the_multi_rows_skip_when_the_stream_functions_are_missing(monkeypatch, capsys):
    monkeypatch.setattr(logprobe, "stream", None)
    monkeypatch.setattr(logprobe, "astream", None)
    assert stream_bench.main(["multi", "async-multi"]) == 0
    assert capsys.readouterr().out.count("skipped: stream API not available") == 2


def test_transport_feeder_and_delivery_rows_deliver_every_line(capsys):
    args = ["transport", "feeder", "delivery", "--lines", "600", "--repeat", "1"]
    assert stream_bench.main([*args, "--json"]) == 0
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [r["row"] for r in records] == ["transport", "feeder", "feeder", "delivery"]
    assert all(r["delivered"] == r["expected"] > 0 for r in records)


def test_without_the_exit_packet_the_stream_has_no_status():
    lines = build_lines("live", 20)
    stream, packets = pack_packets(lines, exit_packet=False)
    payloads, status = decode(stream)
    assert (payloads, status, packets) == (lines, None, 20)


def test_a_held_connection_stays_open_after_the_lines():
    with FakeAdbProcess("dense", 20, hold=True) as srv:
        expected = len(b"".join(build_lines("dense", 20)))
        with stream_bench._open_logcat(srv.port, srv.serial) as sock:
            decoder = _adb.ShellV2Decoder()
            seen = 0
            while seen < expected:
                out, _err, status = decoder.feed(sock.recv(65536))
                assert status is None
                seen += len(out)
            sock.settimeout(0.3)
            with pytest.raises(TimeoutError):
                sock.recv(1)  # nothing comes, and the connection is not closed


class _FakeStream:
    """A stream over the fake server's connection, as strict as the real one."""

    def __init__(self, device, *, drop, end):
        self.device = device
        self.drop = drop
        self.end = end
        self.stopped = False

    def kill(self):
        self.stopped = True

    stop = kill

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return None

    def __iter__(self):
        address = self.device._address
        argv = _adb.logcat_argv(dump=False, tail=None, t=None)
        with _adb.open_shell(address, self.device.serial, argv) as shell:
            shell.set_timeout(0.1)
            count = 0
            while not self.stopped:
                try:
                    event = shell.read()
                except TimeoutError:
                    continue  # nothing arrived within the slice: look at `stopped`
                if event is None:
                    break
                for _ in event[1].splitlines():
                    count += 1
                    if count > self.drop:
                        yield object()
        if self.end:
            raise logprobe.LogprobeError(
                "device_lost", "the connection ended", {"exit_status": 0}
            )


@pytest.mark.parametrize("end", [False, True])
def test_burst_row_checks_delivery_against_a_stream(monkeypatch, capsys, end):
    # With `end` the stream also raises the error a connection that ended with
    # exit status 0 gives, after its last entry.
    for drop, expected in ((0, "yes"), (3, "NO")):
        monkeypatch.setattr(
            logprobe.Device,
            "stream",
            lambda self, drop=drop: _FakeStream(self, drop=drop, end=end),
            raising=False,
        )
        monkeypatch.setattr(stream_bench, "SETTLE_SECONDS", 0.5)
        args = ["burst", "--burst-lines", "400", "--repeat", "1"]
        assert stream_bench.main(args) == 0
        assert f"100% delivery: {expected}" in capsys.readouterr().out


def test_the_stream_is_opened_with_default_settings(monkeypatch):
    seen = []

    def stream(self, *args, **kwargs):
        seen.append((args, kwargs))
        return _FakeStream(self, drop=0, end=False)

    monkeypatch.setattr(logprobe.Device, "stream", stream, raising=False)
    monkeypatch.setattr(stream_bench, "SETTLE_SECONDS", 0.5)
    assert stream_bench.main(["burst", "--burst-lines", "50", "--repeat", "1"]) == 0
    assert seen == [((), {})]


def test_stream_rows_ask_the_fake_server_to_hold_the_connection(monkeypatch):
    holds = []
    real = stream_bench.FakeAdbProcess

    def spy(*args, **kwargs):
        holds.append(kwargs.get("hold"))
        return real(*args, **kwargs)

    monkeypatch.setattr(stream_bench, "FakeAdbProcess", spy)
    monkeypatch.setattr(
        logprobe.Device,
        "stream",
        lambda self: _FakeStream(self, drop=0, end=False),
        raising=False,
    )
    monkeypatch.setattr(stream_bench, "SETTLE_SECONDS", 0.5)
    assert stream_bench.main(["burst", "--burst-lines", "20", "--repeat", "1"]) == 0
    assert holds == [True]


def test_a_stream_run_stops_after_the_last_expected_entry(monkeypatch):
    class Endless:
        taken = 0

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return None

        def __iter__(self):
            # Bounded so that a run that does not stop fails instead of hanging.
            while Endless.taken < 100:
                Endless.taken += 1
                yield object()

        def stop(self):
            pass

        kill = stop

    monkeypatch.setattr(
        logprobe.Device, "stream", lambda _self: Endless(), raising=False
    )
    with FakeAdbProcess("live", 30, "line", "s", hold=True) as srv:
        sample = stream_bench._stream_once("burst", "x", srv, 0.0)
    assert (sample.delivered, Endless.taken) == (30, 30)


def test_ctrl_c_ends_the_run_with_status_130(monkeypatch):
    def interrupted(_args):
        raise KeyboardInterrupt

    monkeypatch.setitem(stream_bench.ROW_FUNCTIONS, "feeder", interrupted)
    assert stream_bench.main(["feeder"]) == 130


def test_a_run_that_hits_the_time_limit_is_not_reported_as_complete(
    monkeypatch, capsys
):
    class Stuck(_FakeStream):
        def __iter__(self):
            for _ in range(399):
                yield object()
            while not self.stopped:  # the last entry never comes, nor an end
                time.sleep(0.02)

    monkeypatch.setattr(
        logprobe.Device,
        "stream",
        lambda self: Stuck(self, drop=0, end=False),
        raising=False,
    )
    monkeypatch.setattr(stream_bench, "RUN_TIMEOUT", 0.3)
    args = ["burst", "--burst-lines", "400", "--repeat", "1"]
    assert stream_bench.main(args) == 0
    out = capsys.readouterr().out
    assert "TIMED OUT in 1 of 1" in out
    assert "100% delivery: NO" in out


def test_a_first_run_that_delivers_nothing_still_gets_a_verdict():
    empty = stream_bench.Sample("burst", "x", 400, 0, 0.0)
    full = stream_bench.Sample("burst", "x", 400, 400, 0.01)
    assert "100% delivery: NO" in stream_bench.format_group([empty, full])


@pytest.mark.parametrize("text", ["0", "-1", "nan", "inf"])
def test_slow_us_must_be_finite_and_above_zero(text):
    with pytest.raises(SystemExit):
        stream_bench.parse_args(["slow-burst", "--slow-us", text])
