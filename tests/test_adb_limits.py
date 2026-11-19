"""Limits on what an adb server can make logprobe hold or wait for."""

from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
import time
from typing import TYPE_CHECKING

import pytest

from logprobe import Device, LogprobeError, _aadb, _adb, _adump, _astream, _dump
from tests.fake_adb_server import Cut, FakeAdbServer, ShellScript

if TYPE_CHECKING:
    from collections.abc import Generator

SERIAL = "emulator-5554"
PREFIX = 'export ANDROID_LOG_TAGS=""; exec '


def recv_exactly(conn: socket.socket, size: int) -> bytes:
    """Receive exactly ``size`` bytes, however the network splits them."""
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            msg = f"the client closed after {len(data)} of {size} bytes"
            raise AssertionError(msg)
        data += chunk
    return data


def read_request(conn: socket.socket) -> bytes:
    return recv_exactly(conn, int(recv_exactly(conn, 4), 16))


def address_of(fake: FakeAdbServer) -> _adb.ServerAddress:
    return _adb.resolve_server_address(fake.address)


@pytest.fixture
def one_device(fake: FakeAdbServer) -> FakeAdbServer:
    fake.add_device(SERIAL)
    return fake


# --- shell packets -----------------------------------------------------------


def header(kind: int, length: int) -> bytes:
    return bytes([kind]) + length.to_bytes(4, "little")


@pytest.mark.parametrize("kind", [1, 2])
def test_a_shell_packet_longer_than_the_limit_is_a_protocol_error(kind: int) -> None:
    decoder = _adb.ShellV2Decoder()
    pieces, status, error = decoder.feed_pieces(
        header(kind, _adb.MAX_SHELL_PACKET + 1) + b"xyz"
    )
    assert (pieces, status) == ([], None)
    assert isinstance(error, LogprobeError)
    assert error.code == "adb_error"
    assert error.details["length"] == _adb.MAX_SHELL_PACKET + 1
    # Nothing is accepted after it.
    assert decoder.feed_pieces(b"more")[2] is not None


def test_a_shell_packet_of_the_limit_is_accepted() -> None:
    decoder = _adb.ShellV2Decoder()
    pieces, _, error = decoder.feed_pieces(header(1, _adb.MAX_SHELL_PACKET) + b"ab")
    assert error is None
    assert [(kind, bytes(piece), ends) for kind, piece, ends in pieces] == [
        ("stdout", b"ab", False)
    ]


def test_a_huge_packet_header_ends_a_command_at_once() -> None:
    # The payload never comes; without the limit the read would wait for it
    # until the timeout.
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(5)
    release = threading.Event()

    def serve() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(5)
            for _ in range(2):  # transport request, then shell request
                read_request(conn)
                conn.sendall(b"OKAY")
            conn.sendall(header(1, 0xFFFFFFFF) + b"x" * 1000)
            release.wait(5)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        address = _adb.ServerAddress(
            "127.0.0.1", listener.getsockname()[1], is_default=False
        )
        began = time.monotonic()
        with pytest.raises(LogprobeError) as raised:
            _adb.run_shell(address, SERIAL, ["huge"], 3.0)
        assert raised.value.code == "adb_error"
        assert raised.value.details["length"] == 0xFFFFFFFF
        assert time.monotonic() - began < 2
    finally:
        release.set()
        thread.join(timeout=10)
        listener.close()


# --- output of the commands logprobe runs itself ------------------------------


def chatty_script() -> ShellScript:
    return ShellScript(steps=[("stdout", b"x" * 100)] * 3 + [("stderr", b"e" * 60)])


def test_run_shell_stops_at_max_output(one_device: FakeAdbServer) -> None:
    one_device.shell[PREFIX + "big"] = chatty_script()
    address = address_of(one_device)
    with pytest.raises(LogprobeError) as raised:
        _adb.run_shell(address, SERIAL, ["big"], 5.0, max_output=250)
    assert raised.value.code == "adb_error"
    assert raised.value.details == {"command": "big", "limit": 250}
    # Stdout and stderr count together; exactly the limit is fine.
    result = _adb.run_shell(address, SERIAL, ["big"], 5.0, max_output=360)
    assert (len(result.stdout), len(result.stderr)) == (300, 60)
    with pytest.raises(LogprobeError):
        _adb.run_shell(address, SERIAL, ["big"], 5.0, max_output=359)


def test_arun_shell_stops_at_max_output(one_device: FakeAdbServer) -> None:
    one_device.shell[PREFIX + "big"] = chatty_script()
    address = address_of(one_device)
    with pytest.raises(LogprobeError) as raised:
        asyncio.run(_aadb.arun_shell(address, SERIAL, ["big"], 5.0, max_output=250))
    assert raised.value.code == "adb_error"
    result = asyncio.run(
        _aadb.arun_shell(address, SERIAL, ["big"], 5.0, max_output=360)
    )
    assert (len(result.stdout), len(result.stderr)) == (300, 60)


def test_the_commands_of_streams_and_dumps_are_limited(
    one_device: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_adb, "COMMAND_OUTPUT_LIMIT", 250)
    one_device.shell[PREFIX + "big"] = chatty_script()
    device = Device(SERIAL, adb_server=one_device.address, start_server=False)
    with pytest.raises(LogprobeError):
        device._run_command(["big"], 5.0)
    one_device.shell[PREFIX + "pm list packages -U"] = chatty_script()
    with pytest.raises(LogprobeError):
        _dump._take_list(address_of(one_device), SERIAL)


def cut_script() -> ShellScript:
    # 200 bytes of stdout, then 80 of a 100-byte stderr packet, and the
    # connection drops: the 80 bytes are kept as stderr.
    return ShellScript(
        steps=[("stdout", b"o" * 200), Cut("stderr", b"e" * 100, 5 + 80)],
        exit_status=None,
    )


def test_the_held_part_of_a_cut_stderr_packet_counts_toward_the_limit(
    one_device: FakeAdbServer,
) -> None:
    one_device.shell[PREFIX + "cut"] = cut_script()
    address = address_of(one_device)
    result = _adb.run_shell(address, SERIAL, ["cut"], 5.0, max_output=280)
    assert (len(result.stdout), len(result.stderr)) == (200, 80)
    with pytest.raises(LogprobeError) as raised:
        _adb.run_shell(address, SERIAL, ["cut"], 5.0, max_output=279)
    assert raised.value.details == {"command": "cut", "limit": 279}
    result = asyncio.run(
        _aadb.arun_shell(address, SERIAL, ["cut"], 5.0, max_output=280)
    )
    assert (len(result.stdout), len(result.stderr)) == (200, 80)
    with pytest.raises(LogprobeError):
        asyncio.run(_aadb.arun_shell(address, SERIAL, ["cut"], 5.0, max_output=279))


@pytest.mark.parametrize("mode", ["blocking", "async"])
def test_the_held_part_counts_toward_the_limit_on_a_timeout(
    one_device: FakeAdbServer, mode: str
) -> None:
    # As above, but the connection stays open after the cut: the command times
    # out, and the 80 held bytes are added before the timeout is raised.
    address = address_of(one_device)

    def run(name: str, limit: int) -> object:
        # A waiting point gates one connection, so each run has its own.
        one_device.shell[PREFIX + name] = ShellScript(
            steps=[("stdout", b"o" * 200), Cut("stderr", b"e" * 100, 85, hold=name)],
            exit_status=None,
        )
        try:
            if mode == "blocking":
                return _adb.run_shell(address, SERIAL, [name], 0.5, max_output=limit)
            return asyncio.run(
                _aadb.arun_shell(address, SERIAL, [name], 0.5, max_output=limit)
            )
        finally:
            one_device.release(name)

    with pytest.raises(LogprobeError) as raised:
        run("over", 279)
    assert raised.value.details == {"command": "over", "limit": 279}
    with pytest.raises(_adb.CommandTimeoutError) as timed_out:
        run("fits", 280)
    assert timed_out.value.stderr == b"e" * 80


def test_the_async_commands_of_streams_and_dumps_are_limited(
    one_device: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_adb, "COMMAND_OUTPUT_LIMIT", 250)
    one_device.shell[PREFIX + "pm list packages -U"] = chatty_script()
    with pytest.raises(LogprobeError):
        asyncio.run(_adump._take_list(address_of(one_device), SERIAL))
    # The asyncio stream's own commands go through _astream._run_command.
    passed: list[object] = []
    real = _astream.arun_shell

    async def spy(*args: object, **named: object) -> object:
        passed.append(named.get("max_output"))
        return await real(*args, **named)  # ty: ignore[invalid-argument-type]

    monkeypatch.setattr(_astream, "arun_shell", spy)
    one_device.shell[PREFIX + "small"] = ShellScript(steps=[("stdout", b"ok")])
    device = Device(SERIAL, adb_server=one_device.address, start_server=False)
    unit = _astream._AUnit(device, None, 0.0)
    core = _astream._ACore([unit], _astream.AsyncOutbox(10, 1 << 20))
    result = asyncio.run(_astream._run_command(core, unit, ["small"], 5.0))
    assert result.stdout == b"ok"
    assert passed == [250]


def test_device_shell_has_no_output_limit(
    one_device: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_adb, "COMMAND_OUTPUT_LIMIT", 250)
    one_device.shell[PREFIX + "big"] = chatty_script()
    device = Device(SERIAL, adb_server=one_device.address, start_server=False)
    result = device.shell(["big"])
    assert (len(result.stdout), len(result.stderr)) == (300, 60)


# --- host queries --------------------------------------------------------------


@contextlib.contextmanager
def trickling_server(
    reply: bytes, gap: float, *, status: bytes = b"OKAY"
) -> Generator[tuple[_adb.ServerAddress, threading.Event]]:
    """A server that answers one request with ``status`` at once (b"" for none),
    then sends ``reply`` byte by byte, ``gap`` seconds apart."""
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(5)
    stop = threading.Event()

    def serve() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(5)
            read_request(conn)
            conn.sendall(status)
            for byte in reply:
                if stop.wait(gap):
                    return
                try:
                    conn.sendall(bytes([byte]))
                except OSError:
                    return

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        yield (
            _adb.ServerAddress(
                "127.0.0.1", listener.getsockname()[1], is_default=False
            ),
            stop,
        )
    finally:
        stop.set()
        thread.join(timeout=10)
        listener.close()


REPLY = b"0014" + b"x" * 20  # 24 bytes, one every 0.1 s: 2.4 s in all


def test_a_host_query_reply_that_trickles_in_is_cut_at_the_timeout() -> None:
    with trickling_server(REPLY, 0.1) as (address, _):
        began = time.monotonic()
        with pytest.raises(LogprobeError) as raised:
            _adb.host_query(address, "host:version", timeout=0.5)
        took = time.monotonic() - began
    assert raised.value.code == "adb_error"
    assert took < 1.5


def test_an_async_host_query_reply_that_trickles_in_is_cut_at_the_timeout() -> None:
    with trickling_server(REPLY, 0.1) as (address, _):
        began = time.monotonic()
        with pytest.raises(LogprobeError) as raised:
            asyncio.run(_aadb.ahost_query(address, "host:version", timeout=0.5))
        took = time.monotonic() - began
    assert raised.value.code == "adb_error"
    assert took < 1.5


# Every field (status, length, body) takes 0.2 s, within the 0.3 s limit on its
# own; together they take 0.6 s.
FIELDS = b"OKAY0004abcd"
FAILED = b"FAIL0004nope"


@pytest.mark.parametrize("reply", [FIELDS, FAILED])
def test_the_limit_covers_all_fields_of_a_host_reply_together(reply: bytes) -> None:
    server = trickling_server(reply, 0.05, status=b"")
    with server as (address, _), pytest.raises(LogprobeError) as raised:
        _adb.host_query(address, "host:version", timeout=0.3)
    assert str(raised.value) == "timed out waiting for the adb server"
    server = trickling_server(reply, 0.05, status=b"")
    with server as (address, _), pytest.raises(LogprobeError) as raised:
        asyncio.run(_aadb.ahost_query(address, "host:version", timeout=0.3))
    assert str(raised.value) == "timed out waiting for the adb server"


def test_the_host_query_limit_holds_while_a_cancel_callback_is_asked() -> None:
    with trickling_server(REPLY, 0.1) as (address, _):
        began = time.monotonic()
        with pytest.raises(LogprobeError) as raised:
            _adb.host_query(
                address, "host:version", timeout=0.5, cancelled=lambda: False
            )
        took = time.monotonic() - began
    assert raised.value.code == "adb_error"
    assert took < 1.5
    with trickling_server(REPLY, 0.1) as (address, _):
        stop_at = time.monotonic() + 0.3
        with pytest.raises(_adb.Cancelled):
            _adb.host_query(
                address,
                "host:version",
                timeout=5.0,
                cancelled=lambda: time.monotonic() > stop_at,
            )


def test_a_host_query_that_answers_in_time_is_unchanged() -> None:
    with trickling_server(b"0002ok", 0.01) as (address, _):
        assert _adb.host_query(address, "host:version", timeout=2.0) == b"ok"
    with trickling_server(b"0002ok", 0.01) as (address, _):
        reply = asyncio.run(_aadb.ahost_query(address, "host:version", timeout=2.0))
        assert reply == b"ok"
