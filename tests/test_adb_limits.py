"""Limits on what an adb server can make logprobe hold or wait for."""

from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
import time
from typing import TYPE_CHECKING

import pytest

from logprobe import Device, LogprobeError, _aadb, _adb, _dump
from tests.fake_adb_server import FakeAdbServer, ShellScript

if TYPE_CHECKING:
    from collections.abc import Generator

SERIAL = "emulator-5554"
PREFIX = 'export ANDROID_LOG_TAGS=""; exec '


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
            for _ in range(2):  # transport request, then shell request
                size = int(conn.recv(4), 16)
                conn.recv(size)
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
    reply: bytes, gap: float
) -> Generator[tuple[_adb.ServerAddress, threading.Event]]:
    """A server that answers one request OKAY, then sends ``reply`` byte by byte."""
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(5)
    stop = threading.Event()

    def serve() -> None:
        conn, _ = listener.accept()
        with conn:
            size = int(conn.recv(4), 16)
            conn.recv(size)
            conn.sendall(b"OKAY")
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


def test_a_host_query_that_answers_in_time_is_unchanged() -> None:
    with trickling_server(b"0002ok", 0.01) as (address, _):
        assert _adb.host_query(address, "host:version", timeout=2.0) == b"ok"
    with trickling_server(b"0002ok", 0.01) as (address, _):
        reply = asyncio.run(_aadb.ahost_query(address, "host:version", timeout=2.0))
        assert reply == b"ok"
