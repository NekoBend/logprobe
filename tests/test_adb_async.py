"""The blocking and the asyncio adb clients, and what is special about asyncio.

The first half runs one test body against both clients, so they cannot drift
apart on what they send, what they accept and which errors they raise. The
second half covers what only the asyncio client has: reads that can be cut
short and resumed, cancellation, and the promise of no threads.
"""

from __future__ import annotations

import asyncio
import contextlib
import gc
import socket
import struct
import sys
import threading
import time
from types import SimpleNamespace
from typing import TYPE_CHECKING, NamedTuple, Protocol, cast

import pytest

from logprobe import LogprobeError, _aadb, _adb
from logprobe._adb import protocol as adb_protocol
from logprobe._adb import shell as adb_shell
from tests.fake_adb_server import (
    BAD_LENGTHS,
    FakeAdbServer,
    ShellScript,
    Wait,
    free_port,
    packet,
)
from tests.test_adb_protocol import ScriptedSocket

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator, Sequence

SERIAL = "emulator-5554"
PREFIX = 'export ANDROID_LOG_TAGS=""; exec '
STDIN_CLOSED = b"\x04\x00\x00\x00\x00"

pytestmark = pytest.mark.filterwarnings("error::ResourceWarning")


@pytest.fixture(autouse=True)
def clean_event_loops(caplog: pytest.LogCaptureFixture) -> Generator[None]:
    """Fail a test that leaves a pending task or an unclosed transport behind."""
    yield
    gc.collect()
    problems = [r.getMessage() for r in caplog.records if r.name == "asyncio"]
    assert problems == []


@pytest.fixture
def one_device(fake: FakeAdbServer) -> FakeAdbServer:
    fake.add_device(SERIAL)
    fake.features[SERIAL] = ["shell_v2", "cmd"]
    return fake


def address_of(fake: FakeAdbServer) -> _adb.ServerAddress:
    return _adb.resolve_server_address(fake.address)


@contextlib.contextmanager
def raw_server(reply: bytes) -> Generator[tuple[_adb.ServerAddress, bytearray]]:
    """A one-shot server that sends ``reply`` at once, ends its side, and records."""
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(5)  # a client that never connects cannot hang the test run
    received = bytearray()

    def serve() -> None:
        conn, _ = listener.accept()
        with conn, contextlib.suppress(OSError):  # the client may hang up early
            conn.sendall(reply)
            conn.shutdown(socket.SHUT_WR)  # a short reply is then really cut off
            while chunk := conn.recv(4096):
                received.extend(chunk)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        yield (
            _adb.ServerAddress(
                "127.0.0.1", listener.getsockname()[1], is_default=False
            ),
            received,
        )
    finally:
        # Longer than the listener's 5 s, so that a client that never
        # connects fails this test and not a later one.
        thread.join(timeout=10)
        listener.close()


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


@contextlib.contextmanager
def reset_server(output: bytes) -> Generator[_adb.ServerAddress]:
    """A one-shot server that answers the handshake, sends ``output``, then resets.

    It resets only after the whole stdin close packet has arrived, so the reset
    never meets a send the client still has in progress.
    """
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(5)  # a client that never connects cannot hang the test run

    def serve() -> None:
        conn, _ = listener.accept()
        # If the client never sends the stdin close packet, the reads below time
        # out instead of hanging.
        conn.settimeout(5)
        with conn:
            for _ in range(2):  # transport request, then shell request
                size = int(recv_exactly(conn, 4), 16)
                recv_exactly(conn, size)
                conn.sendall(b"OKAY")
            assert recv_exactly(conn, len(STDIN_CLOSED)) == STDIN_CLOSED
            conn.sendall(output)
            conn.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
            )

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        yield _adb.ServerAddress("127.0.0.1", listener.getsockname()[1], False)  # noqa: FBT003
    finally:
        # Longer than the listener's 5 s, so that a client that never
        # connects fails this test and not a later one.
        thread.join(timeout=10)
        listener.close()


@contextlib.contextmanager
def trickle_server(reply: bytes, delay: float) -> Generator[_adb.ServerAddress]:
    """A one-shot server that reads one request, then sends ``reply`` slowly."""
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(5)  # a client that never connects cannot hang the test run

    def serve() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.recv(4096)
            with contextlib.suppress(OSError):  # the client gave up
                for index in range(len(reply)):
                    conn.sendall(reply[index : index + 1])
                    time.sleep(delay)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        yield _adb.ServerAddress("127.0.0.1", listener.getsockname()[1], False)  # noqa: FBT003
    finally:
        # Longer than the listener's 5 s, so that a client that never
        # connects fails this test and not a later one.
        thread.join(timeout=10)
        listener.close()


class ScriptedReader:
    """A stream reader whose read() returns one scripted chunk per call.

    The counterpart of ``ScriptedSocket`` for the asyncio client: nothing is
    merged or split by a network, so each chunk reaches the decoder as one
    receive. After the script is used up, read() returns ``b""``.
    """

    lost: Exception | None = None

    def __init__(self, chunks: Sequence[bytes]) -> None:
        self._chunks = list(chunks)
        self.read_calls = 0

    async def read(self, size: int) -> bytes:
        self.read_calls += 1
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if len(chunk) > size:  # a real read never returns more than asked
            self._chunks.insert(0, chunk[size:])
            chunk = chunk[:size]
        return chunk


class Client(Protocol):
    def events(
        self,
        address: _adb.ServerAddress,
        args: Sequence[str],
        timeout: float = 5.0,
        pause: float = 0.0,
    ) -> tuple[list[_adb.ShellEvent], int | None]: ...

    def reads(self, address: _adb.ServerAddress) -> tuple[list[object], int | None]: ...

    def run(
        self,
        address: _adb.ServerAddress,
        args: Sequence[str],
        timeout: float | None,
        serial: str = SERIAL,
    ) -> _adb.ShellResult: ...

    def features(
        self, address: _adb.ServerAddress, timeout: float = 5.0
    ) -> frozenset[str]: ...

    def require_shell_v2(self, address: _adb.ServerAddress) -> None: ...

    def fail_stdin_close(
        self, monkeypatch: pytest.MonkeyPatch, error: type[OSError]
    ) -> None:
        """Make sending the stdin close packet fail with ``error``."""
        ...

    def scripted(self, chunks: Sequence[bytes]) -> Scripted:
        """Read four times from a stream that receives exactly these chunks."""
        ...


class Scripted(NamedTuple):
    """What four reads of a scripted stream gave: events or errors, in order."""

    found: list[object]
    exit_status: int | None
    receives: int


class Blocking:
    def events(
        self,
        address: _adb.ServerAddress,
        args: Sequence[str],
        timeout: float = 5.0,
        pause: float = 0.0,
    ) -> tuple[list[_adb.ShellEvent], int | None]:
        with _adb.open_shell(address, SERIAL, args, timeout=timeout) as stream:
            time.sleep(pause)
            found = []
            while (event := stream.read()) is not None:
                found.append(event)
        return found, stream.exit_status

    def reads(self, address: _adb.ServerAddress) -> tuple[list[object], int | None]:
        found: list[object] = []
        with _adb.open_shell(address, SERIAL, ["x"]) as stream:
            for _ in range(4):
                try:
                    found.append(stream.read())
                except LogprobeError as error:
                    found.append(error)
        return found, stream.exit_status

    def run(
        self,
        address: _adb.ServerAddress,
        args: Sequence[str],
        timeout: float | None,
        serial: str = SERIAL,
    ) -> _adb.ShellResult:
        return _adb.run_shell(address, serial, args, timeout)

    def features(
        self, address: _adb.ServerAddress, timeout: float = 5.0
    ) -> frozenset[str]:
        return _adb.device_features(address, SERIAL, timeout)

    def require_shell_v2(self, address: _adb.ServerAddress) -> None:
        _adb.require_shell_v2(address, SERIAL)

    def fail_stdin_close(
        self, monkeypatch: pytest.MonkeyPatch, error: type[OSError]
    ) -> None:
        real = _adb._send_all

        def send_all(
            sock: socket.socket,
            data: bytes,
            deadline: float | None,
            cancelled: Callable[[], bool] | None,
            idle: float | None,
        ) -> None:
            if data == STDIN_CLOSED:
                raise error
            real(sock, data, deadline, cancelled, idle)

        monkeypatch.setattr(adb_protocol, "_send_all", send_all)
        monkeypatch.setattr(adb_shell, "_send_all", send_all)

    def scripted(self, chunks: Sequence[bytes]) -> Scripted:
        sock = ScriptedSocket(chunks)
        stream = _adb.ShellStream(cast("socket.socket", sock))
        found: list[object] = []
        for _ in range(4):
            try:
                found.append(stream.read())
            except LogprobeError as error:
                found.append(error)
        return Scripted(found, stream.exit_status, sock.recv_calls)


class Async:
    def events(
        self,
        address: _adb.ServerAddress,
        args: Sequence[str],
        timeout: float = 5.0,
        pause: float = 0.0,
    ) -> tuple[list[_adb.ShellEvent], int | None]:
        async def go() -> tuple[list[_adb.ShellEvent], int | None]:
            found = []
            async with await _aadb.aopen_shell(
                address, SERIAL, args, timeout=timeout
            ) as stream:
                await asyncio.sleep(pause)
                while (event := await stream.read()) is not None:
                    found.append(event)
            return found, stream.exit_status

        return asyncio.run(go())

    def reads(self, address: _adb.ServerAddress) -> tuple[list[object], int | None]:
        async def go() -> tuple[list[object], int | None]:
            found: list[object] = []
            async with await _aadb.aopen_shell(address, SERIAL, ["x"]) as stream:
                for _ in range(4):
                    try:
                        found.append(await stream.read())
                    except LogprobeError as error:
                        found.append(error)
            return found, stream.exit_status

        return asyncio.run(go())

    def run(
        self,
        address: _adb.ServerAddress,
        args: Sequence[str],
        timeout: float | None,
        serial: str = SERIAL,
    ) -> _adb.ShellResult:
        return asyncio.run(_aadb.arun_shell(address, serial, args, timeout))

    def features(
        self, address: _adb.ServerAddress, timeout: float = 5.0
    ) -> frozenset[str]:
        return asyncio.run(_aadb.adevice_features(address, SERIAL, timeout))

    def require_shell_v2(self, address: _adb.ServerAddress) -> None:
        asyncio.run(_aadb.arequire_shell_v2(address, SERIAL))

    def fail_stdin_close(
        self, monkeypatch: pytest.MonkeyPatch, error: type[OSError]
    ) -> None:
        # A write that is accepted but fails when it is flushed, as a reset does.
        real_write = asyncio.StreamWriter.write
        real_drain = asyncio.StreamWriter.drain
        last: list[bytes] = []

        def write(writer: asyncio.StreamWriter, data: bytes) -> None:
            last.append(bytes(data))
            real_write(writer, data)

        async def drain(writer: asyncio.StreamWriter) -> None:
            if last[-1] == STDIN_CLOSED:
                raise error
            await real_drain(writer)

        monkeypatch.setattr(asyncio.StreamWriter, "write", write)
        monkeypatch.setattr(asyncio.StreamWriter, "drain", drain)

    #: Read with `AsyncShellStream.read_part` instead of ``read``.
    parts = False

    def scripted(self, chunks: Sequence[bytes]) -> Scripted:
        reader = ScriptedReader(chunks)
        transport = SimpleNamespace(abort=lambda: None)
        writer = SimpleNamespace(transport=transport)

        async def go() -> Scripted:
            stream = _aadb.AsyncShellStream(
                cast("_aadb._Reader", reader), cast("asyncio.StreamWriter", writer)
            )
            read = stream.read_part if self.parts else stream.read
            found: list[object] = []
            for _ in range(4):
                try:
                    found.append(await read())
                except LogprobeError as error:
                    found.append(error)
            return Scripted(found, stream.exit_status, reader.read_calls)

        return asyncio.run(go())


class AsyncParts(Async):
    """The asyncio client read with ``read_part``, as the asyncio log stream does."""

    parts = True


@pytest.fixture(params=[Blocking, Async], ids=["blocking", "async"])
def client(request: pytest.FixtureRequest) -> Client:
    return request.param()


@pytest.fixture(
    params=[Blocking, Async, AsyncParts], ids=["blocking", "async", "async-read_part"]
)
def decoder(request: pytest.FixtureRequest) -> Client:
    """A client for the scripted tests of how a stream ends, read either way."""
    return request.param()


def merge(events: list[_adb.ShellEvent]) -> dict[str, bytes]:
    return {
        kind: b"".join(data for k, data in events if k == kind)
        for kind in ("stdout", "stderr")
    }


# --- one scenario, both clients ---------------------------------------------


@pytest.mark.parametrize("delivery", ["plain", "fragment", "coalesce"])
def test_shell_delivers_both_streams_and_the_exit_status(
    client: Client, one_device: FakeAdbServer, delivery: str
) -> None:
    one_device.shell[PREFIX + "logcat"] = ShellScript(
        steps=[("stdout", b"line 1\n"), ("stderr", b"oops\n"), ("stdout", b"line 2\n")],
        exit_status=3,
        fragment=delivery == "fragment",
        coalesce=delivery == "coalesce",
    )
    events, status = client.events(address_of(one_device), ["logcat"])
    assert merge(events) == {"stdout": b"line 1\nline 2\n", "stderr": b"oops\n"}
    assert status == 3
    assert one_device.requests == [
        f"host:transport:{SERIAL}",
        f"shell,v2,raw:{PREFIX}logcat",
    ]


def test_run_collects_output_and_a_dropped_connection_has_no_status(
    client: Client, one_device: FakeAdbServer
) -> None:
    one_device.shell[PREFIX + "getprop ro.x"] = ShellScript(
        steps=[("stdout", b"val"), ("stderr", b"e"), ("stdout", b"ue\n")], exit_status=0
    )
    one_device.shell[PREFIX + "x"] = ShellScript(
        steps=[("stdout", b"a")], exit_status=None
    )
    address = address_of(one_device)
    assert client.run(address, ["getprop", "ro.x"], 5) == _adb.ShellResult(
        0, b"value\n", b"e"
    )
    assert client.run(address, ["x"], 5) == _adb.ShellResult(None, b"a", b"")


@pytest.mark.parametrize(
    ("message", "code"),
    [
        ("device 'emulator-5554' not found", "device_not_found"),
        ("device offline", "device_offline"),
        ("device unauthorized.\nSee adb help", "device_unauthorized"),
        ("closed", "adb_error"),
    ],
)
def test_fail_on_the_transport_request_maps_to_a_code(
    client: Client, one_device: FakeAdbServer, message: str, code: str
) -> None:
    one_device.fail[f"host:transport:{SERIAL}"] = message
    with pytest.raises(LogprobeError) as info:
        client.events(address_of(one_device), ["logcat"])
    assert (info.value.code, info.value.message) == (code, message)
    assert info.value.details == {"serial": SERIAL}


def test_fail_on_the_shell_request_and_an_unknown_device(
    client: Client, one_device: FakeAdbServer
) -> None:
    one_device.fail[f"shell,v2,raw:{PREFIX}logcat"] = "device offline"
    address = address_of(one_device)
    with pytest.raises(LogprobeError) as info:
        client.events(address, ["logcat"])
    assert info.value.code == "device_offline"
    with pytest.raises(LogprobeError) as info:
        client.run(address, ["x"], 5, serial="ghost")
    assert (info.value.code, info.value.details) == (
        "device_not_found",
        {"serial": "ghost"},
    )


def test_features_and_the_missing_shell_v2_check(
    client: Client, one_device: FakeAdbServer
) -> None:
    address = address_of(one_device)
    features = client.features(address)
    assert isinstance(features, frozenset)
    assert features == {"shell_v2", "cmd"}
    assert one_device.requests == [f"host-serial:{SERIAL}:features"]
    client.require_shell_v2(address)
    # "stat_v2" ends in "_v2": only the exact name counts.
    one_device.features[SERIAL] = ["cmd", "stat_v2"]
    with pytest.raises(LogprobeError) as info:
        client.require_shell_v2(address)
    assert info.value.code == "adb_error"
    assert info.value.details == {"serial": SERIAL, "missing_feature": "shell_v2"}


@pytest.mark.parametrize(
    ("reply", "text"),
    [
        (b"WHAT", "invalid status"),
        *[
            (prefix + bad, "invalid length")
            for bad in BAD_LENGTHS
            for prefix in (b"OKAY", b"FAIL")
        ],
        (b"OKAY0004", "closed the connection"),
        (b"OKAY0004ab", "closed the connection"),
    ],
)
def test_a_broken_reply_is_an_adb_error(
    client: Client, reply: bytes, text: str
) -> None:
    with raw_server(reply) as (address, _), pytest.raises(LogprobeError) as info:
        client.features(address)
    assert info.value.code == "adb_error"
    assert text in str(info.value)


def test_a_packet_cut_in_the_middle_delivers_none_of_it(client: Client) -> None:
    reply = b"OKAYOKAY" + packet(1, b"ok") + packet(1, b"cut off")[:-3]
    with raw_server(reply) as (address, _):
        events, status = client.events(address, ["x"])
    assert (events, status) == ([("stdout", b"ok")], None)


@pytest.mark.parametrize(
    ("cut", "stderr"),
    [(packet(1, b"cut off")[:-3], b"err "), (packet(2, b"cut off")[:-3], b"err cut ")],
    ids=["stdout-packet", "stderr-packet"],
)
def test_a_command_without_an_exit_status_keeps_only_a_cut_stderr_part(
    client: Client, cut: bytes, stderr: bytes
) -> None:
    """As `Device.shell` says: stdout holds whole packets only, and stderr
    ends with the received part of a stderr packet that was cut off."""
    reply = b"OKAYOKAY" + packet(1, b"ok") + packet(2, b"err ") + cut
    with raw_server(reply) as (address, _):
        result = client.run(address, ["x"], 5.0)
    assert result == _adb.ShellResult(None, b"ok", stderr)


def test_an_empty_exit_packet_comes_after_the_output_and_only_once(
    client: Client,
) -> None:
    reply = b"OKAYOKAY" + packet(1, b"ok") + packet(3, b"")
    with raw_server(reply) as (address, _):
        found, status = client.reads(address)
    error = found[1]
    assert isinstance(error, LogprobeError)
    assert error.code == "adb_error"
    assert "empty exit packet" in str(error)
    assert (found[0], found[2:], status) == (("stdout", b"ok"), [None, None], None)


def test_bytes_after_the_exit_packet_are_ignored(client: Client) -> None:
    reply = b"OKAYOKAY" + packet(1, b"a") + packet(3, b"\x04") + b"junk"
    with raw_server(reply) as (address, _):
        assert client.events(address, ["x"]) == ([("stdout", b"a")], 4)


def test_a_reset_after_output_keeps_the_output_and_the_exit_status(
    client: Client,
) -> None:
    # The peer resets the connection while the client is not reading yet.
    # Whether the data survives the reset is up to the operating system;
    # Windows may discard it, so the test is skipped there.
    if sys.platform == "win32":
        pytest.skip("Windows may discard unread data when a connection is reset")
    output = packet(1, b"last line\n") + packet(3, b"\x07")
    with reset_server(output) as address:
        events, status = client.events(address, ["x"], pause=0.5)
    assert (events, status) == ([("stdout", b"last line\n")], 7)


def test_a_reset_with_no_output_and_no_exit_packet_is_the_end_of_the_stream(
    client: Client,
) -> None:
    # The server has read the stdin close packet, so only the client's receive
    # can see the reset. No output is buffered, so every operating system
    # gives the same outcome.
    with reset_server(b"") as address:
        assert client.events(address, ["x"]) == ([], None)
    with reset_server(b"") as address:
        assert client.run(address, ["x"], 30) == _adb.ShellResult(None, b"", b"")


@pytest.mark.parametrize(
    ("chunks", "receives"),
    [
        ([packet(1, b"a") + packet(3, b"\x04") + b"junk"], 1),
        ([packet(1, b"a"), packet(3, b"\x04"), b"junk"], 2),
    ],
    ids=["same_receive", "later_receive"],
)
def test_trailing_bytes_are_ignored_and_no_receive_follows_the_exit_packet(
    decoder: Client, chunks: list[bytes], receives: int
) -> None:
    # For the blocking client the later_receive case overlaps with
    # test_packets_in_separate_chunks in test_adb_protocol.py; it stays so that
    # both clients share one body.
    result = decoder.scripted(chunks)
    assert result.found == [("stdout", b"a"), None, None, None]
    assert result.exit_status == 4
    assert result.receives == receives  # none after the exit packet


@pytest.mark.parametrize(
    "chunks",
    [
        [packet(1, b"ok") + packet(3, b"")],
        [packet(1, b"ok"), packet(3, b"")],
    ],
    ids=["same_receive", "own_receive"],
)
def test_output_comes_before_an_empty_exit_packet_error_which_is_raised_once(
    decoder: Client, chunks: list[bytes]
) -> None:
    result = decoder.scripted(chunks)
    error = result.found[1]
    assert isinstance(error, LogprobeError)
    assert error.code == "adb_error"
    assert (result.found[0], result.found[2:]) == (("stdout", b"ok"), [None, None])
    assert result.exit_status is None
    assert result.receives == len(chunks)


def test_a_packet_cut_short_at_the_end_of_the_stream_delivers_none_of_it(
    client: Client,
) -> None:
    result = client.scripted([packet(1, b"ok"), packet(1, b"cut off")[:-3]])
    assert result.found == [("stdout", b"ok"), None, None, None]
    assert result.exit_status is None
    assert result.receives == 3  # the two chunks, then the end of the stream


def test_read_part_delivers_the_part_of_a_packet_cut_short_at_the_end() -> None:
    result = AsyncParts().scripted([packet(1, b"ok"), packet(1, b"cut off")[:-3]])
    assert result.found == [("stdout", b"ok"), ("stdout", b"cut "), None, None]
    assert result.exit_status is None
    assert result.receives == 3  # the two chunks, then the end of the stream


def test_a_host_reply_that_trickles_in_is_cut_at_the_timeout(
    client: Client,
) -> None:
    # One byte every 40 ms: no single wait outlasts the 0.15 s limit, but the
    # whole reply does, and the limit covers the whole exchange.
    reply = b"OKAY%04x%s" % (len(b"cmd"), b"cmd")
    with trickle_server(reply, 0.04) as address, pytest.raises(LogprobeError) as raised:
        client.features(address, timeout=0.15)
    assert raised.value.code == "adb_error"
    assert str(raised.value) == "timed out waiting for the adb server"


def test_a_host_reply_that_trickles_in_within_the_timeout_is_whole(
    client: Client,
) -> None:
    reply = b"OKAY%04x%s" % (len(b"cmd"), b"cmd")
    with trickle_server(reply, 0.04) as address:
        assert client.features(address, timeout=2.0) == {"cmd"}


def test_the_requests_on_the_wire_are_exactly_these_bytes(client: Client) -> None:
    command = PREFIX + "log -t 'a b' 'it'\"'\"'s' ''"
    reply = b"OKAYOKAY" + packet(3, b"\x00")
    with raw_server(reply) as (address, received):
        client.events(address, ["log", "-t", "a b", "it's", ""])
    transport = f"host:transport:{SERIAL}"
    shell = f"shell,v2,raw:{command}"
    assert bytes(received) == (
        b"%04x%s%04x%s"
        % (len(transport), transport.encode(), len(shell), shell.encode())
        + STDIN_CLOSED
    )


@pytest.mark.parametrize(
    ("error", "timeout"),
    [(BrokenPipeError, 30.0), (ConnectionResetError, 30.0), (TimeoutError, None)],
)
def test_a_connection_failure_sending_the_stdin_close_is_an_adb_error(
    client: Client,
    one_device: FakeAdbServer,
    monkeypatch: pytest.MonkeyPatch,
    error: type[OSError],
    timeout: float | None,
) -> None:
    # A TimeoutError of the operating system is a failed connection only
    # without a time limit on the call; with one, it is the caller's deadline.
    client.fail_stdin_close(monkeypatch, error)
    with pytest.raises(LogprobeError) as info:
        client.run(address_of(one_device), ["true"], timeout)
    assert info.value.code == "adb_error"
    assert "connection to the adb server failed" in str(info.value)


@pytest.mark.parametrize("silent_prefix", ["host:transport:", "shell,v2,raw:"])
def test_a_silent_handshake_step_times_out_and_closes(
    client: Client, one_device: FakeAdbServer, silent_prefix: str
) -> None:
    one_device.silent_prefix = silent_prefix
    with pytest.raises(LogprobeError) as info:
        client.events(address_of(one_device), ["logcat"], timeout=0.2)
    assert info.value.code == "adb_error"
    assert "timed out" in str(info.value)
    assert one_device.client_closed.wait(5)


def test_an_unreachable_server_is_adb_server_unavailable(client: Client) -> None:
    # The default address, where the server could be started: a connection
    # that fails here still says nothing about starting it.
    address = _adb.ServerAddress("127.0.0.1", free_port(), is_default=True)
    with pytest.raises(LogprobeError) as info:
        client.events(address, ["logcat"])
    assert info.value.code == "adb_server_unavailable"
    assert info.value.details["port"] == address.port
    assert info.value.details["reason"] == (
        "the adb server stopped accepting connections"
    )
    assert "auto_start_allowed" not in info.value.details


@pytest.mark.parametrize("silent_prefix", ["host:transport:", None])
def test_the_one_shot_limit_covers_handshake_and_trickling_output(
    client: Client, one_device: FakeAdbServer, silent_prefix: str | None
) -> None:
    # Either the handshake never answers, or one byte arrives every 50 ms so
    # that no single read waits long but the packet would take seconds.
    one_device.silent_prefix = silent_prefix
    one_device.shell[PREFIX + "slow"] = ShellScript(
        steps=[("stdout", b"z" * 100)], fragment=True, byte_delay=0.05
    )
    started = time.monotonic()
    with pytest.raises(TimeoutError, match=r"did not finish within 0\.4 seconds"):
        client.run(address_of(one_device), ["slow"], 0.4)
    assert time.monotonic() - started < 3
    if silent_prefix is not None:
        assert one_device.client_closed.wait(5)


# --- asyncio only ----------------------------------------------------------------


def test_a_read_cut_short_loses_and_repeats_nothing(one_device: FakeAdbServer) -> None:
    out = bytes(range(60))
    err = bytes(range(100, 130))
    one_device.shell[PREFIX + "slow"] = ShellScript(
        steps=[("stdout", out), ("stderr", err)], fragment=True, byte_delay=0.004
    )

    async def go() -> tuple[list[_adb.ShellEvent], int, int | None]:
        found: list[_adb.ShellEvent] = []
        cut = 0
        async with await _aadb.aopen_shell(
            address_of(one_device), SERIAL, ["slow"]
        ) as stream:
            while True:
                try:
                    async with asyncio.timeout(_adb.TICK / 10):
                        event = await stream.read()
                except TimeoutError:
                    cut += 1
                    continue
                if event is None:
                    break
                found.append(event)
        return found, cut, stream.exit_status

    found, cut, status = asyncio.run(go())
    assert merge(found) == {"stdout": out, "stderr": err}
    assert cut >= 2  # a packet really was split across cut-short reads
    assert status == 0


def test_a_read_cut_by_its_own_timeout_loses_and_repeats_nothing(
    one_device: FakeAdbServer,
) -> None:
    out = bytes(range(10))
    err = bytes(range(100, 105))
    # Every gap between two bytes is longer than the per-read limit.
    one_device.shell[PREFIX + "slow"] = ShellScript(
        steps=[("stdout", out), ("stderr", err)], fragment=True, byte_delay=0.03
    )

    async def go() -> tuple[list[_adb.ShellEvent], int, int | None]:
        found: list[_adb.ShellEvent] = []
        cut = 0
        async with await _aadb.aopen_shell(
            address_of(one_device), SERIAL, ["slow"]
        ) as stream:
            stream.set_timeout(0.01)
            while True:
                try:
                    event = await stream.read_part()
                except TimeoutError:
                    cut += 1
                    continue
                if event is None:
                    break
                found.append(event)
        return found, cut, stream.exit_status

    found, cut, status = asyncio.run(go())
    assert merge(found) == {"stdout": out, "stderr": err}
    assert cut >= 2
    assert status == 0


def test_close_is_idempotent_and_ends_reading(one_device: FakeAdbServer) -> None:
    async def go() -> None:
        async with await _aadb.aopen_shell(
            address_of(one_device), SERIAL, ["logcat"]
        ) as stream:
            stream.close()
            stream.close()
            assert await stream.read() is None
        stream.close()
        assert stream.exit_status is None

    asyncio.run(go())
    assert one_device.wait_idle(5)


async def until(condition: Callable[[], bool]) -> None:
    """Wait for something a thread of the fake server will do."""
    async with asyncio.timeout(5):
        while not condition():  # noqa: ASYNC110
            await asyncio.sleep(0.005)


@pytest.mark.parametrize("step", ["transport", "shell", "features", "read", "run"])
def test_cancelling_a_task_closes_its_connection(
    one_device: FakeAdbServer, step: str
) -> None:
    address = address_of(one_device)
    one_device.silent_prefix = {
        "transport": "host:transport:",
        "shell": "shell,v2,raw:",
        "features": "host-serial:",
    }.get(step)
    one_device.add_sequence(
        "logcat", ShellScript(steps=[("stdout", b"first\n"), Wait("hold")])
    )
    work: dict[str, Callable[[], Awaitable[object]]] = {
        "transport": lambda: _aadb.aopen_shell(address, SERIAL, ["logcat"]),
        "shell": lambda: _aadb.aopen_shell(address, SERIAL, ["logcat"]),
        "features": lambda: _aadb.adevice_features(address, SERIAL),
        "read": lambda: _read_all(address),
        "run": lambda: _aadb.arun_shell(address, SERIAL, ["logcat"], None),
    }

    async def go() -> None:
        task = asyncio.ensure_future(work[step]())
        if step in {"read", "run"}:
            await until(lambda: one_device.wait_reached("hold", 0))
        else:
            await until(one_device.silent_started.is_set)
        task.cancel()
        # The exception's traceback keeps the cancelled coroutines, and so
        # their connections, alive: only a close by the client can end the
        # server's side before the wait below, never garbage collection.
        with pytest.raises(asyncio.CancelledError) as caught:
            await task
        # The server is still waiting (the command is held, the handshake is
        # unanswered), so it only ends its side if the client closed first.
        if step in {"read", "run"}:
            await until(lambda: one_device.wait_done(0, 0))
        else:
            await until(one_device.client_closed.is_set)
        one_device.release("hold")
        del caught, task  # not before the server has been watched

    asyncio.run(go())
    assert one_device.wait_idle(5)


async def _read_all(address: _adb.ServerAddress) -> None:
    async with await _aadb.aopen_shell(address, SERIAL, ["logcat"]) as stream:
        while await stream.read() is not None:
            pass


def test_cancelling_while_connecting_closes_the_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    made: list[socket.socket] = []

    async def hang(sock: socket.socket, address: object) -> None:  # noqa: ARG001
        made.append(sock)
        await asyncio.Event().wait()

    address = _adb.ServerAddress("127.0.0.1", free_port(), is_default=False)

    async def go() -> None:
        monkeypatch.setattr(asyncio.get_running_loop(), "sock_connect", hang)
        task = asyncio.ensure_future(_aadb.aopen_shell(address, SERIAL, ["logcat"]))
        await until(lambda: bool(made))
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(go())
    assert [sock.fileno() for sock in made] == [-1]


@pytest.mark.parametrize("exception", [KeyboardInterrupt, SystemExit])
def test_an_interrupt_in_the_handshake_closes_the_connection(
    monkeypatch: pytest.MonkeyPatch,
    one_device: FakeAdbServer,
    exception: type[BaseException],
) -> None:
    real = _aadb._receive
    calls = 0

    async def interrupted(*args: object) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 2:  # the status of the shell request
            raise exception
        return await real(*args)  # ty: ignore[invalid-argument-type]

    monkeypatch.setattr(_aadb, "_receive", interrupted)
    # The server never answers the shell request and ends its side only when
    # the client closes.
    one_device.silent_prefix = "shell,v2,raw:"

    async def go() -> None:
        # The traceback keeps the half-open connection alive, so only a close
        # by the client can end the server's side before the wait.
        with pytest.raises(exception) as caught:
            await _aadb.aopen_shell(address_of(one_device), SERIAL, ["logcat"])
        await until(lambda: one_device.wait_idle(0))
        del caught  # not before the server has been watched

    asyncio.run(go())
    assert one_device.wait_idle(5)


def test_the_async_client_starts_no_thread(
    monkeypatch: pytest.MonkeyPatch, one_device: FakeAdbServer
) -> None:
    caller = threading.current_thread()
    started: list[str] = []
    real_start = threading.Thread.start

    def start(self: threading.Thread) -> None:
        if threading.current_thread() is caller:
            started.append(self.name)
        real_start(self)

    monkeypatch.setattr(threading.Thread, "start", start)
    address = address_of(one_device)
    Async().features(address)
    Async().events(address, ["logcat"])
    Async().run(address, ["logcat"], 5)
    with pytest.raises(LogprobeError):
        Async().events(_adb.ServerAddress("127.0.0.1", free_port(), False), ["x"])  # noqa: FBT003
    assert started == []
