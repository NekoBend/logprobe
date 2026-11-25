"""Shell protocol v2 decoding, cancellable waits and the logcat command line."""

from __future__ import annotations

import contextlib
import os
import socket
import sys
import threading
import time
from typing import TYPE_CHECKING, Any, cast

import pytest

from logprobe import LogprobeError, _adb
from logprobe._adb import protocol as adb_protocol
from logprobe._adb import sockets as adb_sockets
from tests.fake_adb_server import FakeAdbServer, ShellScript, packet
from tests.test_adb_protocol import ScriptedSocket

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

SERIAL = "emulator-5554"
TICK = _adb.TICK
# Generous margins: a cancelled wait must end within about one tick, but CI
# machines can be slow, so the bounds below allow several ticks.
LATE = TICK + 1.5


def address_of(fake: FakeAdbServer) -> _adb.ServerAddress:
    return _adb.resolve_server_address(fake.address)


@pytest.fixture
def one_device(fake: FakeAdbServer) -> FakeAdbServer:
    fake.add_device(SERIAL)
    return fake


def decode_all(chunks: list[bytes]) -> tuple[bytes, bytes, int | None]:
    decoder = _adb.ShellV2Decoder()
    out = err = b""
    status = None
    for chunk in chunks:
        o, e, s = decoder.feed(chunk)
        assert len(o) <= len(chunk)
        assert len(e) <= len(chunk)
        out += o
        err += e
        if s is not None:
            assert status is None
            status = s
    return out, err, status


STREAM = (
    packet(1, b"hello ")
    + packet(2, b"warn")
    + packet(9, b"?" * 7)
    + packet(1, b"")
    + packet(1, b"world")
    + packet(3, b"\x07")
)


# --- the decoder -----------------------------------------------------------------


def test_decoder_whole_stream_in_one_feed() -> None:
    assert _adb.ShellV2Decoder().feed(STREAM) == (b"hello world", b"warn", 7)


@pytest.mark.parametrize("cut", range(len(STREAM) + 1))
def test_decoder_under_every_two_way_split(cut: int) -> None:
    assert decode_all([STREAM[:cut], STREAM[cut:]]) == (b"hello world", b"warn", 7)


def test_decoder_byte_by_byte() -> None:
    chunks = [bytes([b]) for b in STREAM]
    assert decode_all(chunks) == (b"hello world", b"warn", 7)


@pytest.mark.parametrize("first", range(1, 14))
@pytest.mark.parametrize("second", range(1, 14))
def test_decoder_under_every_three_way_split_near_headers(
    first: int, second: int
) -> None:
    a, b = first, first + second
    assert decode_all([STREAM[:a], STREAM[a:b], STREAM[b:]]) == (
        b"hello world",
        b"warn",
        7,
    )


def test_decoder_status_arrives_only_with_the_last_byte() -> None:
    decoder = _adb.ShellV2Decoder()
    assert decoder.feed(packet(3, b"\x05")[:-1]) == (b"", b"", None)
    assert decoder.feed(packet(3, b"\x05")[-1:]) == (b"", b"", 5)


def test_decoder_exit_payload_longer_than_one_byte_uses_the_first() -> None:
    assert decode_all([packet(3, b"\x02\x09\x09")]) == (b"", b"", 2)


def test_decoder_large_payload_is_streamed_not_buffered() -> None:
    payload = bytes(range(256)) * 4096  # 1 MiB in one packet
    decoder = _adb.ShellV2Decoder()
    wire = packet(1, payload) + packet(3, b"\x00")
    received = bytearray()
    sizes = []
    for start in range(0, len(wire), 65_536):
        chunk = wire[start : start + 65_536]
        out, err, status = decoder.feed(chunk)
        assert err == b""
        assert len(out) <= len(chunk)
        sizes.append(len(out))
        received += out
        # The held state is a partial header, a kind and a length: nothing
        # that grows with the packet.
        assert len(decoder._header) <= 5
    assert bytes(received) == payload
    assert status == 0
    assert max(sizes) <= 65_536
    assert sum(1 for size in sizes if size) > 10  # delivered along the way


def test_decoder_first_chunk_of_a_huge_packet_returns_at_once() -> None:
    decoder = _adb.ShellV2Decoder()
    header = packet(1, b"x" * 1_000_000)[:5]
    assert decoder.feed(header + b"abc") == (b"abc", b"", None)
    assert decoder.feed(b"def") == (b"def", b"", None)


def test_decoder_data_after_exit_in_the_same_feed_is_an_error() -> None:
    with pytest.raises(LogprobeError) as info:
        _adb.ShellV2Decoder().feed(packet(3, b"\x00") + b"x")
    assert info.value.code == "adb_error"


def test_decoder_data_after_exit_in_a_later_feed_is_an_error() -> None:
    decoder = _adb.ShellV2Decoder()
    assert decoder.feed(packet(3, b"\x00"))[2] == 0
    assert decoder.feed(b"") == (b"", b"", None)
    with pytest.raises(LogprobeError) as info:
        decoder.feed(packet(1, b"late"))
    assert info.value.code == "adb_error"


def test_decoder_empty_exit_packet_is_an_error_at_any_split() -> None:
    wire = packet(1, b"x") + packet(3, b"")
    for cut in range(1, len(wire)):
        with pytest.raises(LogprobeError) as info:
            decode_all([wire[:cut], wire[cut:]])
        assert info.value.code == "adb_error"


def test_decoder_pieces_keep_the_order_and_mark_packet_ends() -> None:
    pieces, status, error = _adb.ShellV2Decoder().feed_pieces(STREAM)
    assert [(kind, bytes(piece), ends) for kind, piece, ends in pieces] == [
        ("stdout", b"hello ", True),
        ("stderr", b"warn", True),
        ("stdout", b"world", True),
    ]
    assert (status, error) == (7, None)


def test_decoder_pieces_of_a_split_packet_end_only_in_the_last() -> None:
    wire = packet(1, b"abcdef")
    decoder = _adb.ShellV2Decoder()
    flags = []
    for start in range(0, len(wire), 3):
        pieces, _, _ = decoder.feed_pieces(wire[start : start + 3])
        flags += [(bytes(piece), ends) for _, piece, ends in pieces]
    assert flags == [(b"a", False), (b"bcd", False), (b"ef", True)]


def test_decoder_pieces_hand_back_output_decoded_before_an_error() -> None:
    pieces, status, error = _adb.ShellV2Decoder().feed_pieces(
        packet(1, b"ok") + packet(3, b"")
    )
    assert [bytes(piece) for _, piece, _ in pieces] == [b"ok"]
    assert status is None
    assert isinstance(error, LogprobeError)
    assert error.code == "adb_error"


def test_set_deadline_none_restores_a_blocking_socket() -> None:
    class Sock(ScriptedSocket):
        timeout: float | None = None

        def settimeout(self, value: float | None) -> None:
            self.timeout = value

    stub = Sock([])
    stream = _adb.ShellStream(cast("socket.socket", stub))
    stream.set_timeout(5.0)
    stream.set_deadline(time.monotonic() + 5.0)
    stub.timeout = 1.0  # what a deadline read leaves behind
    stream.set_deadline(None)
    assert stub.timeout is None
    assert stream._timeout is None


def test_stream_delivers_a_packet_whole_however_it_arrives() -> None:
    wire = packet(1, b"abcdef") + packet(3, b"\x00")
    stub = ScriptedSocket([wire[i : i + 3] for i in range(0, len(wire), 3)])
    stream = _adb.ShellStream(cast("socket.socket", stub))
    assert stream.read() == ("stdout", b"abcdef")
    assert stream.read() is None


# --- logcat_argv ------------------------------------------------------------------

FORMAT = ["-v", "threadtime", "-v", "year", "-v", "usec", "-v", "zone", "-v", "uid"]


def test_logcat_argv_live() -> None:
    assert _adb.logcat_argv(dump=False, tail=None, t=None) == ["logcat", *FORMAT]


def test_logcat_argv_dump_tail_and_time() -> None:
    assert _adb.logcat_argv(dump=True, tail=None, t=None) == ["logcat", *FORMAT, "-d"]
    assert _adb.logcat_argv(dump=True, tail=50, t=None) == [
        "logcat",
        *FORMAT,
        "-d",
        "-t",
        "50",
    ]
    assert _adb.logcat_argv(dump=False, tail=None, t="1700000000.123") == [
        "logcat",
        *FORMAT,
        "-T",
        "1700000000.123",
    ]


@pytest.mark.parametrize(
    "bad", ["1700000000", "", ".5", "1.", "1e9.0", "1.2.3", "-1.5", " 1.5", "1.5\n"]
)
def test_logcat_argv_rejects_t_that_is_not_an_epoch_with_a_dot(bad: str) -> None:
    with pytest.raises(ValueError, match="decimal point"):
        _adb.logcat_argv(dump=False, tail=None, t=bad)


@pytest.mark.parametrize("bad", [0, -3])
def test_logcat_argv_rejects_a_tail_below_one(bad: int) -> None:
    with pytest.raises(ValueError, match="at least 1"):
        _adb.logcat_argv(dump=True, tail=bad, t=None)


def test_logcat_argv_rejects_wrong_types() -> None:
    bad: Any = object()
    with pytest.raises(TypeError):
        _adb.logcat_argv(dump=True, tail=True, t=None)
    with pytest.raises(TypeError):
        _adb.logcat_argv(dump=True, tail=bad, t=None)
    with pytest.raises(TypeError):
        _adb.logcat_argv(dump=True, tail=None, t=bad)
    with pytest.raises(TypeError):
        _adb.logcat_argv(dump=bad, tail=None, t=None)


def test_logcat_argv_builds_a_valid_device_command() -> None:
    command = _adb.device_command(_adb.logcat_argv(dump=True, tail=5, t="1.5"))
    assert command.endswith(
        "exec logcat -v threadtime -v year -v usec -v zone -v uid -d -t 5 -T 1.5"
    )


# --- cancellation -----------------------------------------------------------------


class Flag:
    """A cancel callback that turns true ``delay`` seconds after creation."""

    def __init__(self, delay: float) -> None:
        self.at = time.monotonic() + delay
        self.polls = 0
        self.fired_at: float | None = None

    def __call__(self) -> bool:
        self.polls += 1
        if time.monotonic() >= self.at:
            if self.fired_at is None:
                self.fired_at = time.monotonic()
            return True
        return False

    def lateness(self) -> float:
        """Seconds from the moment the flag became true to now."""
        return time.monotonic() - self.at


def never() -> bool:
    return False


class MuteServer:
    """A server that accepts the handshake and then never sends a byte."""

    def __init__(self, address: _adb.ServerAddress) -> None:
        self.address = address
        self.client_closed = threading.Event()


@pytest.fixture
def mute_after_okay() -> Generator[MuteServer]:
    listener = socket.create_server(("127.0.0.1", 0))
    address = _adb.ServerAddress(
        "127.0.0.1", listener.getsockname()[1], is_default=False
    )
    server = MuteServer(address)

    def read_exact(conn: socket.socket, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = conn.recv(size - len(data))
            if not chunk:
                raise OSError("client closed")
            data += chunk
        return data

    def serve() -> None:
        # A test that fails before connecting must not leave this thread
        # blocked in accept().
        listener.settimeout(5)
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(10)
            with contextlib.suppress(OSError):
                for _ in range(2):
                    size = int(read_exact(conn, 4), 16)
                    read_exact(conn, size)
                    conn.sendall(b"OKAY")
                while conn.recv(100):
                    pass
        server.client_closed.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        thread.join(timeout=12)
        listener.close()


def test_cancel_during_a_silent_host_query(one_device: FakeAdbServer) -> None:
    one_device.silent = True
    flag = Flag(0.3)
    with pytest.raises(_adb.Cancelled):
        _adb.host_query(address_of(one_device), "host:version", cancelled=flag)
    assert flag.lateness() < LATE
    assert one_device.client_closed.wait(5)  # the call closed its socket


def test_cancel_during_device_features(one_device: FakeAdbServer) -> None:
    one_device.silent = True
    flag = Flag(0.2)
    with pytest.raises(_adb.Cancelled):
        _adb.device_features(address_of(one_device), SERIAL, cancelled=flag)
    assert flag.lateness() < LATE
    assert one_device.client_closed.wait(5)


@pytest.mark.parametrize("silent_prefix", ["host:transport:", "shell,v2,raw:"])
def test_cancel_during_the_open_shell_handshake(
    one_device: FakeAdbServer, silent_prefix: str
) -> None:
    one_device.silent_prefix = silent_prefix
    flag = Flag(0.3)
    with pytest.raises(_adb.Cancelled):
        _adb.open_shell(address_of(one_device), SERIAL, ["logcat"], cancelled=flag)
    assert flag.lateness() < LATE
    assert one_device.client_closed.wait(5)


def test_cancel_during_run_shell_while_the_command_is_silent(
    mute_after_okay: MuteServer,
) -> None:
    flag = Flag(0.3)
    started = time.monotonic()
    with pytest.raises(_adb.Cancelled):
        _adb.run_shell(
            mute_after_okay.address, SERIAL, ["sleep", "99"], None, cancelled=flag
        )
    assert flag.lateness() < LATE
    assert time.monotonic() - started >= 0.25
    assert mute_after_okay.client_closed.wait(5)


def test_cancel_during_stream_read_closes_the_stream(
    mute_after_okay: MuteServer,
) -> None:
    stream = _adb.open_shell(mute_after_okay.address, SERIAL, ["logcat"])
    flag = Flag(0.3)
    with pytest.raises(_adb.Cancelled):
        stream.read(flag)
    assert flag.lateness() < LATE
    assert stream._closed
    assert stream.read() is None  # closed: the end, no new wait
    assert mute_after_okay.client_closed.wait(5)


def test_cancel_before_connecting_raises_at_once() -> None:
    address = _adb.ServerAddress("127.0.0.1", 9, is_default=False)
    with pytest.raises(_adb.Cancelled):
        _adb.connect(address, cancelled=lambda: True)


def test_cancel_while_connecting_to_a_server_that_never_accepts() -> None:
    # A listener whose backlog is full leaves further connections pending.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(0)
    port = listener.getsockname()[1]
    fillers = []
    try:
        for _ in range(8):
            filler = socket.socket()
            filler.settimeout(0.0)
            filler.connect_ex(("127.0.0.1", port))
            fillers.append(filler)
        address = _adb.ServerAddress("127.0.0.1", port, is_default=False)
        flag = Flag(0.3)
        try:
            sock = _adb.connect(address, 5.0, cancelled=flag)
        except _adb.Cancelled:
            assert flag.lateness() < LATE
        else:  # this platform still completed the handshake in the kernel
            sock.close()
            pytest.skip("the kernel accepted the connection despite a full backlog")
    finally:
        for filler in fillers:
            filler.close()
        listener.close()


def test_connect_with_a_callback_that_stays_false_connects(
    one_device: FakeAdbServer,
) -> None:
    sock = _adb.connect(address_of(one_device), cancelled=never)
    try:
        assert sock.gettimeout() == _adb.DEFAULT_TIMEOUT
    finally:
        sock.close()


def test_a_callback_that_stays_false_changes_no_result(
    one_device: FakeAdbServer,
) -> None:
    key = 'export ANDROID_LOG_TAGS=""; exec getprop ro.x'
    one_device.shell[key] = ShellScript(
        steps=[("stdout", b"val"), ("stderr", b"e"), ("stdout", b"ue\n")],
        exit_status=0,
        fragment=True,
    )
    one_device.features[SERIAL] = ["shell_v2"]
    address = address_of(one_device)
    result = _adb.run_shell(address, SERIAL, ["getprop", "ro.x"], 5, cancelled=never)
    assert result == _adb.ShellResult(0, b"value\n", b"e")
    assert _adb.device_features(address, SERIAL, cancelled=never) == {"shell_v2"}
    assert _adb.host_query(address, "host:version", cancelled=never) == b"0029"


def test_cancel_flag_is_asked_about_every_tick_not_more_often_than_needed(
    one_device: FakeAdbServer,
) -> None:
    one_device.silent = True
    flag = Flag(0.6)
    with pytest.raises(_adb.Cancelled):
        _adb.host_query(address_of(one_device), "host:version", cancelled=flag)
    # About 0.6 s at one poll per quarter second; a busy loop would poll far more.
    assert 2 <= flag.polls <= 12


def test_deadline_wins_when_it_comes_before_cancellation(
    one_device: FakeAdbServer,
) -> None:
    one_device.silent_prefix = "host:transport:"
    flag = Flag(5.0)
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="did not finish"):
        _adb.run_shell(address_of(one_device), SERIAL, ["x"], 0.4, cancelled=flag)
    assert time.monotonic() - started < 0.4 + LATE
    assert flag.fired_at is None
    assert one_device.client_closed.wait(5)


def test_cancellation_wins_when_it_comes_before_the_deadline(
    one_device: FakeAdbServer,
) -> None:
    one_device.silent_prefix = "host:transport:"
    flag = Flag(0.2)
    with pytest.raises(_adb.Cancelled):
        _adb.run_shell(address_of(one_device), SERIAL, ["x"], 30.0, cancelled=flag)
    assert flag.lateness() < LATE
    assert one_device.client_closed.wait(5)


def test_deadline_applies_to_stream_reads_with_a_callback(
    mute_after_okay: MuteServer,
) -> None:
    stream = _adb.open_shell(mute_after_okay.address, SERIAL, ["logcat"])
    stream.set_deadline(time.monotonic() + 0.4)
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            stream.read(never)
    finally:
        stream.close()
    assert time.monotonic() - started < 0.4 + LATE


def test_handshake_timeout_without_deadline_stays_an_adb_error(
    one_device: FakeAdbServer,
) -> None:
    one_device.silent = True
    with pytest.raises(LogprobeError) as info:
        _adb.host_query(
            address_of(one_device), "host:version", timeout=0.4, cancelled=never
        )
    assert info.value.code == "adb_error"
    assert "timed out" in str(info.value)
    assert one_device.client_closed.wait(5)


def test_stream_timeout_still_applies_with_a_callback(
    mute_after_okay: MuteServer,
) -> None:
    stream = _adb.open_shell(mute_after_okay.address, SERIAL, ["logcat"])
    stream.set_timeout(0.4)
    try:
        with pytest.raises(TimeoutError):
            stream.read(never)
    finally:
        stream.close()


def test_stream_reads_data_that_trickles_in_with_a_callback(
    one_device: FakeAdbServer,
) -> None:
    one_device.shell['export ANDROID_LOG_TAGS=""; exec logcat'] = ShellScript(
        steps=[("stdout", b"abc")], fragment=True, byte_delay=0.01
    )
    with _adb.open_shell(address_of(one_device), SERIAL, ["logcat"]) as stream:
        events = []
        while (event := stream.read(never)) is not None:
            events.append(event)
    assert b"".join(data for _, data in events) == b"abc"
    assert stream.exit_status == 0


# --- sockets are closed by the thread that owns them ---------------------------


class RecordingSocket:
    """A socket stand-in that notes which thread calls each method.

    ``recv`` honors the timeout like a real socket: it waits for it and raises
    ``TimeoutError``.
    """

    def __init__(self) -> None:
        self.timeout: float | None = None
        self.timeouts: list[float | None] = []
        self.calls: list[tuple[str, int]] = []

    def _note(self, name: str) -> None:
        self.calls.append((name, threading.get_ident()))

    def settimeout(self, value: float | None) -> None:
        self.timeout = value
        self.timeouts.append(value)

    def recv(self, _size: int) -> bytes:
        self._note("recv")
        time.sleep(self.timeout or 0.0)
        raise TimeoutError

    def shutdown(self, _how: int) -> None:
        self._note("shutdown")

    def close(self) -> None:
        self._note("close")


def test_the_reading_thread_closes_its_own_socket() -> None:
    stub = RecordingSocket()
    stream = _adb.ShellStream(cast("socket.socket", stub))
    stop = threading.Event()
    outcome: list[BaseException] = []
    owner: list[int] = []

    def reader() -> None:
        owner.append(threading.get_ident())
        try:
            stream.read(stop.is_set)
        except BaseException as error:  # noqa: BLE001 - recorded for the test
            outcome.append(error)

    thread = threading.Thread(target=reader)
    thread.start()
    time.sleep(0.3)
    stop.set()  # the only thing another thread does
    thread.join(5)
    assert not thread.is_alive()
    assert len(outcome) == 1
    assert isinstance(outcome[0], _adb.Cancelled)
    closing = [(name, ident) for name, ident in stub.calls if name != "recv"]
    assert closing
    assert {ident for _, ident in closing} == {owner[0]}
    assert [name for name, _ in closing].count("close") == 1
    assert max(stub.timeout or 0, TICK) <= TICK  # every wait was one slice


def test_every_slice_is_at_most_one_tick() -> None:
    stub = RecordingSocket()
    stream = _adb.ShellStream(cast("socket.socket", stub))
    flag = Flag(0.6)
    with pytest.raises(_adb.Cancelled):
        stream.read(flag)
    assert stub.timeouts
    assert all(value is not None and 0 < value <= TICK for value in stub.timeouts)


def test_socket_closed_by_the_owner_when_a_handshake_is_cancelled(
    one_device: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    one_device.silent = True
    # Only the client's socket counts: the fake server's own threads close
    # their sockets too, at times of their own.
    client_sockets: set[socket.socket] = set()
    closers: list[int] = []
    real_open = _adb._open_numeric
    real_close = socket.socket.close

    def recording_open(
        address: _adb.ServerAddress,
        timeout: float,
        cancelled: Callable[[], bool] | None = None,
    ) -> socket.socket:
        sock = real_open(address, timeout, cancelled)
        client_sockets.add(sock)
        return sock

    def recording_close(self: socket.socket) -> None:
        if self in client_sockets:
            closers.append(threading.get_ident())
        real_close(self)

    monkeypatch.setattr(adb_sockets, "_open_numeric", recording_open)
    monkeypatch.setattr(adb_protocol, "_open_numeric", recording_open)
    monkeypatch.setattr(socket.socket, "close", recording_close)
    flag = Flag(0.2)
    with pytest.raises(_adb.Cancelled):
        _adb.run_shell(address_of(one_device), SERIAL, ["x"], None, cancelled=flag)
    assert len(client_sockets) == 1
    assert closers == [threading.get_ident()]


# --- the connect phase ------------------------------------------------------------


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_refused_connection_with_a_callback_is_adb_server_unavailable() -> None:
    address = _adb.ServerAddress("127.0.0.1", free_port(), is_default=False)
    # Windows retries a refused connection for about two seconds before it
    # reports the refusal, so the limit must be well above that.
    with pytest.raises(LogprobeError) as info:
        _adb.connect(address, 10.0, cancelled=never)
    assert info.value.code == "adb_server_unavailable"
    assert isinstance(info.value.__cause__, ConnectionRefusedError)


def test_connect_waits_in_slices_of_at_most_one_tick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[float] = []

    def fake_wait(_sock: socket.socket, seconds: float) -> bool:
        seen.append(seconds)
        return False

    monkeypatch.setattr(adb_sockets, "_wait_writable", fake_wait)
    # A non-routable address keeps the attempt pending; skip if refused at once.
    address = _adb.ServerAddress("10.255.255.1", 5037, is_default=False)
    flag = Flag(0.2)
    with contextlib.suppress(_adb.Cancelled, LogprobeError):
        _adb.connect(address, 30.0, cancelled=lambda: bool(seen) and flag())
    if not seen:
        pytest.skip("the connection did not stay pending on this host")
    assert all(0 < value <= TICK for value in seen)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX descriptor numbers")
def test_connect_with_a_callback_works_above_descriptor_1024(
    one_device: FakeAdbServer,
) -> None:
    if sys.platform == "win32":
        pytest.skip("the resource module and the 1024 limit are POSIX only")
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    wanted = 1300
    if hard != resource.RLIM_INFINITY and hard < wanted:
        pytest.skip("the descriptor limit is too low")
    if soft != resource.RLIM_INFINITY and soft < wanted:
        resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
    held: list[int] = []
    try:
        while True:
            fd = os.open(os.devnull, os.O_RDONLY)
            held.append(fd)
            if fd >= 1100:
                break
        sock = _adb.connect(address_of(one_device), 5.0, cancelled=never)
        try:
            assert sock.fileno() >= 1024
        finally:
            sock.close()
    finally:
        for fd in held:
            os.close(fd)
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


def test_an_unexpected_exception_while_connecting_closes_the_socket(
    one_device: FakeAdbServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[socket.socket] = []

    def interrupted(sock: socket.socket, *_rest: object) -> None:
        opened.append(sock)
        raise KeyboardInterrupt

    monkeypatch.setattr(adb_sockets, "_connect_sliced", interrupted)
    with pytest.raises(KeyboardInterrupt):
        _adb.connect(address_of(one_device), 5.0, cancelled=never)
    assert len(opened) == 1
    assert opened[0].fileno() == -1


def test_exit_status_stays_none_until_read_returns_none() -> None:
    wire = packet(1, b"out") + packet(2, b"err") + packet(3, b"\x00")
    stream = _adb.ShellStream(cast("socket.socket", ScriptedSocket([wire])))
    assert stream.read() == ("stdout", b"out")
    assert stream.exit_status is None
    assert stream.read() == ("stderr", b"err")
    assert stream.exit_status is None
    assert stream.read() is None
    assert stream.exit_status == 0
