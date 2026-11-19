"""Wire protocol, FAIL mapping, shell v2 decoding and request validation."""

from __future__ import annotations

import contextlib
import socket
import threading
import time
from typing import TYPE_CHECKING, cast

import pytest

from logprobe import LogprobeError, _adb
from tests.fake_adb_server import BAD_LENGTHS, FakeAdbServer, ShellScript, packet

if TYPE_CHECKING:
    from collections.abc import Generator, Sequence

SERIAL = "emulator-5554"
PREFIX = 'export ANDROID_LOG_TAGS=""; exec '


def address_of(fake: FakeAdbServer) -> _adb.ServerAddress:
    return _adb.resolve_server_address(fake.address)


@contextlib.contextmanager
def raw_server(reply: bytes) -> Generator[_adb.ServerAddress]:
    """A one-shot server that reads one request, sends ``reply`` and hangs up."""
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(5)  # a client that never connects cannot hang the test run

    def serve() -> None:
        conn, _ = listener.accept()
        with conn:
            size = int(conn.recv(4), 16)
            conn.recv(size)
            conn.sendall(reply)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        yield _adb.ServerAddress(
            "127.0.0.1", listener.getsockname()[1], is_default=False
        )
    finally:
        # Longer than the listener's 5 s, so that a client that never
        # connects fails this test and not a later one.
        thread.join(timeout=10)
        listener.close()


@pytest.fixture
def one_device(fake: FakeAdbServer) -> FakeAdbServer:
    fake.add_device(SERIAL)
    return fake


# --- framing and simple queries ---------------------------------------------


def test_request_is_hex_length_then_payload() -> None:
    assert _adb.encode_request("host:version") == b"000chost:version"


def test_request_length_counts_bytes_not_characters() -> None:
    assert _adb.encode_request("é") == b"0002\xc3\xa9"


def test_oversized_request_is_rejected() -> None:
    with pytest.raises(ValueError, match="too long"):
        _adb.encode_request("x" * 0x10000)


def test_server_version(fake: FakeAdbServer) -> None:
    fake.version = 0x29
    assert _adb.server_version(address_of(fake)) == 41
    assert fake.requests == ["host:version"]


def test_device_list_parses_state_and_key_values(fake: FakeAdbServer) -> None:
    fake.add_device(
        "R58M1234",
        "device",
        product="beyond1",
        model="SM_G973F",
        device="beyond1",
        transport_id="3",
    )
    fake.add_device("emulator-5554", "offline")
    fake.add_device("XYZ", "unauthorized", transport_id="7")
    assert _adb.list_devices(address_of(fake)) == [
        _adb.DeviceInfo("R58M1234", "device", "SM_G973F", "beyond1", "beyond1", "3"),
        _adb.DeviceInfo("emulator-5554", "offline"),
        _adb.DeviceInfo("XYZ", "unauthorized", transport_id="7"),
    ]
    assert fake.requests == ["host:devices-l"]


def test_parse_plain_line_with_all_properties() -> None:
    text = "emulator-5554 device product:x model:y device:z transport_id:1\n"
    assert _adb.parse_devices(text) == [
        _adb.DeviceInfo("emulator-5554", "device", "y", "x", "z", "1")
    ]


def test_parse_state_with_spaces_and_extra_properties() -> None:
    text = (
        "0123456789ABCDEF       no permissions (user in plugdev group; "
        "are your udev rules wrong?); see "
        "[http://developer.android.com/tools/device.html] usb:1-4 transport_id:2\n"
    )
    assert _adb.parse_devices(text) == [
        _adb.DeviceInfo(
            "0123456789ABCDEF",
            "no permissions (user in plugdev group; are your udev rules wrong?); "
            "see [http://developer.android.com/tools/device.html]",
            transport_id="2",
        )
    ]


def test_parse_no_serial_number() -> None:
    text = (
        "(no serial number)     no permissions (user in plugdev group; "
        "are your udev rules wrong?); see "
        "[http://developer.android.com/tools/device.html] usb:1-4 transport_id:2\n"
        "(no serial number)  offline\n"
    )
    assert _adb.parse_devices(text) == [
        _adb.DeviceInfo(
            "(no serial number)",
            "no permissions (user in plugdev group; are your udev rules wrong?); "
            "see [http://developer.android.com/tools/device.html]",
            transport_id="2",
        ),
        _adb.DeviceInfo("(no serial number)", "offline"),
    ]


def test_parse_skips_blank_and_serial_only_lines() -> None:
    assert _adb.parse_devices("\n   \nlonely\n") == []


def test_parse_skips_a_serial_that_no_request_can_carry() -> None:
    # A NUL character, bytes that were not UTF-8 (decoded as U+FFFD) and a
    # serial too long for the features request; the other lines still count.
    longest = "s" * (0xFFFF - len("host-serial::features"))
    text = (
        "a\0b device product:x\n"
        "bad\ufffdname device\n"
        f"{longest}x device\n"
        f"{longest} device\n"
        "emulator-5554 device\n"
    )
    assert _adb.parse_devices(text) == [
        _adb.DeviceInfo(longest, "device"),
        _adb.DeviceInfo("emulator-5554", "device"),
    ]
    # The longest kept serial still fits the request.
    _adb.encode_request(_adb.features_request(longest))


def test_device_info_is_frozen() -> None:
    info = _adb.DeviceInfo("a", "device")
    with pytest.raises(AttributeError):
        info.state = "offline"  # ty: ignore[invalid-assignment]


def test_empty_device_list(fake: FakeAdbServer) -> None:
    assert _adb.list_devices(address_of(fake)) == []


# --- strict length fields -----------------------------------------------------


def test_uppercase_hex_length_is_accepted() -> None:
    with raw_server(b"OKAY000A" + b"0123456789") as address:
        assert _adb.host_query(address, "host:version") == b"0123456789"


@pytest.mark.parametrize("bad", BAD_LENGTHS)
def test_invalid_version_is_a_protocol_error(bad: bytes) -> None:
    with raw_server(b"OKAY0004" + bad) as address, pytest.raises(LogprobeError) as info:
        _adb.server_version(address)
    assert info.value.code == "adb_error"
    assert "invalid version" in str(info.value)


def test_version_must_be_exactly_four_digits() -> None:
    with raw_server(b"OKAY00050001a") as address, pytest.raises(LogprobeError) as info:
        _adb.server_version(address)
    assert info.value.code == "adb_error"


# --- FAIL mapping -------------------------------------------------------------


@pytest.mark.parametrize(
    ("message", "code"),
    [
        ("device 'emulator-5554' not found", "device_not_found"),
        ("device offline", "device_offline"),
        (
            "device unauthorized.\nThis adbd's $ADB_VENDOR_KEYS is not set",
            "device_unauthorized",
        ),
        ("closed", "adb_error"),
        ("unknown host service", "adb_error"),
    ],
)
def test_fail_replies_map_to_codes(
    one_device: FakeAdbServer, message: str, code: str
) -> None:
    one_device.fail[f"host-serial:{SERIAL}:features"] = message
    with pytest.raises(LogprobeError) as info:
        _adb.device_features(address_of(one_device), SERIAL)
    assert info.value.code == code
    assert info.value.message == message
    assert info.value.details == {"serial": SERIAL}


def test_handshake_timeout_closes_the_socket(fake: FakeAdbServer) -> None:
    fake.silent = True
    with pytest.raises(LogprobeError) as info:
        _adb.host_query(address_of(fake), "host:version", timeout=0.2)
    assert info.value.code == "adb_error"
    assert "timed out" in str(info.value)
    assert fake.client_closed.wait(5)


# --- request validation --------------------------------------------------------


@pytest.mark.parametrize("bad", ["a\0b", "a\nb", "a\rb", ""])
def test_bad_serials_are_rejected_before_any_connection(
    fake: FakeAdbServer, bad: str
) -> None:
    with pytest.raises(ValueError, match="serial"):
        _adb.device_features(address_of(fake), bad)
    with pytest.raises(ValueError, match="serial"):
        _adb.open_shell(address_of(fake), bad, ["logcat"])
    assert fake.requests == []


def test_non_string_serial_is_type_error(fake: FakeAdbServer) -> None:
    with pytest.raises(TypeError):
        _adb.device_features(address_of(fake), 5)  # ty: ignore[invalid-argument-type]


@pytest.mark.parametrize("bad", ["a\0b", "a\nb"])
def test_bad_shell_arguments_are_rejected(one_device: FakeAdbServer, bad: str) -> None:
    with pytest.raises(ValueError, match="argument"):
        _adb.open_shell(address_of(one_device), SERIAL, ["logcat", bad])
    assert one_device.requests == []


def test_empty_args_and_string_args_are_rejected() -> None:
    with pytest.raises(ValueError, match="empty"):
        _adb.device_command([])
    with pytest.raises(TypeError):
        _adb.device_command("logcat")
    with pytest.raises(ValueError, match="program"):
        _adb.device_command(["", "x"])


# --- device_command ------------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "tail"),
    [
        (["logcat"], "logcat"),
        (["logcat", "-b", "main,system"], "logcat -b main,system"),
        (["echo", "a b"], "echo 'a b'"),
        (["echo", "it's"], "echo 'it'\"'\"'s'"),
        (["echo", "$HOME", "`id`", '"q"'], "echo '$HOME' '`id`' '\"q\"'"),
        (["echo", ""], "echo ''"),
        (["echo", "a;b|c&d"], "echo 'a;b|c&d'"),
    ],
)
def test_device_command_quotes_arguments(args: Sequence[str], tail: str) -> None:
    assert _adb.device_command(args) == PREFIX + tail


# --- shell v2 decoding ---------------------------------------------------------


class ScriptedSocket:
    """A socket stand-in whose recv() returns the scripted chunks, one per call.

    Unlike a socketpair, nothing is buffered or merged by the kernel, so each
    chunk really reaches the decoder as its own recv() result. After the
    script is used up, recv() returns ``b""`` (end of stream).
    """

    def __init__(self, chunks: Sequence[bytes]) -> None:
        self._chunks = list(chunks)
        self.recv_calls = 0

    def recv(self, size: int) -> bytes:
        self.recv_calls += 1
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if len(chunk) > size:  # a real recv() never returns more than asked
            self._chunks.insert(0, chunk[size:])
            chunk = chunk[:size]
        return chunk

    def settimeout(self, value: float | None) -> None:
        pass

    def shutdown(self, how: int) -> None:
        pass

    def close(self) -> None:
        pass


def make_stream(
    chunks: Sequence[bytes],
) -> tuple[_adb.ShellStream, ScriptedSocket]:
    """A ShellStream fed exactly these recv() chunks, then end of stream."""
    stub = ScriptedSocket(chunks)
    return _adb.ShellStream(cast("socket.socket", stub)), stub


def drain(stream: _adb.ShellStream) -> list[_adb.ShellEvent]:
    events = []
    while (event := stream.read()) is not None:
        events.append(event)
    return events


STREAM = (
    packet(1, b"hello ") + packet(2, b"warn") + packet(1, b"world") + packet(3, b"\x07")
)


def merge(events: list[_adb.ShellEvent]) -> dict[str, bytes]:
    merged = {"stdout": b"", "stderr": b""}
    for kind, data in events:
        merged[kind] += data
    return merged


def test_packets_in_separate_chunks() -> None:
    stream, stub = make_stream([packet(1, b"a"), packet(2, b"b"), packet(3, b"\x00")])
    assert drain(stream) == [("stdout", b"a"), ("stderr", b"b")]
    assert stream.exit_status == 0
    assert stub.recv_calls == 3


def test_several_packets_in_one_chunk() -> None:
    stream, stub = make_stream([STREAM])
    assert drain(stream) == [
        ("stdout", b"hello "),
        ("stderr", b"warn"),
        ("stdout", b"world"),
    ]
    assert stream.exit_status == 7
    assert stub.recv_calls == 1


def test_packets_split_byte_by_byte() -> None:
    stream, stub = make_stream([bytes([b]) for b in STREAM])
    assert merge(drain(stream)) == {"stdout": b"hello world", "stderr": b"warn"}
    assert stream.exit_status == 7
    assert stub.recv_calls == len(STREAM)  # one recv() per byte, none extra


@pytest.mark.parametrize("cut", range(1, len(STREAM)))
def test_packets_split_at_every_offset(cut: int) -> None:
    stream, stub = make_stream([STREAM[:cut], STREAM[cut:]])
    assert merge(drain(stream)) == {"stdout": b"hello world", "stderr": b"warn"}
    assert stream.exit_status == 7
    assert stub.recv_calls == 2


def test_large_payload_spanning_many_recvs() -> None:
    payload = bytes(range(256)) * 480  # 120 KiB
    stream, stub = make_stream(
        [packet(1, payload[:60_000]), packet(1, payload[60_000:]), packet(3, b"\x00")]
    )
    assert b"".join(data for _, data in drain(stream)) == payload
    assert stream.exit_status == 0
    assert stub.recv_calls == 3


def test_one_packet_larger_than_the_receive_size() -> None:
    payload = bytes(range(256)) * 1000  # 250 KiB in a single packet
    stream, stub = make_stream([packet(1, payload) + packet(3, b"\x00")])
    assert b"".join(data for _, data in drain(stream)) == payload
    # The stub honors the requested size, so the packet needs several recv() calls.
    assert stub.recv_calls > 1


def test_dropped_connection_has_no_exit_status() -> None:
    stream, stub = make_stream([packet(1, b"partial")])
    assert drain(stream) == [("stdout", b"partial")]
    assert stream.exit_status is None
    assert stub.recv_calls == 2  # the data, then the end of stream


def test_nonzero_exit_status_and_ignored_packets() -> None:
    stream, _ = make_stream(
        [packet(5, b"\0" * 16), packet(1, b""), packet(1, b"x"), packet(3, b"\xff")]
    )
    assert drain(stream) == [("stdout", b"x")]
    assert stream.exit_status == 255


def test_read_after_end_keeps_returning_none_and_close_is_idempotent() -> None:
    stream, _ = make_stream([packet(3, b"\x00")])
    assert stream.read() is None
    assert stream.read() is None
    stream.close()
    stream.close()
    assert stream.exit_status == 0


def test_close_before_reading_is_safe_and_idempotent() -> None:
    stream, stub = make_stream([packet(1, b"unread")])
    stream.close()
    stream.close()
    assert stream.read() is None
    assert stream.exit_status is None
    assert stub.recv_calls == 0


# --- shell over the fake server ---------------------------------------------------


def test_open_shell_removes_the_handshake_timeout(one_device: FakeAdbServer) -> None:
    stream = _adb.open_shell(address_of(one_device), SERIAL, ["logcat"], timeout=3.0)
    try:
        assert stream._sock.gettimeout() is None
    finally:
        stream.close()


def test_open_shell_deadline_in_the_handshake_is_a_timeout_error(
    one_device: FakeAdbServer,
) -> None:
    one_device.silent_prefix = "shell,v2,raw:"
    deadline = time.monotonic() + 0.3
    with pytest.raises(TimeoutError):
        _adb.open_shell(address_of(one_device), SERIAL, ["logcat"], deadline=deadline)
    assert one_device.client_closed.wait(5)


def test_run_shell_times_out_when_the_command_never_ends() -> None:
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(5)  # a client that never connects cannot hang the test run
    release = threading.Event()

    def serve() -> None:
        conn, _ = listener.accept()
        with conn:
            for _ in range(2):  # transport request, then shell request
                size = int(conn.recv(4), 16)
                conn.recv(size)
                conn.sendall(b"OKAY")
            release.wait(5)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        address = _adb.ServerAddress(
            "127.0.0.1", listener.getsockname()[1], is_default=False
        )
        with pytest.raises(TimeoutError):
            _adb.run_shell(address, SERIAL, ["sleep", "99"], 0.3)
    finally:
        release.set()
        # Longer than the listener's 5 s, so that a client that never
        # connects fails this test and not a later one.
        thread.join(timeout=10)
        listener.close()


def test_run_shell_without_timeout_waits_for_the_output(
    one_device: FakeAdbServer,
) -> None:
    one_device.shell[PREFIX + "slow"] = ShellScript(
        steps=[("stdout", b"abc")], fragment=True, byte_delay=0.05
    )
    result = _adb.run_shell(address_of(one_device), SERIAL, ["slow"], None)
    assert result == _adb.ShellResult(0, b"abc", b"")
