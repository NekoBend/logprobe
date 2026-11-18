"""A scriptable fake adb server for tests (smart-socket protocol, 127.0.0.1 only)."""

from __future__ import annotations

import contextlib
import queue
import select
import shlex
import socket
import socketserver
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, cast

if TYPE_CHECKING:
    from collections.abc import Callable

Output = tuple[Literal["stdout", "stderr"], bytes]

_ENV_PREFIX = 'export ANDROID_LOG_TAGS=""; exec '
_PACKET_ID = {"stdout": 1, "stderr": 2}
_HEADER_SIZE = 5


@dataclass(frozen=True)
class Wait:
    """A waiting point: the script stops here until the test releases ``name``.

    The test calls :meth:`FakeAdbServer.wait_reached` to know the connection
    got here and :meth:`FakeAdbServer.release` to let it go on. A release that
    comes before the connection arrives is remembered. With ``live`` the
    connection keeps forwarding lines given to :meth:`FakeAdbServer.inject`
    while it waits, like a running ``logcat`` that gets new lines.

    A name is single-use: it gates the first connection that reaches it. A
    second connection reaching the same name is not held and is recorded in
    :attr:`FakeAdbServer.violations`; use a new name for every waiting point.
    """

    name: str
    live: bool = False


@dataclass(frozen=True)
class Omit:
    """Lines the device wrote but this connection never delivers.

    Nothing is sent; the bytes are recorded in
    :attr:`ConnectionRecord.omitted`, so a test can subtract them from what it
    expects to receive.
    """

    data: bytes


@dataclass(frozen=True)
class Cut:
    """Send only the first ``keep`` bytes of one packet, then drop the connection.

    ``keep`` counts the encoded packet, so a value below 5 cuts inside the
    packet header, a larger one cuts inside the payload. A payload that does
    not end in a newline cuts in the middle of a line. The undelivered rest
    of the payload is recorded in :attr:`ConnectionRecord.lost`. ``keep`` must
    be at least 0 and less than the packet size, otherwise nothing is cut.
    With ``hold`` the connection stays open after the cut part, at a waiting
    point of that name (as a :class:`Wait`), and is dropped only after it.
    """

    kind: Literal["stdout", "stderr"]
    data: bytes
    keep: int
    hold: str | None = None

    def __post_init__(self) -> None:
        size = _HEADER_SIZE + len(self.data)
        if not 0 <= self.keep < size:
            msg = f"keep must be in [0, {size}) for this packet, got {self.keep}"
            raise ValueError(msg)


Step = Output | Wait | Omit | Cut


@dataclass
class ShellScript:
    """What a shell command prints, and how it ends.

    ``steps`` are output tuples ``("stdout", data)``, or the control steps
    :class:`Wait`, :class:`Omit` and :class:`Cut`.
    ``exit_status`` None means: drop the connection without an exit packet.
    ``fragment`` sends the packets one byte at a time, ``coalesce`` in one write.
    ``byte_delay`` is the pause in seconds after each byte in ``fragment`` mode.
    ``expect_t`` is the value the client must pass after ``-T``; a different
    value (or none) is recorded in :attr:`FakeAdbServer.violations`.
    """

    steps: list[Step] = field(default_factory=list)
    exit_status: int | None = 0
    fragment: bool = False
    coalesce: bool = False
    byte_delay: float = 0.0002
    expect_t: str | None = None


@dataclass
class ConnectionRecord:
    """What one shell connection asked for and what the fake did with it.

    The fake fills it while the connection runs; wait for :attr:`done` before
    reading the byte counts. ``stdout`` and ``stderr`` hold what the fake wrote
    to the socket: every packet that was written completely, plus the written
    part of a deliberately cut packet. A packet whose write failed part-way is
    not counted (a client cannot decode it); its whole payload is in ``lost``.
    The fake cannot know how much of the output the client read. ``omitted``
    holds the skipped output, ``lost`` the payload bytes that were meant to be
    sent but were not written: the rest of a cut packet, lines injected into a
    connection that ended first, packets whose write failed, and all scripted
    output after the point where playback ended early (a failed write, a wait
    that was abandoned, a cut). ``dropped`` is True unless the exit packet was
    written.
    """

    index: int
    serial: str | None
    command: str
    t_value: str | None
    # When the fake began to serve the command (``time.perf_counter``).
    started_at: float = field(default_factory=time.perf_counter)
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    omitted: bytearray = field(default_factory=bytearray)
    lost: bytearray = field(default_factory=bytearray)
    dropped: bool = True
    done: threading.Event = field(default_factory=threading.Event)

    def delivered_lines(self) -> list[bytes]:
        """Return the newline-terminated lines in the stdout bytes written.

        This counts bytes written to the socket, including the written part of
        a deliberately cut packet. A client decodes only complete packets, so
        lines inside a cut packet's payload are listed here but never reach it.
        """
        return _split_lines(bytes(self.stdout), complete_only=True)

    def omitted_lines(self) -> list[bytes]:
        """Return the lines the script skipped on purpose."""
        return _split_lines(bytes(self.omitted), complete_only=False)

    def partial_line(self) -> bytes:
        """Return the stdout bytes after the last newline (a cut line)."""
        return bytes(self.stdout).rpartition(b"\n")[2]


def _split_lines(data: bytes, *, complete_only: bool) -> list[bytes]:
    """Split on newline only (a lone carriage return does not end a line)."""
    parts = data.split(b"\n")
    lines = [part + b"\n" for part in parts[:-1]]
    if not complete_only and parts[-1]:
        lines.append(parts[-1])
    return lines


def program_of(command: str) -> str:
    """Return ``command`` without the environment prefix the library adds."""
    return command.removeprefix(_ENV_PREFIX)


def t_value_of(command: str) -> str | None:
    """Return the argument after ``-T`` in a shell command, or None."""
    try:
        words = shlex.split(program_of(command))
    except ValueError:
        return None
    for position, word in enumerate(words[:-1]):
        if word == "-T":
            return words[position + 1]
    return None


def packet(packet_id: int, payload: bytes) -> bytes:
    """Encode one shell protocol v2 packet."""
    return struct.pack("<BI", packet_id, len(payload)) + payload


def _peer_closed(sock: socket.socket) -> bool:
    """Return True when the peer closed its side (without consuming data)."""
    try:
        readable, _, _ = select.select([sock], [], [], 0)
        if not readable:
            return False
        return sock.recv(1, socket.MSG_PEEK) == b""
    except (OSError, ValueError):  # ValueError: the socket is already closed
        return True


class _Handler(socketserver.BaseRequestHandler):
    @property
    def fake(self) -> FakeAdbServer:
        return cast("_Server", self.server).fake

    def _read_exact(self, size: int) -> bytes | None:
        data = b""
        while len(data) < size:
            chunk = self.request.recv(size - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _read_request(self) -> str | None:
        header = self._read_exact(4)
        if header is None:
            return None
        body = self._read_exact(int(header, 16))
        return None if body is None else body.decode()

    def _reply(self, data: bytes) -> None:
        self.request.sendall(b"OKAY" + b"%04x" % len(data) + data)

    def _fail(self, message: str) -> None:
        data = message.encode()
        self.request.sendall(b"FAIL" + b"%04x" % len(data) + data)

    def handle(self) -> None:
        # Without this, Nagle's algorithm may merge the one-byte writes of
        # fragment mode into larger segments.
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with contextlib.suppress(OSError):  # the client went away mid-reply
            self._serve_requests()

    def _serve_requests(self) -> None:  # noqa: PLR0911
        fake = self.fake
        serial: str | None = None
        while True:
            request = self._read_request()
            if request is None:
                fake.client_closed.set()
                return
            fake._record(request)
            prefix = fake.silent_prefix
            if fake.silent or (prefix is not None and request.startswith(prefix)):
                # Never answer; wait until the client gives up and closes.
                fake.silent_started.set()
                while self.request.recv(1):
                    pass
                fake.client_closed.set()
                return
            if request in fake.fail:
                self._fail(fake.fail[request])
                return
            if request == "host:version":
                self._reply(b"%04x" % fake.version)
                return
            if request == "host:devices-l":
                self._reply(fake._devices_text().encode())
                return
            if request.startswith("host-serial:") and request.endswith(":features"):
                target = request[len("host-serial:") : -len(":features")]
                self._reply(",".join(fake.features.get(target, [])).encode())
                return
            if request.startswith("host:transport:"):
                serial = request[len("host:transport:") :]
                if serial not in [d[0] for d in fake.devices]:
                    self._fail(f"device '{serial}' not found")
                    return
                self.request.sendall(b"OKAY")
                continue
            if request.startswith("shell,v2,raw:"):
                self.request.sendall(b"OKAY")
                self._run_shell(request[len("shell,v2,raw:") :], serial)
                return
            self._fail(f"unknown request: {request}")
            return

    def _read_stdin_packet(self) -> None:
        """Consume the packet the client sends first (close-stdin), if any."""
        self.request.settimeout(2.0)
        try:
            self._read_exact(5)
        except OSError:  # the client sent nothing in time
            pass
        finally:
            self.request.settimeout(None)

    def _run_shell(self, command: str, serial: str | None) -> None:
        # Read the client's close-stdin packet first: left unread, it would hide
        # a closed client from the peek that detects one.
        self._read_stdin_packet()
        fake = self.fake
        script, record = fake._begin_shell(command, serial)
        try:
            self._play(script, record)
        finally:
            record.done.set()

    def _account(self, record: ConnectionRecord, item: _Item, *, add: bool) -> None:
        """Add ``item`` to (or take it back out of) the record."""
        if item.kind == "exit":
            record.dropped = not add
            return
        target = record.stdout if item.kind == "stdout" else record.stderr
        if add:
            target.extend(item.data)
        else:
            del target[len(target) - len(item.data) :]

    def _send_items(
        self, script: ShellScript, record: ConnectionRecord, items: list[_Item]
    ) -> None:
        """Write the packets and record them.

        A packet is recorded before it is written, so a client that has read it
        always finds it in the record. When a write fails, the packets that were
        written completely stay in the record; the others (a partly written
        packet counts as not written) are taken back out and their payloads
        recorded as lost, together with all later packets, and the error
        propagates.
        """
        groups = [items] if script.coalesce else [[item] for item in items]
        for number, group in enumerate(groups):
            for item in group:
                self._account(record, item, add=True)
            encoded = b"".join(item.encoded for item in group)
            written = 0
            try:
                if script.fragment and not script.coalesce:
                    for byte in encoded:
                        self.request.sendall(bytes([byte]))
                        written += 1
                        time.sleep(script.byte_delay)
                else:
                    while written < len(encoded):
                        written += self.request.send(encoded[written:])
            except OSError:
                self._roll_back(record, group, written)
                for unsent in groups[number + 1 :]:
                    self._write_off_items(record, unsent)
                raise

    def _roll_back(
        self, record: ConnectionRecord, group: list[_Item], written: int
    ) -> None:
        """Keep the packets of ``group`` written completely; write off the rest."""
        end = 0
        unwritten: list[_Item] = []
        for item in group:
            end += len(item.encoded)
            if end > written:
                self._account(record, item, add=False)
                unwritten.append(item)
        self._write_off_items(record, unwritten)

    @staticmethod
    def _write_off_items(record: ConnectionRecord, items: list[_Item]) -> None:
        for item in items:
            if item.kind != "exit":
                record.lost.extend(item.data)

    def _client_gone(self) -> bool:
        """Return True when the client closed its side (without consuming data)."""
        return _peer_closed(self.request)

    def _drain(
        self,
        lines: queue.Queue[bytes],
        script: ShellScript,
        record: ConnectionRecord,
        *,
        send: bool,
    ) -> OSError | None:
        """Send (``send``) or write off the queued lines; return a send error.

        Once a send fails, the lines still queued are recorded as lost.
        """
        error: OSError | None = None
        while not lines.empty():
            data = lines.get_nowait()
            if error is not None or not send:
                record.lost.extend(data)
                continue
            try:
                self._send_items(script, record, [_Item("stdout", data)])
            except OSError as exc:  # _send_items recorded this line as lost
                error = exc
        return error

    def _wait_point(
        self, step: Wait, script: ShellScript, record: ConnectionRecord
    ) -> bool:
        """Block at a waiting point; return False when the connection must end."""
        fake = self.fake
        lines: queue.Queue[bytes] = queue.Queue()
        if step.live:
            fake._add_live(record.serial, lines)
        if not fake._mark_reached(step.name):
            fake._violate(f"wait point {step.name!r} was reached more than once")
            fake._remove_live(lines)
            return True
        released = fake._event(step.name, "released")
        deadline = time.monotonic() + fake.guard
        keep_going = True
        failed: OSError | None = None
        try:
            while not released.is_set():
                # A client that closed is not a violation, even when the server
                # stops at the same time. stop() shuts the sockets down itself,
                # which looks like a closed client, so it records who had really
                # closed before it sets _stopping. Look at the client first: if
                # _stopping is then set, the record is final and decides; if
                # not, a closed client cannot be stop()'s doing.
                gone = self._client_gone()
                if fake._stopping.is_set():
                    if self.request not in fake._closed_at_stop:
                        fake._violate(
                            f"wait point {step.name!r} was still waiting when "
                            "the server stopped"
                        )
                    keep_going = False
                    break
                if gone:
                    keep_going = False
                    break
                if time.monotonic() > deadline:
                    fake._violate(f"wait point {step.name!r} was never released")
                    keep_going = False
                    break
                try:
                    data = lines.get(timeout=0.01)
                except queue.Empty:
                    continue
                self._send_items(script, record, [_Item("stdout", data)])
        except OSError as error:
            keep_going = False
            failed = error
        finally:
            # Unregister before the last drain: from here on inject() cannot
            # put anything into the queue, so the drain sees every line that
            # was counted as delivered.
            fake._remove_live(lines)
            drain_error = self._drain(lines, script, record, send=keep_going)
            keep_going = keep_going and drain_error is None
            failed = failed or drain_error
        if failed is not None:
            raise failed
        return keep_going

    @staticmethod
    def _write_off(steps: list[Step], record: ConnectionRecord) -> None:
        """Account for the steps that will not run: output is lost, omits stay."""
        for step in steps:
            if isinstance(step, Omit):
                record.omitted.extend(step.data)
            elif isinstance(step, Cut):
                record.lost.extend(step.data)
            elif not isinstance(step, Wait):
                record.lost.extend(step[1])

    def _play(self, script: ShellScript, record: ConnectionRecord) -> None:
        pending: list[_Item] = []

        def flush() -> None:
            items = pending[:]
            pending.clear()
            self._send_items(script, record, items)

        # Index of the first step whose output has not been written off yet.
        unplayed = 0
        try:
            for number, step in enumerate(script.steps):
                unplayed = number
                if isinstance(step, Wait):
                    flush()
                    unplayed = number + 1
                    if not self._wait_point(step, script, record):
                        self._write_off(script.steps[number + 1 :], record)
                        return
                elif isinstance(step, Omit):
                    record.omitted.extend(step.data)
                elif isinstance(step, Cut):
                    flush()
                    unplayed = number + 1
                    encoded = packet(_PACKET_ID[step.kind], step.data)
                    try:
                        self.request.sendall(encoded[: step.keep])
                    except OSError:
                        record.lost.extend(step.data)
                        raise
                    payload_sent = max(0, step.keep - _HEADER_SIZE)
                    target = record.stdout if step.kind == "stdout" else record.stderr
                    target.extend(step.data[:payload_sent])
                    record.lost.extend(step.data[payload_sent:])
                    self._write_off(script.steps[number + 1 :], record)
                    if step.hold is not None:
                        self._wait_point(Wait(step.hold), script, record)
                    return  # closing the connection mid-packet is the point
                else:
                    kind, data = step
                    pending.append(_Item(kind, data))
        except OSError:
            self._write_off(script.steps[unplayed:], record)
            raise
        if script.exit_status is not None:
            pending.append(_Item("exit", bytes([script.exit_status])))
        flush()
        # Closing here means "drop" when there was no exit packet.


@dataclass(frozen=True)
class _Item:
    """One packet to write: ``kind`` is stdout, stderr or exit."""

    kind: Literal["stdout", "stderr", "exit"]
    data: bytes

    @property
    def encoded(self) -> bytes:
        return packet({"stdout": 1, "stderr": 2, "exit": 3}[self.kind], self.data)


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    # Handler threads are joined by server_close(), so stop() leaves none behind.
    daemon_threads = False
    fake: FakeAdbServer

    def process_request(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: object,
    ) -> None:
        if isinstance(request, socket.socket):
            self.fake._connection_opened(request)
        super().process_request(request, client_address)

    def shutdown_request(self, request: socket.socket) -> None:  # ty: ignore[invalid-method-override]
        super().shutdown_request(request)
        self.fake._connection_closed(request)


class FakeAdbServer:
    """Threaded fake adb server; configure the public attributes before use."""

    def __init__(self, port: int = 0) -> None:
        self.devices: list[tuple[str, str, dict[str, str]]] = []
        self.features: dict[str, list[str]] = {}
        self.shell: dict[str, ShellScript] = {}
        self.default_shell = ShellScript()
        self.fail: dict[str, str] = {}
        self.version = 41
        self.silent = False
        # Go silent (never answer) for requests starting with this text.
        self.silent_prefix: str | None = None
        self.client_closed = threading.Event()
        # Set when a request met the silence above and is left unanswered.
        self.silent_started = threading.Event()
        self.requests: list[str] = []
        # One script per connection: ``sequences[(prefix, serial)][n]`` is for
        # the n-th shell connection whose command (without the environment
        # prefix) starts with ``prefix`` and whose device is ``serial`` (None
        # matches every device). Use add_sequence().
        self.sequences: dict[tuple[str, str | None], list[ShellScript]] = {}
        # Answers for one-off commands, by command prefix. Use answer().
        self.oneoff: dict[str, ShellScript] = {}
        # Formats the line a ``log -t TAG MESSAGE`` command adds to the running
        # live streams; None means the command is recorded but adds nothing.
        self.echo_logged: Callable[[str, str], bytes] | None = None
        # ``(tag, message)`` of every ``log -t`` command that succeeded; a failing
        # one (non-zero exit status, or cut off) is not recorded.
        self.logged: list[tuple[str, str]] = []
        # One record per shell connection, in arrival order.
        self.records: list[ConnectionRecord] = []
        # Problems the fake noticed (a wrong -T value, an unreleased wait).
        self.violations: list[str] = []
        # Longest time in seconds a connection waits at a waiting point.
        self.guard = 10.0
        self._events: dict[tuple[str, str], threading.Event] = {}
        self._live: list[tuple[str | None, queue.Queue[bytes]]] = []
        self._matched: dict[tuple[str, str | None], int] = {}
        self._lock = threading.Lock()
        self._open: set[socket.socket] = set()
        self._idle = threading.Condition(self._lock)
        self._stopping = threading.Event()
        # Connections whose client had already closed when stop() began.
        self._closed_at_stop: set[socket.socket] = set()
        # Binding happens in start(), so a test can reserve a port that stays closed.
        self._server = _Server(("127.0.0.1", port), _Handler, bind_and_activate=False)
        self._server.fake = self
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def port(self) -> int:
        return self._server.server_address[1]  # after bind: the real port

    @property
    def address(self) -> str:
        """The server address in ``tcp:HOST:PORT`` form."""
        return f"tcp:127.0.0.1:{self.port}"

    def add_device(self, serial: str, state: str = "device", **info: str) -> None:
        self.devices.append((serial, state, info))

    def _serve(self) -> None:
        self._server.serve_forever(poll_interval=0.01)

    def start(self) -> FakeAdbServer:
        self._server.server_bind()
        self._server.server_activate()
        self._thread.start()
        return self

    def stop(self) -> None:
        """Stop serving; end every open connection and wait for its thread."""
        with self._lock:
            self._closed_at_stop = {s for s in self._open if _peer_closed(s)}
        self._stopping.set()
        # Stop accepting first, so no connection can open after the snapshot.
        if self._thread.is_alive():
            self._server.shutdown()
            self._thread.join(timeout=5)
        with self._lock:
            open_sockets = list(self._open)
        # Shutting a socket down also wakes a handler blocked in recv().
        for sock in open_sockets:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
        self._server.server_close()  # joins the handler threads

    def _connection_opened(self, request: socket.socket) -> None:
        with self._lock:
            self._open.add(request)

    def _connection_closed(self, request: socket.socket) -> None:
        with self._idle:
            self._open.discard(request)
            self._idle.notify_all()

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """Wait until every accepted connection is closed on the server side."""
        with self._idle:
            return self._idle.wait_for(lambda: not self._open, timeout)

    def add_sequence(
        self, prefix: str, *scripts: ShellScript, serial: str | None = None
    ) -> None:
        """Give the n-th shell connection starting with ``prefix`` the n-th script.

        With ``serial`` the sequence only counts connections to that device;
        when a device has no sequence of its own for the prefix, the one added
        without ``serial`` applies. Sequences and one-off answers compete by
        prefix length: the longest matching prefix decides, and a sequence wins
        a tie. Once the winning sequence has no script left, the connection
        gets ``default_shell``; no shorter prefix is tried. Exact ``shell``
        entries are checked before everything else.
        """
        self.sequences.setdefault((prefix, serial), []).extend(scripts)

    def answer(
        self, prefix: str, stdout: bytes = b"", exit_status: int | None = 0
    ) -> None:
        """Answer one-off commands starting with ``prefix`` with ``stdout``.

        Typical prefixes: ``date +%s``, ``getprop``, ``logcat -g``,
        ``dumpsys package``. The most specific (longest) prefix wins; see
        :meth:`add_sequence` for how it competes with sequences.
        """
        steps: list[Step] = [("stdout", stdout)] if stdout else []
        self.oneoff[prefix] = ShellScript(steps=steps, exit_status=exit_status)

    def _event(self, name: str, kind: str) -> threading.Event:
        with self._lock:
            return self._events.setdefault((name, kind), threading.Event())

    def _mark_reached(self, name: str) -> bool:
        """Mark waiting point ``name`` as reached; False if it already was."""
        with self._lock:
            event = self._events.setdefault((name, "reached"), threading.Event())
            first = not event.is_set()
            event.set()
            return first

    def wait_reached(self, name: str, timeout: float = 5.0) -> bool:
        """Wait until a connection stands at waiting point ``name``."""
        return self._event(name, "reached").wait(timeout)

    def release(self, name: str) -> None:
        """Let the connection at waiting point ``name`` go on (now or later)."""
        self._event(name, "released").set()

    def wait_done(self, index: int, timeout: float = 5.0) -> bool:
        """Wait until shell connection ``index`` (0-based) has finished."""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                if index < len(self.records):
                    record = self.records[index]
                    break
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.005)
        return record.done.wait(max(0.0, deadline - time.monotonic()))

    def inject(self, data: bytes, serial: str | None = None) -> int:
        """Send ``data`` as stdout on the connections waiting at a live point.

        With ``serial`` only connections to that device get it. Return how many
        connections got it. A connection counts only while it is registered,
        and it delivers (or records as lost) every line it counted.
        """
        with self._lock:
            targets = [
                lines for key, lines in self._live if serial is None or key == serial
            ]
            for target in targets:
                target.put(data)
        return len(targets)

    def _add_live(self, serial: str | None, lines: queue.Queue[bytes]) -> None:
        with self._lock:
            self._live.append((serial, lines))

    def _remove_live(self, lines: queue.Queue[bytes]) -> None:
        with self._lock:
            self._live = [entry for entry in self._live if entry[1] is not lines]

    def _violate(self, message: str) -> None:
        with self._lock:
            self.violations.append(message)

    def expected_loss(self) -> bytes:
        """Return all skipped output (``Omit`` steps) of all connections."""
        with self._lock:
            return b"".join(bytes(r.omitted) for r in self.records)

    def _pick_script(self, command: str, serial: str | None) -> ShellScript:
        """Choose the script for a connection; the caller holds the lock."""
        if command in self.shell:
            return self.shell[command]
        program = program_of(command)
        best: tuple[str, str | None] | None = None
        for key in self.sequences:
            prefix, key_serial = key
            if key_serial not in (None, serial) or not program.startswith(prefix):
                continue
            if best is None or (len(prefix), key_serial is not None) > (
                len(best[0]),
                best[1] is not None,
            ):
                best = key
        oneoff = [p for p in self.oneoff if program.startswith(p)]
        longest = max(oneoff, key=len, default=None)
        if best is not None and (longest is None or len(best[0]) >= len(longest)):
            count = self._matched.get(best, 0)
            self._matched[best] = count + 1
            scripts = self.sequences[best]
            return scripts[count] if count < len(scripts) else self.default_shell
        if longest is not None:
            return self.oneoff[longest]
        if program.split(maxsplit=2)[:2] == ["log", "-t"]:
            return ShellScript()
        return self.default_shell

    @staticmethod
    def _log_entry(program: str) -> tuple[str, str] | None:
        """Return ``(tag, message)`` of a ``log -t TAG MESSAGE`` command."""
        words = program.split(maxsplit=2)
        if words[:2] != ["log", "-t"] or len(words) != 3:
            return None
        try:
            words = shlex.split(program)
        except ValueError:
            return None
        if len(words) < 4:
            return None
        return words[2], " ".join(words[3:])

    def _begin_shell(
        self, command: str, serial: str | None
    ) -> tuple[ShellScript, ConnectionRecord]:
        program = program_of(command)
        entry = self._log_entry(program)
        with self._lock:
            index = len(self.records)
            record = ConnectionRecord(index, serial, command, t_value_of(command))
            self.records.append(record)
            script = self._pick_script(command, serial)
            succeeds = script.exit_status == 0 and not any(
                isinstance(step, Cut) for step in script.steps
            )
            if entry is not None and succeeds:
                self.logged.append(entry)
            else:
                entry = None
        if entry is not None and self.echo_logged is not None:
            self.inject(self.echo_logged(*entry), serial)
        if script.expect_t is not None and record.t_value != script.expect_t:
            self._violate(
                f"connection {index}: expected -T {script.expect_t!r}, "
                f"got {record.t_value!r}"
            )
        return script, record

    def _record(self, request: str) -> None:
        with self._lock:
            self.requests.append(request)

    def _devices_text(self) -> str:
        lines = []
        for serial, state, info in self.devices:
            extras = " ".join(f"{k}:{v}" for k, v in info.items())
            lines.append(f"{serial:<22} {state} {extras}".rstrip())
        return "".join(line + "\n" for line in lines)


# Four bytes that are not a valid hex length field, though some look like one.
BAD_LENGTHS = [b" 01a", b"+01a", b"0x1a", b"-001", b"01a\n", b"\xff\xff\xff\xff"]


def free_port() -> int:
    """Return a TCP port on 127.0.0.1 that nothing listens on right now."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
