"""Run one test body against the blocking and the asyncio log stream.

``Mode`` creates streams through ``logprobe.stream`` or ``logprobe.astream`` and
hands the test an object with the interface of ``LogStream``. For the asyncio
stream this is an adapter that runs the stream on an event loop in a helper
thread of the test and forwards each call with ``run_coroutine_threadsafe``.
The thread belongs to the tests: the library starts none. The thread is named
``test-event-loop``, so a test of "no thread of the library" is not disturbed.

What only one version has stays out of the shared bodies: ``on_entry``, reader
threads, a ``KeyboardInterrupt`` that reaches a blocking wait, and the private
seams of the blocking client. Those tests do not request the ``mode`` fixture.
"""

from __future__ import annotations

import asyncio
import functools
import threading
from typing import TYPE_CHECKING, Any, Protocol, Self

import logprobe
from logprobe import _aadb, _astream, _resume
from logprobe._adb import protocol as adb_protocol

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterable, Iterator
    from types import TracebackType

    import pytest

    from logprobe import Device, Gap, LogEntry, LogprobeError, StreamSummary

# A call into the loop that takes longer than this is a hang, not a slow test.
CALL_GUARD = 60.0


class StreamLike(Protocol):
    """What the shared test bodies use of a started or unstarted stream."""

    serials: tuple[str, ...]
    _core: Any

    @property
    def summary(self) -> StreamSummary: ...
    def start(self) -> Self: ...
    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> object: ...
    def __iter__(self) -> Iterator[LogEntry]: ...
    def items(self) -> Iterator[LogEntry | Gap]: ...
    def join(self, timeout: float | None = None) -> StreamSummary: ...
    def stop(self, flush: float | None = None) -> None: ...
    def kill(self) -> None: ...


class _LoopThread:
    """An event loop that runs in a thread of its own until it is closed."""

    def __init__(self) -> None:
        self._ready = threading.Event()
        self._leave: asyncio.Event | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self._thread = threading.Thread(
            target=lambda: asyncio.run(self._serve()),
            name="test-event-loop",
            daemon=True,
        )
        self._thread.start()
        if not self._ready.wait(CALL_GUARD):
            msg = "the event loop did not start"
            raise RuntimeError(msg)

    async def _serve(self) -> None:
        self.loop = asyncio.get_running_loop()
        self._leave = asyncio.Event()
        self._ready.set()
        await self._leave.wait()

    def call[T](self, awaitable: Awaitable[T]) -> T:
        """Run ``awaitable`` on the loop and wait for its result."""
        assert self.loop is not None

        async def forward() -> T:
            return await awaitable

        return asyncio.run_coroutine_threadsafe(forward(), self.loop).result(CALL_GUARD)

    def close(self) -> None:
        """End the loop; ``asyncio.run`` cancels the tasks that are left."""
        assert self.loop is not None
        assert self._leave is not None
        self.loop.call_soon_threadsafe(self._leave.set)
        self._thread.join(CALL_GUARD)
        assert not self._thread.is_alive()


class _Iteration:
    """A blocking iterator over an ``AsyncLogStream`` iteration."""

    def __init__(self, loop: _LoopThread, inner: Any) -> None:  # noqa: ANN401
        self._loop = loop
        self._inner = inner

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> Any:  # noqa: ANN401
        try:
            return self._loop.call(self._inner.__anext__())
        except StopAsyncIteration:
            raise StopIteration from None

    def close(self) -> None:
        self._inner.close()


class _AsyncAdapter:
    """The interface of ``LogStream`` over an ``AsyncLogStream`` on a helper loop."""

    def __init__(self, loop: _LoopThread, inner: logprobe.AsyncLogStream) -> None:
        self._loop = loop
        self._inner = inner
        self.serials = inner.serials
        self._core = inner._core

    @property
    def summary(self) -> StreamSummary:
        return self._inner.summary

    def start(self) -> Self:
        self._loop.call(self._inner.start())
        return self

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._loop.call(self._inner.__aexit__(exc_type, exc, traceback))

    def __iter__(self) -> _Iteration:
        return _Iteration(self._loop, self._inner.__aiter__())

    def items(self) -> _Iteration:
        return _Iteration(self._loop, self._inner.items())

    def join(self, timeout: float | None = None) -> StreamSummary:
        return self._loop.call(self._inner.join(timeout))

    def stop(self, flush: float | None = None) -> None:
        self._inner.stop(flush)

    def kill(self) -> None:
        self._inner.kill()


class Mode:
    """One of the two versions of the stream, for a parametrized test."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.is_async = name == "async"
        self._loop = _LoopThread() if self.is_async else None
        self._made: list[StreamLike] = []

    def stream(
        self,
        devices: Iterable[Device | str],
        *args: Any,  # noqa: ANN401
        **kwargs: Any,  # noqa: ANN401
    ) -> StreamLike:
        """``logprobe.stream`` or ``logprobe.astream``, as one interface."""
        if self._loop is None:
            made: StreamLike = logprobe.stream(devices, *args, **kwargs)
        else:
            made = _AsyncAdapter(self._loop, logprobe.astream(devices, *args, **kwargs))
        self._made.append(made)
        return made

    def device_stream(self, device: Device, *args: Any, **kwargs: Any) -> StreamLike:  # noqa: ANN401
        """``Device.stream`` or ``Device.astream``, as one interface."""
        if self._loop is None:
            made: StreamLike = device.stream(*args, **kwargs)
        else:
            made = _AsyncAdapter(self._loop, device.astream(*args, **kwargs))
        self._made.append(made)
        return made

    def unwrap(self, s: StreamLike) -> object:
        """The ``LogStream`` or ``AsyncLogStream`` behind ``s``."""
        return s._inner if isinstance(s, _AsyncAdapter) else s

    @property
    def cls(self) -> type:
        return logprobe.AsyncLogStream if self.is_async else logprobe.LogStream

    def patch_ticks(self, monkeypatch: pytest.MonkeyPatch, tick: float) -> None:
        """Set the length of every wait slice of both readers."""
        monkeypatch.setattr(_astream, "TICK", tick)
        monkeypatch.setattr(logprobe._stream, "TICK", tick)

    def open_fails(
        self,
        monkeypatch: pytest.MonkeyPatch,
        device: Device,
        error: BaseException,
    ) -> None:
        """Make opening the logcat connection of ``device`` raise ``error``."""
        if self.is_async:

            async def failing(*_args: object, **_kwargs: object) -> None:
                raise error

            monkeypatch.setattr(_astream, "aopen_shell", failing)
        else:

            def failing_open(*_args: object, **_kwargs: object) -> None:
                raise error

            monkeypatch.setattr(device, "_open_logcat", failing_open)

    def patch_read_size(self, monkeypatch: pytest.MonkeyPatch, size: int) -> None:
        """Make a reader receive and feed about ``size`` bytes of output at a time.

        The asyncio reader gets both a smaller network read and a smaller batch:
        the stall limit of ``detect_skips`` counts per network read.
        """
        if self.is_async:
            monkeypatch.setattr(_aadb, "RECV_SIZE", size)
            monkeypatch.setattr(_astream, "_BATCH_BYTES", size)
        else:
            monkeypatch.setattr(logprobe._stream, "RECV_SIZE", size)

    def after_features_check(
        self,
        monkeypatch: pytest.MonkeyPatch,
        device: Device,
        hook: Callable[[], object],
    ) -> None:
        """Call ``hook`` right after the check of the device's features is done."""
        if self.is_async:
            original = _astream.arequire_shell_v2

            async def checked(*args: Any, **kwargs: Any) -> None:  # noqa: ANN401
                await original(*args, **kwargs)
                hook()

            monkeypatch.setattr(_astream, "arequire_shell_v2", checked)
        else:
            original_check = type(device)._require_shell_v2

            def checked_sync(device: Device, cancelled: Any = None) -> None:  # noqa: ANN401
                original_check(device, cancelled)
                hook()

            monkeypatch.setattr(type(device), "_require_shell_v2", checked_sync)

    def limit_adb_steps(self, monkeypatch: pytest.MonkeyPatch, seconds: float) -> None:
        """Give the asyncio adb client a short per-step limit (the blocking one
        has none inside a deadline), as if its default of 10 seconds were short.
        """
        if self.is_async:
            limited = functools.partial(_aadb.aopen_shell, timeout=seconds)
            monkeypatch.setattr(_astream, "aopen_shell", limited)

    def hook_failure(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook: Callable[..., LogprobeError],
    ) -> None:
        """Route the conversion of an adb FAIL message through ``hook``."""
        monkeypatch.setattr(_aadb if self.is_async else adb_protocol, "failure", hook)

    def readers_running(self, s: StreamLike, serial: str) -> int:
        """How many readers (threads or tasks) of ``serial`` are alive."""
        count = 0
        for unit in s._core.units:
            if unit.serial != serial:
                continue
            if self.is_async:
                count += unit.task is not None and not unit.task.done()
            else:
                count += unit.thread is not None and unit.thread.is_alive()
        return count

    def wait_readers_ended(self, s: StreamLike, timeout: float) -> None:
        """Wait until every reader of ``s`` ended."""
        if self.is_async:
            deadline = timeout
            ended = threading.Event()
            while any(self.readers_running(s, serial) for serial in s.serials):
                assert deadline > 0, "the readers did not end"
                ended.wait(0.005)
                deadline -= 0.005
            return
        for unit in s._core.units:
            if unit.thread is not None:
                unit.thread.join(timeout)
                assert not unit.thread.is_alive()

    def gate_backoff(
        self,
        monkeypatch: pytest.MonkeyPatch,
        entered: threading.Event,
        release: threading.Event,
    ) -> None:
        """Hold every wait before a reconnect until ``release`` is set.

        A reader thread blocks on the event. A task must not block the loop, so
        the asyncio reader looks at the event between short sleeps instead.
        """
        if self.is_async:

            async def gated(core: Any, _unit: object, _delay: float) -> bool:  # noqa: ANN401
                entered.set()
                while not release.is_set():
                    if core.outbox.stopping:
                        return False
                    await asyncio.sleep(0.005)
                return True

            monkeypatch.setattr(_astream, "_pause", gated)
            return

        def blocked(_failures: int) -> float:
            entered.set()
            assert release.wait(CALL_GUARD)
            return 0.0

        monkeypatch.setattr(_resume, "backoff", blocked)

    def close(self) -> None:
        """Kill every stream the test made and end the helper loop."""
        for made in self._made:
            made.kill()
        if self._loop is not None:
            self._loop.close()
