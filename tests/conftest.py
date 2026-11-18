"""Shared fixtures: a clean environment and a fake adb server."""

from __future__ import annotations

import gc
from typing import TYPE_CHECKING

import pytest

from tests.fake_adb_server import FakeAdbServer
from tests.stream_modes import Mode

if TYPE_CHECKING:
    from collections.abc import Iterator

_ENV_VARIABLES = (
    "ADB_SERVER_SOCKET",
    "ANDROID_ADB_SERVER_ADDRESS",
    "ANDROID_ADB_SERVER_PORT",
    "LOGPROBE_ADB",
    "ANDROID_HOME",
    "ANDROID_SDK_ROOT",
    "ANDROID_SERIAL",
)


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every variable the library reads, so tests start from defaults."""
    for name in _ENV_VARIABLES:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def fake() -> Iterator[FakeAdbServer]:
    server = FakeAdbServer().start()
    try:
        yield server
    finally:
        server.stop()
    # Tests that provoke violations on purpose clear the list themselves.
    assert server.violations == []


@pytest.fixture
def server(fake: FakeAdbServer) -> Iterator[FakeAdbServer]:
    """The fake server; at the end every connection must be closed."""
    yield fake
    assert fake.wait_idle(10.0), "a connection to the adb server stayed open"


@pytest.fixture(params=["blocking", "async"])
def mode(
    request: pytest.FixtureRequest,
    server: FakeAdbServer,  # noqa: ARG001  (it must outlive the streams)
    caplog: pytest.LogCaptureFixture,
) -> Iterator[Mode]:
    """The version of the stream a shared test body runs against.

    At the end every stream the test made is killed and the helper event loop
    of the asyncio version is closed; a task or a transport that is left behind
    (an asyncio log record or a ResourceWarning) fails the test.
    """
    made = Mode(request.param)
    yield made
    made.close()
    gc.collect()
    problems = [r.getMessage() for r in caplog.records if r.name == "asyncio"]
    assert problems == []
