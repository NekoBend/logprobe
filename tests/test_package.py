import subprocess
import sys
from pathlib import Path

import pytest

import logprobe

ASYNC_NAMES = {"AsyncLogStream", "astream"}


def test_package_has_docstring() -> None:
    assert logprobe.__doc__
    assert logprobe.__doc__.strip()


def test_public_surface() -> None:
    assert logprobe.__all__ == sorted(logprobe.__all__)
    assert set(logprobe.__all__) == {
        "And",
        "Anr",
        "AsyncLogStream",
        "Condition",
        "Crash",
        "Device",
        "DeviceInfo",
        "DeviceSummary",
        "Gap",
        "Level",
        "LogEntry",
        "LogLevel",
        "LogStream",
        "LogprobeError",
        "Message",
        "Not",
        "Or",
        "Package",
        "Pid",
        "StreamSummary",
        "Tag",
        "Tid",
        "Uid",
        "astream",
        "devices",
        "export_logs",
        "parse_lines",
        "read_file",
        "stream",
    }
    for name in logprobe.__all__:
        assert hasattr(logprobe, name), name
    assert {n for n in dir(logprobe) if not n.startswith("_")} == set(logprobe.__all__)


def test_parse_names_are_not_reexported() -> None:
    from logprobe import _parse

    for name in _parse.__all__:
        assert not hasattr(logprobe, name), name


def test_asyncio_is_imported_only_with_the_asyncio_names() -> None:
    """``import logprobe`` and every blocking name leave asyncio unimported.

    It runs in a new interpreter, because this one has imported asyncio already,
    isolated and without ``site`` so that no startup hook imports asyncio first.
    ``-B``: ``-I`` ignores PYTHONDONTWRITEBYTECODE, and the child must not write
    bytecode into the source tree.
    """
    root = str(Path(logprobe.__file__).parent.parent)
    code = f"""
import sys
sys.path.insert(0, {root!r})
print("asyncio" in sys.modules)
import logprobe
print("asyncio" in sys.modules)
print(sorted(set(dir(logprobe)) & {ASYNC_NAMES!r}))
for name in sorted(set(logprobe.__all__) - {ASYNC_NAMES!r}):
    getattr(logprobe, name)
print("asyncio" in sys.modules)
logprobe.astream
print("asyncio" in sys.modules)
"""
    result = subprocess.run(  # the test's own code on this interpreter
        [sys.executable, "-I", "-S", "-B", "-c", code],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "False",  # before: the check can see a change
        "False",  # after import logprobe
        str(sorted(ASYNC_NAMES)),  # dir() lists the names before their import
        "False",  # after every blocking name
        "True",  # the first asyncio name imports the asyncio stream
    ]


def test_the_asyncio_names_are_those_of_the_asyncio_stream() -> None:
    from logprobe import _astream

    assert logprobe.astream is _astream.astream
    assert logprobe.AsyncLogStream is _astream.AsyncLogStream
    assert set(dir(logprobe)) >= ASYNC_NAMES


def test_an_unknown_name_is_an_attribute_error() -> None:
    with pytest.raises(AttributeError, match="has no attribute 'nope'"):
        _ = logprobe.nope  # ty: ignore[unresolved-attribute]
    assert not hasattr(logprobe, "nope")
