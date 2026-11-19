"""Server address resolution, adb lookup and the auto-start rule."""

from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from logprobe import LogprobeError, _adb
from tests.fake_adb_server import FakeAdbServer, free_port

ADB_NAME = "adb.exe" if sys.platform == "win32" else "adb"


def make_adb(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ADB_NAME
    path.write_bytes(b"")
    path.chmod(0o755)
    return path


def assert_same_path(actual: str | None, expected: Path) -> None:
    """Compare paths, not strings: Windows may report ``adb.EXE`` for ``adb.exe``."""
    assert actual is not None
    assert os.path.normcase(actual) == os.path.normcase(str(expected))


# --- address resolution ----------------------------------------------------


def test_default_address_is_flagged_default() -> None:
    assert _adb.resolve_server_address() == _adb.ServerAddress(
        "127.0.0.1", 5037, is_default=True
    )


def test_explicit_argument_wins_over_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ADB_SERVER_SOCKET", "tcp:10.0.0.1:1111")
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", "2222")
    assert _adb.resolve_server_address("tcp:192.0.2.7:3333") == _adb.ServerAddress(
        "192.0.2.7", 3333, is_default=False
    )


def test_socket_variable_wins_over_port_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ADB_SERVER_SOCKET", "tcp:10.0.0.1:1111")
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", "2222")
    assert _adb.resolve_server_address() == _adb.ServerAddress(
        "10.0.0.1", 1111, is_default=False
    )


def test_port_variable_uses_loopback_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", "2222")
    assert _adb.resolve_server_address() == _adb.ServerAddress(
        "127.0.0.1", 2222, is_default=False
    )


def test_bracketed_ipv6_host_is_unwrapped() -> None:
    assert _adb.resolve_server_address("tcp:[::1]:5037").host == "::1"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "127.0.0.1:5037",
        "tcp:127.0.0.1",
        "tcp::5037",
        "tcp:127.0.0.1:0",
        "tcp:127.0.0.1:65536",
        "tcp:127.0.0.1:port",
        "local:abc",
    ],
)
def test_malformed_argument_raises_value_error(value: str) -> None:
    with pytest.raises(ValueError, match="tcp:HOST:PORT"):
        _adb.resolve_server_address(value)


def test_non_string_argument_raises_type_error() -> None:
    with pytest.raises(TypeError):
        _adb.resolve_server_address(5037)  # ty: ignore[invalid-argument-type]


def test_malformed_socket_variable_is_usage_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ADB_SERVER_SOCKET", "nonsense")
    with pytest.raises(LogprobeError) as info:
        _adb.resolve_server_address()
    assert info.value.code == "usage_error"
    assert info.value.details == {"variable": "ADB_SERVER_SOCKET"}
    assert "ADB_SERVER_SOCKET" in str(info.value)


# 5,000 digits: past int()'s default digit limit, within Windows' limit on the
# length of an environment variable.
@pytest.mark.parametrize("value", ["abc", "0", "65536", "-1", "12 34", "1" * 5_000])
def test_malformed_port_variable_is_usage_error(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", value)
    with pytest.raises(LogprobeError) as info:
        _adb.resolve_server_address()
    assert info.value.code == "usage_error"
    assert info.value.details == {"variable": "ANDROID_ADB_SERVER_PORT"}


ACCEPTED_HOSTS = [
    ("tcp:127.0.0.1:5037", "127.0.0.1"),
    ("tcp:10.1.2.3:1", "10.1.2.3"),
    ("tcp:[::1]:5037", "::1"),
    ("tcp:[2001:0DB8:0:0:0:0:0:1]:5037", "2001:db8::1"),
    ("tcp:[0:0:0:0:0:0:0:1]:5037", "::1"),
    ("tcp:LOCALHOST:5037", "127.0.0.1"),
    ("tcp:LocalHost:5037", "127.0.0.1"),
    ("tcp:[fe80::1%eth0]:5037", "fe80::1%eth0"),
    ("tcp:[fe80::1%12]:5037", "fe80::1%12"),
    ("tcp:[fe80::1%br-1.5_x]:5037", "fe80::1%br-1.5_x"),
    (f"tcp:[fe80::1%{'a' * 63}]:5037", f"fe80::1%{'a' * 63}"),
]


@pytest.mark.parametrize(("text", "host"), ACCEPTED_HOSTS)
def test_accepted_hosts_become_canonical_numeric(text: str, host: str) -> None:
    assert _adb.resolve_server_address(text).host == host


@pytest.mark.parametrize(("text", "host"), ACCEPTED_HOSTS)
def test_accepted_hosts_in_environment(
    monkeypatch: pytest.MonkeyPatch, text: str, host: str
) -> None:
    monkeypatch.setenv("ADB_SERVER_SOCKET", text)
    port = int(text.rsplit(":", 1)[1])
    assert _adb.resolve_server_address() == _adb.ServerAddress(
        host, port, is_default=False
    )


REJECTED_HOSTS = [
    "tcp:adb.example.invalid:5037",
    "tcp::5037",
    "tcp:bad host:5037",
    "tcp:[not-an-ip]:5037",
    "tcp:1.2.3:5037",
    "tcp:256.1.1.1:5037",
    "tcp:[127.0.0.1]:5037",
    "tcp:::1:5037",
    "tcp:[]:5037",
    "tcp:localhost.:5037",
    "tcp:[fe80::1%]:5037",
    "tcp:[fe80::1%a b]:5037",
    "tcp:[fe80::1%a..b]:5037",
    "tcp:[fe80::1%.a]:5037",
    "tcp:[fe80::1%a.]:5037",
    "tcp:[fe80::1%a%b]:5037",
    "tcp:[fe80::1%a/b]:5037",
    "tcp:[fe80::1%e\u00e9]:5037",
    "tcp:[fe80::1%a\n]:5037",
    f"tcp:[fe80::1%{'a' * 64}]:5037",
]


@pytest.mark.parametrize("value", REJECTED_HOSTS)
def test_non_ip_host_argument_is_value_error(value: str) -> None:
    with pytest.raises(ValueError, match="IP address") as info:
        _adb.resolve_server_address(value)
    assert "localhost" in str(info.value)


def test_scope_id_with_nul_is_rejected() -> None:
    # NUL cannot be stored in an environment variable, so only the argument.
    with pytest.raises(ValueError, match="IP address"):
        _adb.resolve_server_address("tcp:[fe80::1%a\x00b]:5037")


@pytest.mark.parametrize("value", REJECTED_HOSTS)
def test_non_ip_host_variable_is_usage_error(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("ADB_SERVER_SOCKET", value)
    with pytest.raises(LogprobeError) as info:
        _adb.resolve_server_address()
    assert info.value.code == "usage_error"
    assert info.value.details == {"variable": "ADB_SERVER_SOCKET"}
    assert "IP address" in str(info.value)
    assert "localhost" in str(info.value)


def test_resolve_and_connect_never_look_up_a_name(
    monkeypatch: pytest.MonkeyPatch, fake: FakeAdbServer
) -> None:
    real_getaddrinfo = socket.getaddrinfo
    lookups: list[object] = []

    def guarded_getaddrinfo(host: object, *args: object, **kwargs: object) -> object:
        if isinstance(host, bytes):
            host = host.decode("ascii")
        lookups.append(host)
        flags = kwargs.get("flags", 0)
        assert isinstance(flags, int)
        if not flags & socket.AI_NUMERICHOST:
            msg = f"getaddrinfo without AI_NUMERICHOST for {host!r}"
            raise AssertionError(msg)
        try:
            ipaddress.ip_address(str(host))
        except ValueError:
            msg = f"name lookup attempted: {host!r}"
            raise AssertionError(msg) from None
        return real_getaddrinfo(host, *args, **kwargs)  # ty: ignore[invalid-argument-type]

    def forbidden_gethostbyname(host: str) -> str:
        msg = f"gethostbyname called: {host!r}"
        raise AssertionError(msg)

    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyname", forbidden_gethostbyname)

    for spelling in ("LOCALHOST", "localhost", "127.0.0.1"):
        address = _adb.resolve_server_address(f"tcp:{spelling}:{fake.port}")
        assert address.host == "127.0.0.1"
        _adb.ensure_server(address, adb=None, start_server=False)
        assert _adb.server_version(address) > 0
    # Only numeric hosts ever reached getaddrinfo.
    assert lookups
    assert set(lookups) == {"127.0.0.1"}

    with pytest.raises(ValueError, match="IP address"):
        _adb.resolve_server_address(f"tcp:adb.example.invalid:{fake.port}")
    assert set(lookups) == {"127.0.0.1"}


def test_connecting_refuses_a_non_numeric_host_without_a_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_getaddrinfo = socket.getaddrinfo
    calls: list[object] = []

    def guarded_getaddrinfo(host: object, *args: object, **kwargs: object) -> object:
        calls.append(host)
        flags = kwargs.get("flags", 0)
        assert isinstance(flags, int)
        if not flags & socket.AI_NUMERICHOST:
            msg = f"getaddrinfo without AI_NUMERICHOST for {host!r}"
            raise AssertionError(msg)
        return real_getaddrinfo(host, *args, **kwargs)  # ty: ignore[invalid-argument-type]

    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    address = _adb.ServerAddress("adb.example.invalid", 5037, is_default=False)
    assert isinstance(_adb._can_connect(address, 1.0), socket.gaierror)
    with pytest.raises(LogprobeError) as info:
        _adb.connect(address, 1.0)
    assert info.value.code == "adb_server_unavailable"
    assert calls


def test_long_scope_id_fails_as_a_connection_error_not_a_unicode_error() -> None:
    address = _adb.resolve_server_address(f"tcp:[fe80::1%{'a' * 63}]:{free_port()}")
    error = _adb._can_connect(address, 1.0)
    assert isinstance(error, OSError)
    with pytest.raises(LogprobeError) as info:
        _adb.connect(address, 1.0)
    assert info.value.code == "adb_server_unavailable"


def test_scope_id_rejection_states_the_zone_rule() -> None:
    with pytest.raises(ValueError, match="zone") as info:
        _adb.resolve_server_address("tcp:[fe80::1%a b]:5037")
    assert "IP address" in str(info.value)
    with pytest.raises(ValueError, match="IP address") as other:
        _adb.resolve_server_address("tcp:[not-an-ip]:5037")
    assert "zone" not in str(other.value)


# --- adb lookup ------------------------------------------------------------


@pytest.fixture
def lookup_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """Four places an adb could live; PATH is restricted to an empty directory."""
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    return {
        "explicit": make_adb(tmp_path / "explicit"),
        "env": make_adb(tmp_path / "env"),
        "path": make_adb(tmp_path / "pathdir"),
        "home": make_adb(tmp_path / "home" / "platform-tools"),
        "sdk": make_adb(tmp_path / "sdk" / "platform-tools"),
    }


def test_find_adb_order(
    lookup_dirs: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANDROID_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(tmp_path / "sdk"))
    # Last: ANDROID_HOME before ANDROID_SDK_ROOT.
    assert_same_path(_adb.find_adb(), lookup_dirs["home"])
    (lookup_dirs["home"]).unlink()
    assert_same_path(_adb.find_adb(), lookup_dirs["sdk"])
    # PATH beats the SDK variables.
    monkeypatch.setenv("PATH", str(lookup_dirs["path"].parent))
    assert_same_path(_adb.find_adb(), lookup_dirs["path"])
    # LOGPROBE_ADB beats PATH.
    monkeypatch.setenv("LOGPROBE_ADB", str(lookup_dirs["env"]))
    assert_same_path(_adb.find_adb(), lookup_dirs["env"])
    # The explicit argument beats everything.
    assert_same_path(
        _adb.find_adb(str(lookup_dirs["explicit"])), lookup_dirs["explicit"]
    )


def test_find_adb_returns_none_when_nothing_matches(
    lookup_dirs: dict[str, Path],
) -> None:
    assert lookup_dirs  # PATH is restricted to an empty directory
    assert _adb.find_adb() is None


def test_find_adb_does_not_fall_back_from_a_wrong_explicit_path(
    lookup_dirs: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", str(lookup_dirs["path"].parent))
    assert _adb.find_adb(str(tmp_path / "missing" / ADB_NAME)) is None


# --- Windows lookup: never the current directory -------------------------------


@pytest.fixture
def windows_lookup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """A PATH directory and a current directory that each hold an ``adb.exe``."""
    on_path = tmp_path / "pathdir"
    cwd = tmp_path / "cwd"
    for directory in (on_path, cwd):
        directory.mkdir()
        (directory / "adb.exe").write_bytes(b"")
        (directory / "adb.exe").chmod(0o755)
    monkeypatch.chdir(cwd)
    # Lowercase, because the test file system may be case-sensitive.
    monkeypatch.setenv("PATHEXT", ".com;.exe;.bat;.cmd")
    return {"path": on_path, "cwd": cwd}


def test_windows_lookup_ignores_the_current_directory(
    windows_lookup: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = windows_lookup["cwd"].parent / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    assert _adb._which("adb", windows=True) is None


def test_windows_lookup_skips_empty_and_dot_entries(
    windows_lookup: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", os.pathsep.join(["", ".", str(windows_lookup["path"])]))
    found = _adb._which("adb", windows=True)
    assert found is not None
    assert Path(found).parent == windows_lookup["path"]
    monkeypatch.setenv("PATH", os.pathsep.join(["", "."]))
    assert _adb._which("adb", windows=True) is None


def test_windows_lookup_skips_every_relative_entry(
    windows_lookup: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Each of these would resolve against the current directory, which holds an
    # adb.exe directly and one in "bin".
    sub = windows_lookup["cwd"] / "bin"
    sub.mkdir()
    (sub / "adb.exe").write_bytes(b"")
    (sub / "adb.exe").chmod(0o755)
    for entry in ("./", ".//", "bin", "./bin", "bin/..", "bin/../."):
        monkeypatch.setenv("PATH", entry)
        assert _adb._which("adb", windows=True) is None, entry
    # An absolute entry after them is still searched.
    path = os.pathsep.join(["./", "bin", str(windows_lookup["path"])])
    monkeypatch.setenv("PATH", path)
    found = _adb._which("adb", windows=True)
    assert found is not None
    assert Path(found).parent == windows_lookup["path"]


def test_find_adb_on_a_windows_platform_skips_a_relative_sdk_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # shutil.which reads sys.platform on each call, so the lookups are recorded
    # instead of run: the test is about which directories are tried.
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delenv("LOGPROBE_ADB", raising=False)
    tried: list[str] = []

    def record(command: str, **_: object) -> None:
        tried.append(command)

    monkeypatch.setattr(_adb, "_which", record)
    root = tmp_path / "sdk"
    for variable in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        monkeypatch.delenv("ANDROID_HOME", raising=False)
        monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
        for relative in ("sdk", ".", "./sdk"):
            monkeypatch.setenv(variable, relative)
            tried.clear()
            assert _adb.find_adb() is None
            assert tried == ["adb"], (variable, relative)
        monkeypatch.setenv(variable, str(root))
        tried.clear()
        assert _adb.find_adb() is None
        assert tried == ["adb", str(root / "platform-tools" / "adb.exe")]


def test_windows_lookup_matches_pathext_case_insensitively(
    windows_lookup: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", str(windows_lookup["path"]))
    # "adb.exe" already ends in a PATHEXT extension, whatever the case of ".EXE".
    monkeypatch.setenv("PATHEXT", ".EXE")
    found = _adb._which("adb.exe", windows=True)
    assert found is not None
    assert Path(found).name == "adb.exe"
    # A bare name gets each PATHEXT extension appended; ".BAT" finds no adb.bat.
    monkeypatch.setenv("PATHEXT", ".BAT")
    assert _adb._which("adb", windows=True) is None


def test_find_adb_on_a_windows_platform_ignores_the_current_directory(
    windows_lookup: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("PATH", str(windows_lookup["cwd"].parent / "nowhere"))
    assert _adb.find_adb() is None
    monkeypatch.setenv("LOGPROBE_ADB", "adb")
    assert _adb.find_adb() is None
    monkeypatch.setenv("PATH", str(windows_lookup["path"]))
    assert_same_path(_adb.find_adb(), windows_lookup["path"] / "adb.exe")


def test_other_platforms_use_shutil_which(
    windows_lookup: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", str(windows_lookup["path"]))
    assert _adb._which("adb.exe", windows=False) == shutil.which("adb.exe")


# --- auto-start rule -------------------------------------------------------


class StartRecorder:
    """Stands in for subprocess.run; optionally brings a fake server up."""

    def __init__(
        self,
        bring_up: FakeAdbServer | None = None,
        *,
        returncode: int = 0,
        stdout: bytes = b"",
        stderr: bytes = b"",
    ) -> None:
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self.bring_up = bring_up
        self.result = (returncode, stdout, stderr)

    def __call__(
        self, argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((argv, kwargs))
        if self.bring_up is not None:
            self.bring_up.start()
        return subprocess.CompletedProcess(argv, *self.result)


@pytest.fixture
def closed_default_port(monkeypatch: pytest.MonkeyPatch) -> int:
    port = free_port()
    monkeypatch.setattr(_adb, "DEFAULT_PORT", port)
    return port


@pytest.fixture
def adb_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = make_adb(tmp_path / "bin")
    monkeypatch.setenv("LOGPROBE_ADB", str(path))
    return path


def recorder(
    monkeypatch: pytest.MonkeyPatch,
    bring_up: FakeAdbServer | None = None,
    **result: object,
) -> StartRecorder:
    rec = StartRecorder(bring_up, **result)  # ty: ignore[invalid-argument-type]
    monkeypatch.setattr(_adb.subprocess, "run", rec)
    return rec


def unavailable(**kwargs: object) -> LogprobeError:
    address = _adb.resolve_server_address(kwargs.pop("explicit", None))  # ty: ignore[invalid-argument-type]
    with pytest.raises(LogprobeError) as info:
        _adb.ensure_server(
            address, adb=None, start_server=bool(kwargs.pop("start_server", True))
        )
    assert info.value.code == "adb_server_unavailable"
    return info.value


def test_running_server_needs_no_start(
    monkeypatch: pytest.MonkeyPatch, fake: FakeAdbServer
) -> None:
    rec = recorder(monkeypatch)
    _adb.ensure_server(
        _adb.resolve_server_address(fake.address), adb=None, start_server=True
    )
    assert rec.calls == []


@pytest.mark.usefixtures("adb_on_path")
def test_start_server_disabled_runs_nothing(
    monkeypatch: pytest.MonkeyPatch, closed_default_port: int
) -> None:
    rec = recorder(monkeypatch)
    error = unavailable(start_server=False)
    assert rec.calls == []
    assert error.details["host"] == "127.0.0.1"
    assert error.details["port"] == closed_default_port
    assert error.details["auto_start_allowed"] is False
    assert "start_server is disabled" in str(error.details["reason"])


@pytest.mark.usefixtures("adb_on_path")
def test_explicit_address_runs_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = recorder(monkeypatch)
    port = free_port()
    error = unavailable(explicit=f"tcp:127.0.0.1:{port}")
    assert rec.calls == []
    assert error.details["port"] == port
    assert error.details["auto_start_allowed"] is False


@pytest.mark.usefixtures("adb_on_path")
def test_socket_variable_runs_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = recorder(monkeypatch)
    monkeypatch.setenv("ADB_SERVER_SOCKET", f"tcp:127.0.0.1:{free_port()}")
    error = unavailable()
    assert rec.calls == []
    assert error.details["auto_start_allowed"] is False


@pytest.mark.usefixtures("adb_on_path")
def test_port_variable_runs_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = recorder(monkeypatch)
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", str(free_port()))
    error = unavailable()
    assert rec.calls == []
    assert error.details["auto_start_allowed"] is False


def test_missing_adb_runs_nothing(
    monkeypatch: pytest.MonkeyPatch, closed_default_port: int, tmp_path: Path
) -> None:
    rec = recorder(monkeypatch)
    monkeypatch.setenv("PATH", str(tmp_path))
    error = unavailable()
    assert rec.calls == []
    assert error.details["port"] == closed_default_port
    assert error.details["auto_start_allowed"] is True
    assert "not found" in str(error.details["reason"])


def test_all_conditions_true_starts_server_exactly_once(
    monkeypatch: pytest.MonkeyPatch, closed_default_port: int, adb_on_path: Path
) -> None:
    server = FakeAdbServer(closed_default_port)
    try:
        rec = recorder(monkeypatch, bring_up=server)
        _adb.ensure_server(_adb.resolve_server_address(), adb=None, start_server=True)
        assert len(rec.calls) == 1
        argv, kwargs = rec.calls[0]
        assert len(argv) == 2
        assert_same_path(argv[0], adb_on_path)
        assert argv[1] == "start-server"
        assert kwargs["timeout"] == 20
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["capture_output"] is True
    finally:
        server.stop()


@pytest.mark.usefixtures("adb_on_path")
def test_start_server_gets_mdns_disabled_in_a_copy_of_the_environment(
    monkeypatch: pytest.MonkeyPatch, closed_default_port: int
) -> None:
    monkeypatch.delenv("ADB_MDNS", raising=False)
    monkeypatch.setenv("LOGPROBE_TEST_MARKER", "kept")
    server = FakeAdbServer(closed_default_port)
    try:
        rec = recorder(monkeypatch, bring_up=server)
        _adb.ensure_server(_adb.resolve_server_address(), adb=None, start_server=True)
    finally:
        server.stop()
    env = rec.calls[0][1]["env"]
    assert isinstance(env, dict)
    assert env["ADB_MDNS"] == "0"
    assert env["LOGPROBE_TEST_MARKER"] == "kept"
    assert "ADB_MDNS" not in os.environ


@pytest.mark.usefixtures("adb_on_path")
def test_start_server_overrides_an_existing_mdns_setting(
    monkeypatch: pytest.MonkeyPatch, closed_default_port: int
) -> None:
    monkeypatch.setenv("ADB_MDNS", "1")
    server = FakeAdbServer(closed_default_port)
    try:
        rec = recorder(monkeypatch, bring_up=server)
        _adb.ensure_server(_adb.resolve_server_address(), adb=None, start_server=True)
    finally:
        server.stop()
    assert rec.calls[0][1]["env"]["ADB_MDNS"] == "0"  # ty: ignore[not-subscriptable]
    assert os.environ["ADB_MDNS"] == "1"


@pytest.mark.usefixtures("adb_on_path")
def test_failed_start_reports_returncode_and_stderr(
    monkeypatch: pytest.MonkeyPatch, closed_default_port: int
) -> None:
    assert closed_default_port
    recorder(monkeypatch, returncode=1, stdout=b"out", stderr=b"boom \xff")
    error = unavailable()
    assert error.details["start_server_returncode"] == 1
    assert error.details["start_server_output"] == "boom \ufffd"


@pytest.mark.usefixtures("adb_on_path")
def test_failed_start_falls_back_to_stdout_and_caps_the_output(
    monkeypatch: pytest.MonkeyPatch, closed_default_port: int
) -> None:
    assert closed_default_port
    recorder(monkeypatch, returncode=0, stdout=b"x" * 5000)
    error = unavailable()
    assert error.details["start_server_returncode"] == 0
    assert error.details["start_server_output"] == "x" * 2000


@pytest.mark.usefixtures("adb_on_path")
def test_failed_start_is_reported_after_one_attempt(
    monkeypatch: pytest.MonkeyPatch, closed_default_port: int
) -> None:
    rec = recorder(monkeypatch)
    error = unavailable()
    assert len(rec.calls) == 1
    assert error.details["port"] == closed_default_port
    assert error.details["auto_start_allowed"] is True
    assert "still unreachable" in str(error.details["reason"])


@pytest.mark.usefixtures("adb_on_path")
def test_start_timeout_is_reported(
    monkeypatch: pytest.MonkeyPatch, closed_default_port: int
) -> None:
    def hang(argv: list[str], **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired(argv, 20, stderr=b"still starting")

    monkeypatch.setattr(_adb.subprocess, "run", hang)
    error = unavailable()
    assert closed_default_port == error.details["port"]
    assert "failed" in str(error.details["reason"])
    assert error.details["start_server_output"] == "still starting"
    assert "start_server_returncode" not in error.details


@pytest.mark.usefixtures("adb_on_path")
def test_start_timeout_without_output_has_no_output_detail(
    monkeypatch: pytest.MonkeyPatch, closed_default_port: int
) -> None:
    assert closed_default_port

    def hang(argv: list[str], **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired(argv, 20)

    monkeypatch.setattr(_adb.subprocess, "run", hang)
    assert "start_server_output" not in unavailable().details


@pytest.mark.usefixtures("adb_on_path")
def test_start_server_environment_is_cleaned_of_server_addresses(
    monkeypatch: pytest.MonkeyPatch, closed_default_port: int
) -> None:
    monkeypatch.setenv("ANDROID_ADB_SERVER_ADDRESS", "")
    monkeypatch.setenv("ADB_SERVER_SOCKET", "")
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", "")
    monkeypatch.setenv("LOGPROBE_TEST_MARKER", "kept")
    server = FakeAdbServer(closed_default_port)
    try:
        rec = recorder(monkeypatch, bring_up=server)
        _adb.ensure_server(_adb.resolve_server_address(), adb=None, start_server=True)
    finally:
        server.stop()
    env = rec.calls[0][1]["env"]
    assert isinstance(env, dict)
    for name in (
        "ADB_SERVER_SOCKET",
        "ANDROID_ADB_SERVER_ADDRESS",
        "ANDROID_ADB_SERVER_PORT",
    ):
        assert name not in env
        assert name in os.environ
    assert env["ADB_MDNS"] == "0"
    assert env["LOGPROBE_TEST_MARKER"] == "kept"


@pytest.mark.usefixtures("adb_on_path")
def test_adb_server_address_variable_prevents_auto_start(
    monkeypatch: pytest.MonkeyPatch, closed_default_port: int
) -> None:
    rec = recorder(monkeypatch)
    monkeypatch.setenv("ANDROID_ADB_SERVER_ADDRESS", "adb.example.invalid")
    error = unavailable()
    assert rec.calls == []
    assert error.details["port"] == closed_default_port
    assert error.details["auto_start_allowed"] is False
    reason = str(error.details["reason"])
    assert "ANDROID_ADB_SERVER_ADDRESS" in reason
    assert "does not use it" in reason
    assert "ADB_SERVER_SOCKET=tcp:IP:PORT" in reason


@pytest.mark.usefixtures("adb_on_path")
def test_adb_server_address_variable_is_not_used_for_the_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANDROID_ADB_SERVER_ADDRESS", "192.0.2.9")
    assert _adb.resolve_server_address() == _adb.ServerAddress(
        "127.0.0.1", _adb.DEFAULT_PORT, is_default=True
    )


@pytest.mark.usefixtures("adb_on_path")
def test_empty_adb_server_address_variable_still_allows_auto_start(
    monkeypatch: pytest.MonkeyPatch, closed_default_port: int
) -> None:
    monkeypatch.setenv("ANDROID_ADB_SERVER_ADDRESS", "")
    server = FakeAdbServer(closed_default_port)
    try:
        rec = recorder(monkeypatch, bring_up=server)
        _adb.ensure_server(_adb.resolve_server_address(), adb=None, start_server=True)
    finally:
        server.stop()
    assert len(rec.calls) == 1
