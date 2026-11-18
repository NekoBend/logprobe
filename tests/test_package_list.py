"""The list of every installed package: commands, parsers and outcomes."""

from __future__ import annotations

import re
from collections import Counter

import pytest

from logprobe._attribution import (
    DUMPSYS_PACKAGES_ARGV,
    PM_LIST_ARGV,
    Failed,
    Fallback,
    Listed,
    parse_dumpsys_packages,
    parse_pm_list,
    read_dumpsys_packages,
    read_pm_list,
)
from tests.device_facts import LEVELS, level_dir, load, step

# First lines of `pm list packages -U` on API 36 (probe of 2026-11-18).
PM_36_HEAD = """\
package:com.android.companiondevicemanager.auto_generated_characteristics_rro uid:10035
package:com.android.systemui.auto_generated_rro_vendor__ uid:10088
package:com.google.android.providers.media.module uid:10211
package:com.google.android.overlay.permissioncontroller uid:10074
package:com.google.android.overlay.googlewebview uid:10068
package:com.android.calllogbackup uid:10097
"""

# `pm list packages -U` on API 24: printed on stdout, with exit status 0.
PM_24_UNKNOWN = b"Error: Unknown option: -U\n"

# First lines of `dumpsys package packages` on API 24 (probe of 2026-11-18).
DUMPSYS_24_HEAD = """\
Packages:
  Package [com.android.smoketest] (ac4d0b2):
    userId=10075
    pkg=Package{90f4803 com.android.smoketest}
    codePath=/data/app/SmokeTestApp
    resourcePath=/data/app/SmokeTestApp
    legacyNativeLibraryDir=/data/app/SmokeTestApp/lib
    primaryCpuAbi=null
    secondaryCpuAbi=null
    versionCode=24 minSdk=8 targetSdk=8
    versionName=7.0
    splits=[base]
"""

# First lines of `dumpsys package packages` on API 36 (probe of 2026-11-18),
# a package with a shared user.
DUMPSYS_36_HEAD = """\
Packages:
  Package [com.google.android.networkstack.tethering] (d4f52ba):
    appId=1073
    sharedUser=SharedUserSetting{d8cc3c4 android.uid.networkstack/1073}
    pkg=Package{62d42ad com.google.android.networkstack.tethering}
    codePath=/apex/com.android.tethering/priv-app/TetheringGoogle@360527520
    resourcePath=/apex/com.android.tethering/priv-app/TetheringGoogle@360527520
    legacyNativeLibraryDir=/apex/com.android.tethering/priv-app/TetheringGoogle@360527520/lib
    extractNativeLibs=false
    primaryCpuAbi=x86_64
    secondaryCpuAbi=null
    cpuAbiOverride=null
"""

# Contract for the recordings, written from the recorded text.
PM_LINE = re.compile(r"package:(\S+) uid:(\d+)")
HEADER_PREFIX = "  Package ["


def recorded(level: int, name: str) -> dict:
    return step(load(level_dir(level), "C03"), name)


def recorded_text(level: int, name: str) -> str:
    return "\n".join(recorded(level, name)["stdout"])


def recorded_records(level: int) -> list[tuple[str, int]]:
    """(name, uid) of every record in the recorded listing, in order."""
    lines = recorded(level, "dumpsys_package_packages")["stdout"]
    pairs = []
    for index, line in enumerate(lines):
        if line.startswith(HEADER_PREFIX):
            name = line[len(HEADER_PREFIX) : line.index("]")]
            pairs.append((name, int(lines[index + 1].split("=")[1])))
    return pairs


# -- Commands --------------------------------------------------------------------


def test_list_commands() -> None:
    assert PM_LIST_ARGV == ("pm", "list", "packages", "-U")
    assert DUMPSYS_PACKAGES_ARGV == ("dumpsys", "package", "packages")


# -- pm list packages -U: parser ---------------------------------------------------


def test_pm_parser_reads_the_probe_head() -> None:
    assert parse_pm_list(PM_36_HEAD) == {
        "com.android.companiondevicemanager.auto_generated_characteristics_rro": (
            10035
        ),
        "com.android.systemui.auto_generated_rro_vendor__": 10088,
        "com.google.android.providers.media.module": 10211,
        "com.google.android.overlay.permissioncontroller": 10074,
        "com.google.android.overlay.googlewebview": 10068,
        "com.android.calllogbackup": 10097,
    }


def test_pm_parser_on_the_api36_recording() -> None:
    text = recorded_text(36, "pm_list_packages_U")
    facts = load(level_dir(36), "C03")["facts"]
    expected = {}
    for line in text.splitlines():
        found = PM_LINE.fullmatch(line)
        assert found is not None, line
        expected.setdefault(found.group(1), int(found.group(2)))
    uids = parse_pm_list(text)
    assert uids == expected
    assert len(uids) == facts["pm_U_packages"] == 248
    # Shared uids are several names with the same uid.
    shared = Counter(uids.values())
    assert shared[1000] >= 10
    assert shared[10097] == 5
    assert uids["com.android.settings"] == 1000
    for uid, names in facts["app_uid_tokens_to_packages"].items():
        for name in names:
            assert uids[name] == int(uid), name


def test_pm_list_agrees_with_dumpsys_on_the_api36_recording() -> None:
    from_pm = parse_pm_list(recorded_text(36, "pm_list_packages_U"))
    from_dumpsys = parse_dumpsys_packages(recorded_text(36, "dumpsys_package_packages"))
    assert from_pm is not None
    assert from_dumpsys is not None
    assert {name: from_dumpsys[name] for name in from_pm} == from_pm


def test_pm_parser_shared_uids() -> None:
    text = "package:a uid:1000\npackage:b uid:1000\npackage:c uid:10106\n"
    assert parse_pm_list(text) == {"a": 1000, "b": 1000, "c": 10106}


def test_pm_parser_skips_blank_unrelated_and_crlf_lines() -> None:
    text = "\r\nWARNING: linker: something\r\n  package:a uid:10001  \r\n\r\nb\r\n"
    assert parse_pm_list(text) == {"a": 10001}


def test_pm_parser_keeps_the_first_line_of_a_name() -> None:
    assert parse_pm_list("package:a uid:10001\npackage:a uid:10002\n") == {"a": 10001}


def test_pm_parser_takes_the_first_uid_of_several_users() -> None:
    assert parse_pm_list("package:a uid:10001,1010001\n") == {"a": 10001}


@pytest.mark.parametrize(
    "line",
    [
        "package:a",  # a device that ignores -U
        "package:a uid:",
        "package:a uid:abc",
        "package:a uid:-5",
        "package:a uid:12345678901",  # eleven digits: not a uid
        "package:a uid:4294967296",  # above the 32-bit range
        "package:a uid:5000010042",  # app id 10042 if taken modulo 100000
        "package:a uid:10042,5000010042",
        "package:a uid:\u0661\u0660\u0660\u0660\u0661",  # not ASCII digits
        "package:a uid:10001,",
        "package:a uid:10001,1010002",  # two app ids for one package
        "package:a uid:10001 extra",
        "package: uid:10001",
    ],
)
def test_pm_parser_rejects_a_package_line_without_usable_uid(line: str) -> None:
    assert parse_pm_list(f"package:b uid:10002\n{line}\n") is None


@pytest.mark.parametrize("text", ["", "\n\n", "Error: something\n"])
def test_pm_parser_without_package_lines(text: str) -> None:
    assert parse_pm_list(text) is None


def test_pm_parser_on_a_large_output() -> None:
    count = 200_000
    text = "".join(f"package:p{i} uid:{10000 + i % 9000}\r\n" for i in range(count))
    uids = parse_pm_list(text)
    assert uids is not None
    assert len(uids) == count
    assert uids["p9001"] == 10001


# -- pm list packages -U: outcome --------------------------------------------------


def test_pm_outcome_lists_the_recorded_api36_output() -> None:
    rec = recorded(36, "pm_list_packages_U")
    stdout = "\n".join(rec["stdout"]).encode()
    outcome = read_pm_list(rec["rc"], stdout, b"")
    assert isinstance(outcome, Listed)
    assert len(outcome.uids) == 248


def test_pm_outcome_falls_back_on_the_recorded_api24_output() -> None:
    rec = recorded(24, "pm_list_packages_U")
    assert rec["rc"] == 0
    stdout = "\n".join(rec["stdout"]).encode()
    assert read_pm_list(rec["rc"], stdout, b"") == Fallback(unsupported=True)


@pytest.mark.parametrize("exit_status", [0, 1, 255, None])
def test_pm_outcome_unknown_option_is_decided_by_the_output(
    exit_status: int | None,
) -> None:
    assert read_pm_list(exit_status, PM_24_UNKNOWN, b"") == Fallback(unsupported=True)
    assert read_pm_list(exit_status, b"", PM_24_UNKNOWN) == Fallback(unsupported=True)
    crlf = b"\r\nError: Unknown option: -U\r\n"
    assert read_pm_list(exit_status, crlf, b"") == Fallback(unsupported=True)


@pytest.mark.parametrize(
    "stdout",
    [
        b"Error: Unknown option: -u\n",
        b"Error: Unknown option: -Ux\n",
        b"Error: Unknown option: --U\n",
        b"Error: -U was not understood\n",
    ],
)
def test_pm_outcome_other_errors_are_not_the_unknown_option(stdout: bytes) -> None:
    assert read_pm_list(0, stdout, b"") == Fallback(unsupported=False)


def test_pm_outcome_unparsable_output_with_exit_zero_falls_back() -> None:
    assert read_pm_list(0, b"", b"") == Fallback(unsupported=False)
    bare = b"package:a\npackage:b\n"
    assert read_pm_list(0, bare, b"") == Fallback(unsupported=False)
    assert read_pm_list(0, b"package:a uid:1x\n", b"") == Fallback(unsupported=False)


def test_pm_outcome_non_zero_exit_fails() -> None:
    outcome = read_pm_list(1, b"package:a uid:10001\n", b"Failure\n")
    assert outcome == Failed("did not succeed (exit status 1)", 1)


def test_pm_outcome_without_exit_status_fails() -> None:
    outcome = read_pm_list(None, b"package:a uid:10001\n", b"")
    assert outcome == Failed("ended without an exit status", None)
    assert read_pm_list(None, b"", b"") == Failed("ended without an exit status", None)


def test_pm_outcome_decodes_invalid_utf8() -> None:
    outcome = read_pm_list(0, b"\xff\xfe junk\npackage:a uid:10001\n", b"")
    assert outcome == Listed({"a": 10001})


# -- dumpsys package packages: parser ------------------------------------------------


def test_dumpsys_parser_reads_the_probe_heads() -> None:
    assert parse_dumpsys_packages(DUMPSYS_24_HEAD) == {"com.android.smoketest": 10075}
    assert parse_dumpsys_packages(DUMPSYS_36_HEAD) == {
        "com.google.android.networkstack.tethering": 1073
    }


@pytest.mark.parametrize("level", LEVELS)
def test_dumpsys_parser_on_the_recordings(level: int) -> None:
    facts = load(level_dir(level), "C03")["facts"]
    records = recorded_records(level)
    assert len(records) == facts["dumpsys_packages"]
    expected: dict[str, int] = {}
    for name, uid in records:
        expected.setdefault(name, uid)
    uids = parse_dumpsys_packages(recorded_text(level, "dumpsys_package_packages"))
    assert uids == expected
    for uid, names in facts["app_uid_tokens_to_packages"].items():
        for name in names:
            assert uids[name] == int(uid), name


def test_dumpsys_parser_repeated_records_on_api36() -> None:
    # The API 36 listing repeats some names near its end (the hidden system
    # packages); the first record decides.
    records = recorded_records(36)
    repeated = [
        name for name, count in Counter(n for n, _ in records).items() if count > 1
    ]
    assert len(repeated) == 3
    uids = parse_dumpsys_packages(recorded_text(36, "dumpsys_package_packages"))
    assert uids is not None
    for name in repeated:
        assert uids[name] == next(uid for n, uid in records if n == name)


def test_dumpsys_parser_full_records_with_shared_users() -> None:
    text = """\
Packages:
  Package [com.android.providers.contacts] (1a2b3c4):
    userId=10002
    sharedUser=SharedUserSetting{5d6e7f8 android.uid.shared/10002}
    pkg=Package{9a0b1c2 com.android.providers.contacts}
  Package [com.android.providers.userdictionary] (2b3c4d5):
    userId=10002
    sharedUser=SharedUserSetting{5d6e7f8 android.uid.shared/10002}
  Package [com.android.settings] (3c4d5e6):
    appId=1000
    sharedUser=SharedUserSetting{6e7f8a9 android.uid.system/1000}

Shared users:
  SharedUser [android.uid.shared] (5d6e7f8):
    userId=10002
"""
    assert parse_dumpsys_packages(text) == {
        "com.android.providers.contacts": 10002,
        "com.android.providers.userdictionary": 10002,
        "com.android.settings": 1000,
    }


def test_dumpsys_parser_crlf_blank_and_unrelated_lines() -> None:
    text = (
        "Database versions:\r\n  Internal:\r\n    sdkVersion=36\r\n\r\n"
        "Packages:\r\n  Package [a] (1):\r\n\r\n    appId=10001\r\n"
        "Package [b]:\r\n    userId=10002\r\n"
    )
    assert parse_dumpsys_packages(text) == {"a": 10001, "b": 10002}


def test_dumpsys_parser_skips_a_record_without_uid() -> None:
    text = """\
  Package [a] (1):
    versionCode=1
  Package [b] (2):
    appId=10002
  Package [c] (3):
Shared users:
  SharedUser [x]:
    userId=10008
"""
    assert parse_dumpsys_packages(text) == {"b": 10002}


def test_dumpsys_parser_keeps_the_first_uid_of_a_record() -> None:
    text = "  Package [a] (1):\n    userId=10001\n    appId=10005\n    userId=10009\n"
    assert parse_dumpsys_packages(text) == {"a": 10001}


def test_dumpsys_parser_duplicate_records_first_with_uid_wins() -> None:
    text = """\
  Package [a] (1):
    versionCode=1
  Package [a] (2):
    appId=10002
  Package [a] (3):
    appId=10003
"""
    assert parse_dumpsys_packages(text) == {"a": 10002}


def test_dumpsys_parser_ignores_headers_inside_a_record_and_mentions() -> None:
    text = """\
  Package [a] (1):
    appId=10001
    Package [nested] (9):
      appId=10009
  Package [b] is mentioned here without a record
    appId=10010
  Package [c]
    appId=10003
"""
    assert parse_dumpsys_packages(text) == {"a": 10001, "c": 10003}


@pytest.mark.parametrize(
    "value",
    [
        "abc",
        "",
        "-1",
        "12345678901",
        "4294967296",
        "5000010042",
        "10001x",
        "1e5",
        "\u0661\u0660\u0660\u0660\u0661",
    ],
)
def test_dumpsys_parser_skips_values_that_are_not_uids(value: str) -> None:
    text = (
        f"  Package [a] (1):\n    appId={value}\n  Package [b] (2):\n    appId=10002\n"
    )
    assert parse_dumpsys_packages(text) == {"b": 10002}


def test_dumpsys_parser_takes_a_later_uid_after_a_bad_one() -> None:
    text = "  Package [a] (1):\n    userId=abc\n    userId=10001 gids=[3003]\n"
    assert parse_dumpsys_packages(text) == {"a": 10001}
    text = "  Package [a] (1):\n    userId=5000010042\n    appId=10001\n"
    assert parse_dumpsys_packages(text) == {"a": 10001}


def test_the_largest_uid_is_accepted() -> None:
    assert parse_pm_list("package:a uid:4294967295\n") == {"a": 4294967295}
    text = "  Package [a] (1):\n    appId=4294967295\n"
    assert parse_dumpsys_packages(text) == {"a": 4294967295}


@pytest.mark.parametrize(
    "text",
    [
        "",
        "\r\n\r\n",
        "Error: Could not access the Package Manager. Is the system running?\n",
        "  Package [a] (1):\n    versionCode=1\n",
    ],
)
def test_dumpsys_parser_without_uids(text: str) -> None:
    assert parse_dumpsys_packages(text) is None


def test_dumpsys_parser_on_a_large_output() -> None:
    count = 50_000
    filler = "".join(f"    field{k}=value\n" for k in range(15))
    text = "Packages:\n" + "".join(
        f"  Package [p{i}] ({i:x}):\n    appId={10000 + i % 9000}\n{filler}"
        for i in range(count)
    )
    uids = parse_dumpsys_packages(text)
    assert uids is not None
    assert len(uids) == count
    assert uids["p9001"] == 10001


# -- dumpsys package packages: outcome -----------------------------------------------


@pytest.mark.parametrize("level", LEVELS)
def test_dumpsys_outcome_lists_the_recordings(level: int) -> None:
    rec = recorded(level, "dumpsys_package_packages")
    stdout = "\n".join(rec["stdout"]).encode()
    outcome = read_dumpsys_packages(rec["rc"], stdout)
    assert isinstance(outcome, Listed)
    assert len(outcome.uids) == len(dict(recorded_records(level)))


def test_dumpsys_outcome_shared_user_record() -> None:
    outcome = read_dumpsys_packages(0, DUMPSYS_36_HEAD.encode())
    assert outcome == Listed({"com.google.android.networkstack.tethering": 1073})


def test_dumpsys_outcome_has_no_fallback() -> None:
    assert read_dumpsys_packages(0, PM_24_UNKNOWN) == Failed(
        "printed no package list", 0
    )


@pytest.mark.parametrize(
    "stdout",
    [b"", b"Error: Could not access the Package Manager. Is the system running?\n"],
)
def test_dumpsys_outcome_unusable_output_fails(stdout: bytes) -> None:
    assert read_dumpsys_packages(0, stdout) == Failed("printed no package list", 0)


def test_dumpsys_outcome_non_zero_exit_fails() -> None:
    outcome = read_dumpsys_packages(2, DUMPSYS_24_HEAD.encode())
    assert outcome == Failed("did not succeed (exit status 2)", 2)


def test_dumpsys_outcome_without_exit_status_fails() -> None:
    outcome = read_dumpsys_packages(None, DUMPSYS_24_HEAD.encode())
    assert outcome == Failed("ended without an exit status", None)


def test_dumpsys_parser_reads_no_uid_after_the_record_ended() -> None:
    # A record without a uid, then a uid line at the header's own indentation:
    # that line is outside the record and must not give the record a uid.
    text = (
        "Packages:\n"
        "  Package [a.b] (1):\n"
        "    codePath=/data/app/a.b\n"
        "  userId=10001\n"
        "  Package [c.d] (2):\n"
        "    userId=10002\n"
    )
    assert parse_dumpsys_packages(text) == {"c.d": 10002}
