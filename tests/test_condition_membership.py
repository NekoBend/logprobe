"""Three-valued evaluation of conditions given who owns an entry's uid."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from itertools import product
from typing import Any

import pytest

from logprobe import And, Anr, Condition, Crash, Level, LogEntry, Not, Or, Package, Tag
from logprobe._conditions import MAX_NESTING, _Emitter

CHAIN = 10_000

# What a caller knows about an entry's uid: the owning watched packages, or None.
Owners = frozenset[str] | None
Verdict = bool | None


def entry(**changes: object) -> LogEntry:
    fields: dict[str, Any] = {
        "logged_at": datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC),
        "pid": 100,
        "tid": 101,
        "level": "I",
        "tag": "Tag",
        "message": "hello world",
        "raw": "raw",
    }
    fields.update(changes)
    return LogEntry(**fields)


def member(owners: Owners):
    def check(_entry: LogEntry, names: frozenset[str]) -> bool | None:
        if owners is None:
            return None
        return not owners.isdisjoint(names)

    return check


def judge(condition: Condition, e: LogEntry, owners: Owners) -> bool | None:
    return condition._compile_membership(member(owners))(e)


A = Package("com.a")
B = Package("com.b")
KNOWN = [
    frozenset(),
    frozenset({"com.a"}),
    frozenset({"com.b"}),
    frozenset({"com.a", "com.b"}),
]


# -- truth tables --------------------------------------------------------------

VALUES = [True, False, None]


def constant(value: Verdict) -> Condition:
    """A condition whose three-valued result is ``value`` for the test entry."""
    if value is None:
        return A  # unknown owners
    return Tag("Tag") if value else Tag("other")


@pytest.mark.parametrize(("left", "right"), list(product(VALUES, VALUES)))
def test_and_or_truth_tables(left: Verdict, right: Verdict) -> None:
    def kleene_and() -> bool | None:
        if left is False or right is False:
            return False
        return None if left is None or right is None else True

    def kleene_or() -> bool | None:
        if left is True or right is True:
            return True
        return None if left is None or right is None else False

    e = entry()
    assert judge(constant(left) & constant(right), e, None) is kleene_and()
    assert judge(constant(left) | constant(right), e, None) is kleene_or()


@pytest.mark.parametrize("value", VALUES)
def test_not_truth_table(value: Verdict) -> None:
    expected = None if value is None else not value
    assert judge(~constant(value), entry(), None) is expected


def test_unknown_unless_a_decisive_term_outweighs_the_package_term() -> None:
    e = entry(tag="x")
    assert judge(A | Tag("x"), e, None) is True
    assert judge(A & Tag("x"), e, None) is None
    assert judge(A & Tag("y"), e, None) is False
    assert judge(A | Tag("y"), e, None) is None
    assert judge(~(A & Tag("y")), e, None) is True
    assert judge(Not(A | Tag("x")), e, None) is False
    # Decisive terms win wherever they stand.
    assert judge(Or(A, B, Tag("x")), e, None) is True
    assert judge(And(A, B, Tag("y")), e, None) is False
    assert judge(And(A, Tag("x"), B), e, None) is None


def test_a_condition_without_packages_is_never_unknown() -> None:
    condition = (Level >= "W") | Tag("a")
    for level, tag in product("IW", ["a", "b"]):
        e = entry(level=level, tag=tag)
        assert judge(condition, e, None) is condition(e)


# -- shared uids ---------------------------------------------------------------


@pytest.mark.parametrize("owners", KNOWN)
def test_shared_uid(owners: frozenset[str]) -> None:
    has_a, has_b = "com.a" in owners, "com.b" in owners
    e = entry()
    assert judge(A, e, owners) is has_a
    assert judge(B, e, owners) is has_b
    assert judge(A & B, e, owners) is (has_a and has_b)
    assert judge(A | B, e, owners) is (has_a or has_b)
    assert judge(~A, e, owners) is (not has_a)
    assert judge(~A & ~B, e, owners) is (not has_a and not has_b)
    assert judge(Package("com.a", "com.b"), e, owners) is (has_a or has_b)


def test_shared_uid_with_both_watched() -> None:
    both = frozenset({"com.a", "com.b"})
    e = entry()
    assert judge(A, e, both) is True
    assert judge(B, e, both) is True
    assert judge(A & B, e, both) is True
    assert judge(~A, e, both) is False


def test_member_receives_the_entry_and_the_names() -> None:
    seen: list[tuple[LogEntry, frozenset[str]]] = []

    def record(e: LogEntry, names: frozenset[str]) -> bool | None:
        seen.append((e, names))
        return True

    e = entry()
    assert Package("com.a", "com.b")._compile_membership(record)(e) is True
    assert seen == [(e, frozenset({"com.a", "com.b"}))]


def test_entry_package_field_is_ignored() -> None:
    e = entry(package="com.a")
    assert judge(A, e, frozenset()) is False
    assert judge(B, e, frozenset({"com.b"})) is True


# -- Crash and Anr -------------------------------------------------------------


def java_crash(name: str) -> LogEntry:
    return entry(tag="AndroidRuntime", level="E", message=f"Process: {name}, PID: 1234")


def anr_line(name: str) -> LogEntry:
    return entry(tag="ActivityManager", level="E", message=f"ANR in {name} (c/.Main)")


def never(_entry: LogEntry, _names: frozenset[str]) -> bool | None:
    pytest.fail("member must not be called for Crash or Anr")


def test_crash_and_anr_with_package_read_the_message_not_the_owners() -> None:
    crash = Crash(package="com.a")
    anr = Anr(package="com.a")
    for owners in [None, *KNOWN]:
        assert judge(crash, java_crash("com.a"), owners) is True
        assert judge(crash, java_crash("com.a:svc"), owners) is True
        assert judge(crash, java_crash("com.ab"), owners) is False
        assert judge(anr, anr_line("com.a"), owners) is True
        assert judge(anr, anr_line("com.b"), owners) is False
    assert crash._compile_membership(never)(java_crash("com.a")) is True
    assert anr._compile_membership(never)(anr_line("com.b")) is False
    fatal = entry(tag="AndroidRuntime", level="E", message="FATAL EXCEPTION: main")
    assert Crash()._compile_membership(never)(fatal) is True
    assert Anr()._compile_membership(never)(anr_line("x")) is True


def test_crash_combined_with_package() -> None:
    condition = Crash(package="com.a") | A
    assert judge(condition, java_crash("com.a"), None) is True
    assert judge(condition, java_crash("com.b"), None) is None
    assert judge(condition, java_crash("com.b"), frozenset()) is False
    assert judge(Crash(package="com.a") & A, java_crash("com.b"), None) is False


# -- long chains ---------------------------------------------------------------


def test_long_chains_do_not_recurse() -> None:
    tags = [Tag(f"t{i}") for i in range(CHAIN)]
    conj = And(A, *tags)
    disj = Or(*tags, A)
    assert judge(conj, entry(tag="t0"), None) is False
    assert judge(conj, entry(tag="t0"), frozenset({"com.a"})) is False
    assert judge(disj, entry(tag="t9999"), None) is True
    assert judge(disj, entry(tag="zzz"), None) is None
    assert judge(disj, entry(tag="zzz"), frozenset()) is False
    assert judge(disj, entry(tag="zzz"), frozenset({"com.a"})) is True
    every = And(*[Not(Tag(f"x{i}")) for i in range(CHAIN)], A)
    assert judge(every, entry(), None) is None
    assert judge(every, entry(), frozenset({"com.a"})) is True


def test_nested_to_the_limit() -> None:
    condition: Condition = A
    for i in range(MAX_NESTING):
        condition = Not(condition) if i % 2 == 0 else And(condition, Tag("Tag"))
    assert condition._nesting == MAX_NESTING
    flips = (MAX_NESTING + 1) // 2
    expected_when_owned = flips % 2 == 0
    assert judge(condition, entry(), None) is None
    assert judge(condition, entry(), frozenset({"com.a"})) is expected_when_owned


# -- equivalence with compile() -----------------------------------------------

CONDITIONS = [
    Tag("a"),
    (Level >= "W") & Tag("a"),
    Crash(package="com.a") | Tag("b"),
    Anr(package="com.b") & ~Tag("a"),
    ~(Tag("a") | Tag("b")),
    Not(And(Level >= "E", Or(Tag("a"), Tag("c")))),
]


def entries() -> list[LogEntry]:
    return [
        entry(tag=tag, level=level) for tag, level in product(["a", "b", "c"], "IWE")
    ] + [java_crash("com.a"), java_crash("com.b"), anr_line("com.b")]


@pytest.mark.parametrize("condition", CONDITIONS, ids=repr)
def test_same_as_compile_when_the_condition_has_no_package(
    condition: Condition,
) -> None:
    plain = condition.compile()
    for e in entries():
        assert judge(condition, e, None) is plain(e)


def test_same_as_compile_when_membership_is_known() -> None:
    # The owners of an entry are the package it carries (none when it carries
    # no package), so compile() and the three-valued function must agree.
    def by_field(e: LogEntry, names: frozenset[str]) -> bool | None:
        return e.package in names

    mixed = [
        A,
        A & Tag("a"),
        A | Crash(package="com.b"),
        ~A & ~B,
        Or(And(A, Tag("b")), And(B, Not(Tag("b")))),
        Not(Or(A, And(B, Tag("c")))),
        *CONDITIONS,
    ]
    for condition in mixed:
        plain = condition.compile()
        three = condition._compile_membership(by_field)
        for e, package in product(entries(), [None, "com.a", "com.b"]):
            with_package = dataclasses.replace(e, package=package)
            assert three(with_package) is plain(with_package)


def test_compile_is_unchanged_and_cached() -> None:
    condition = Package("com.a") & Tag("a")
    first = condition.compile()
    assert condition._compile_membership(member(None)) is not first
    assert condition.compile() is first
    assert first(entry(tag="a", package="com.a")) is True
    assert first(entry(tag="a")) is False


def test_tautology_and_contradiction_stay_unknown() -> None:
    assert judge(A | ~A, entry(), None) is None
    assert judge(A & ~A, entry(), None) is None
    assert judge(A | ~A, entry(), frozenset()) is True
    assert judge(A & ~A, entry(), frozenset({"com.a"})) is False


def test_owner_free_subtrees_are_compiled_once() -> None:
    def unused(_e: LogEntry, _names: frozenset[str]) -> bool | None:
        return None

    free = (Level >= "E") | Tag("x") | Tag("y")
    negated = ~Tag("chatty")
    condition = A & free & negated
    assert condition._has_package()
    assert not free._has_package()
    assert not (Crash(package="com.a") | Tag("x"))._has_package()
    # No Package anywhere: the cached compile() function itself is returned.
    assert free._compile_membership(unused) is free.compile()
    assert negated._compile_membership(unused) is negated.compile()
    # Order of member calls and short-circuiting are kept around a run.
    calls: list[str] = []

    def member(_e: LogEntry, _names: frozenset[str]) -> bool | None:
        calls.append("m")
        return True

    fn = (Tag("p") | A | Tag("q") | Tag("r"))._compile_membership(member)
    assert fn(entry(tag="p")) is True
    assert calls == []
    assert fn(entry(tag="z")) is True
    assert calls == ["m"]


def test_owner_free_children_of_a_mixed_junction_share_one_compiled_function(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builds: list[str] = []
    original = _Emitter.build

    def counting(self: _Emitter, expression: str):
        builds.append(expression)
        return original(self, expression)

    monkeypatch.setattr(_Emitter, "build", counting)
    # Three adjacent owner-free children (fresh, so nothing is cached yet),
    # then a Package term, then a second run of two.
    condition = And(Tag("g1"), Tag("g2"), Level >= "W", A, Tag("h1"), Tag("h2"))
    fn = condition._compile_membership(member(frozenset({"com.a"})))
    # One build per run, not one per leaf.
    assert len(builds) == 2
    assert fn(entry(tag="g1")) is False
    assert len(builds) == 2


def test_owner_free_runs_are_not_rebuilt_by_a_second_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builds: list[str] = []
    original = _Emitter.build

    def counting(self: _Emitter, expression: str):
        builds.append(expression)
        return original(self, expression)

    monkeypatch.setattr(_Emitter, "build", counting)
    condition = And(Package("com.b"), Tag("r1") | Tag("r2"), ~Tag("r3"))
    first = condition._compile_membership(member(frozenset({"com.b"})))
    built = len(builds)
    second = condition._compile_membership(member(None))
    assert len(builds) == built
    assert first(entry(tag="r1")) is True
    assert second(entry(tag="r1")) is None
