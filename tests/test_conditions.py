"""Filter conditions: semantics, flattening, long chains, JSON and introspection."""

from __future__ import annotations

import copy
import dataclasses
import enum
import json
import pickle
import re
from datetime import UTC, datetime
from functools import reduce
from operator import and_, or_
from typing import Any, cast

import pytest

from logprobe import (
    And,
    Anr,
    Condition,
    Crash,
    Level,
    LogEntry,
    LogLevel,
    Message,
    Not,
    Or,
    Package,
    Pid,
    Tag,
    Tid,
    Uid,
)
from logprobe._conditions import MAX_NESTING, build_condition

CHAIN = 10_000


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


LEVELS = "VDIWEF"


# -- Level ------------------------------------------------------------------------


@pytest.mark.parametrize("letter_bound", list(LEVELS))
def test_level_comparisons_follow_the_order(letter_bound: str) -> None:
    bound = cast("LogLevel", letter_bound)
    index = LEVELS.index(bound)
    cases = {
        Level >= bound: lambda i: i >= index,
        Level > bound: lambda i: i > index,
        Level <= bound: lambda i: i <= index,
        Level < bound: lambda i: i < index,
        Level == bound: lambda i: i == index,
        Level != bound: lambda i: i != index,
    }
    for condition, expected in cases.items():
        for i, letter in enumerate(LEVELS):
            assert condition(entry(level=letter)) is expected(i), (condition, letter)


def test_level_is_a_singleton_and_comparison_with_the_level_on_the_right() -> None:
    assert repr(Level) == "Level"
    assert (Level >= "W") == ("W" <= Level)  # noqa: SIM300
    assert isinstance(Level >= "W", Condition)


@pytest.mark.parametrize("bad", ["X", "", "w", "WARN", "WE"])
def test_level_rejects_unknown_strings(bad: LogLevel) -> None:
    for build in (
        lambda: Level >= bad,
        lambda: Level > bad,
        lambda: Level <= bad,
        lambda: Level < bad,
        lambda: Level == bad,
        lambda: Level != bad,
    ):
        with pytest.raises(ValueError, match="not a log level"):
            build()


def test_level_rejects_non_strings() -> None:
    with pytest.raises(TypeError):
        _ = Level >= cast("LogLevel", 3)
    with pytest.raises(TypeError):
        _ = Level == cast("str", None)


def test_level_empty_range_matches_nothing() -> None:
    nothing = Level < "V"
    assert [nothing(entry(level=letter)) for letter in LEVELS] == [False] * 6


# -- Tag, Pid, Tid, Uid, Package, Message ------------------------------------------


def test_tag_is_an_exact_match_of_any_name() -> None:
    condition = Tag("ActivityManager", "WindowManager")
    assert condition(entry(tag="ActivityManager"))
    assert condition(entry(tag="WindowManager"))
    assert not condition(entry(tag="Activity"))
    assert not condition(entry(tag="activitymanager"))
    assert not condition(entry(tag="ActivityManager "))
    assert Tag("")(entry(tag=""))


def test_pid_and_tid_match_their_own_field() -> None:
    assert Pid(1, 2)(entry(pid=2))
    assert not Pid(1, 2)(entry(pid=3, tid=2))
    assert Tid(7)(entry(tid=7))
    assert not Tid(7)(entry(pid=7, tid=8))


def test_uid_none_never_matches() -> None:
    assert Uid(1000, 2000)(entry(uid=2000))
    assert not Uid(1000)(entry(uid=None))
    assert not Uid(1000)(entry(uid=1001))
    assert not (Uid(0))(entry(uid=None))


def test_package_matches_the_attributed_package() -> None:
    assert Package("com.x", "com.y")(entry(package="com.y"))
    assert not Package("com.x")(entry(package=None))
    assert not Package("com.x")(entry(package="com.xy"))


def test_members_validate_their_values() -> None:
    for cls in (Tag, Pid, Tid, Uid, Package):
        with pytest.raises(ValueError, match="at least one"):
            cls()
    with pytest.raises(TypeError):
        Tag(1)
    with pytest.raises(TypeError):
        Pid("1")
    with pytest.raises(TypeError):
        Pid(cast("int", True))  # noqa: FBT003
    with pytest.raises(TypeError):
        Package(None)


def test_members_ignore_duplicates_and_keep_written_order() -> None:
    assert Tag("b", "a", "b")._values == ("b", "a")
    assert Tag("a", "b") == Tag("b", "a")
    assert hash(Tag("a", "b")) == hash(Tag("b", "a"))


def test_message_contains_is_a_substring_test() -> None:
    assert Message.contains("lo wo")(entry())
    assert not Message.contains("LO")(entry())
    assert Message.contains("")(entry(message=""))
    with pytest.raises(TypeError):
        Message.contains(cast("str", 1))


def test_message_matches_searches_and_is_not_anchored() -> None:
    condition = Message.matches(r"w\w+d$")
    assert condition(entry())
    assert not Message.matches(r"^world")(entry())
    assert Message.matches("")(entry(message=""))
    assert repr(Message) == "Message"


def test_message_matches_compiles_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    real = re.compile
    monkeypatch.setattr(re, "compile", lambda *a: calls.append(a) or real(*a))
    condition = Message.matches("a+")
    assert len(calls) == 1
    predicate = condition.compile()
    for _ in range(3):
        predicate(entry(message="caat"))
        condition(entry(message="caat"))
    assert len(calls) == 1


def test_message_matches_rejects_a_bad_pattern() -> None:
    with pytest.raises(ValueError, match="regular expression"):
        Message.matches("(")
    with pytest.raises(TypeError):
        Message.matches(cast("str", b"x"))


@pytest.mark.parametrize("pattern", ["(" * 1000, "a{4294967296}"])
def test_message_matches_turns_every_compile_failure_into_value_error(
    pattern: str,
) -> None:
    with pytest.raises(ValueError, match="regular expression"):
        Message.matches(pattern)
    with pytest.raises(ValueError, match=r"^\$\.message_matches: "):
        Condition.from_json({"message_matches": pattern})


# -- operators --------------------------------------------------------------------


def test_operators_build_and_or_not() -> None:
    a, b = Tag("a"), Tag("b")
    assert isinstance(a & b, And)
    assert isinstance(a | b, Or)
    assert isinstance(~a, Not)
    assert (a & b).conditions == (a, b)
    assert (~a).condition == a


def test_operator_truth_tables() -> None:
    a, b = Level >= "W", Tag("t")
    for level in LEVELS:
        for tag in ("t", "u"):
            e = entry(level=level, tag=tag)
            x, y = a(e), b(e)
            assert (a & b)(e) is (x and y)
            assert (a | b)(e) is (x or y)
            assert (~a)(e) is (not x)
            assert (~(a & b))(e) is (not (x and y))
            assert ((a | ~b) & ~(~a | b))(e) is ((x or not y) and not (not x or y))


def test_and_or_flatten_their_operands() -> None:
    a, b, c, d = (Tag(name) for name in "abcd")
    assert And(And(a, b), c).conditions == (a, b, c)
    assert (a & b & c).conditions == (a, b, c)
    assert (a & (b & c)).conditions == (a, b, c)
    assert Or(Or(a, b), Or(c, d)).conditions == (a, b, c, d)
    assert And(a, Or(b, c)).conditions == (a, Or(b, c))
    assert And(Or(a, b), c).conditions == (Or(a, b), c)
    assert And(a).conditions == (a,)


def test_and_or_need_conditions() -> None:
    with pytest.raises(ValueError, match="at least one"):
        And()
    with pytest.raises(ValueError, match="at least one"):
        Or()
    with pytest.raises(TypeError, match="callables are not conditions"):
        And(Tag("a"), cast("Condition", lambda _: True))
    with pytest.raises(TypeError):
        Not(cast("Condition", lambda _: True))
    with pytest.raises(TypeError):
        Tag("a") & (lambda _: True)
    with pytest.raises(TypeError):
        Tag("a") | "x"


def test_a_condition_has_no_truth_value() -> None:
    with pytest.raises(TypeError, match="no truth value"):
        bool(Tag("a"))
    with pytest.raises(TypeError):
        Tag("a") and Tag("b")
    with pytest.raises(TypeError):
        _ = Level >= "I" <= "".join("E")


class _Recording:
    """Stands in for an entry and records which fields were read, in order."""

    def __init__(self) -> None:
        self.reads: list[str] = []

    @property
    def tag(self) -> str:
        self.reads.append("tag")
        return "t"

    @property
    def pid(self) -> int:
        self.reads.append("pid")
        return 1

    @property
    def tid(self) -> int:
        self.reads.append("tid")
        return 2


def test_terms_short_circuit_in_written_order() -> None:
    cases = [
        (Tag("x") & Pid(1) & Tid(2), ["tag"], False),
        (Tag("t") & Pid(2) & Tid(2), ["tag", "pid"], False),
        (Tag("t") & Pid(1) & Tid(2), ["tag", "pid", "tid"], True),
        (Tag("t") | Pid(1) | Tid(2), ["tag"], True),
        (Tag("x") | Pid(1) | Tid(2), ["tag", "pid"], True),
        (Tag("x") | Pid(9) | Tid(9), ["tag", "pid", "tid"], False),
        (Tid(2) & ~Tag("t") & Pid(1), ["tid", "tag"], False),
    ]
    for condition, order, result in cases:
        probe = _Recording()
        assert condition(cast("LogEntry", probe)) is result, condition
        assert probe.reads == order, condition


# -- immutability, equality, hash, repr ---------------------------------------------


def test_conditions_are_immutable() -> None:
    for condition in (Tag("a"), Tag("a") & Tag("b"), ~Tag("a"), Level >= "W"):
        with pytest.raises(AttributeError, match="immutable"):
            setattr(condition, "x", 1)  # noqa: B010
        with pytest.raises(AttributeError, match="immutable"):
            delattr(condition, "_hash")


def test_equality_and_hash_are_by_value() -> None:
    assert Tag("a") == Tag("a")
    assert Tag("a") != Tag("b")
    assert Tag("a") != Pid(1)
    assert Pid(1) != Tid(1)
    assert Tag("a") != "a"
    assert (Level >= "W") == (Level >= "W")
    assert (Level >= "W") != (Level > "W")
    assert Message.contains("a") != Message.matches("a")
    assert Crash() == Crash()
    assert Crash(package="a.b") != Crash()
    assert Crash() != Anr()
    assert (Tag("a") & Tag("b")) == (Tag("a") & Tag("b"))
    assert (Tag("a") & Tag("b")) != (Tag("b") & Tag("a"))
    assert (Tag("a") & Tag("b")) != (Tag("a") | Tag("b"))
    assert ~Tag("a") == ~Tag("a")
    assert {Tag("a"), Tag("a"), Pid(1)} == {Tag("a"), Pid(1)}
    assert hash(Tag("a") & Pid(1)) == hash(Tag("a") & Pid(1))


def test_repr_is_readable_and_evaluates_to_an_equal_condition() -> None:
    cases = {
        Level >= "W": "Level >= 'W'",
        Tag("A", "B"): "Tag('A', 'B')",
        Message.contains("x"): "Message.contains('x')",
        Message.matches("a+"): "Message.matches('a+')",
        Pid(1, 2): "Pid(1, 2)",
        Crash(): "Crash()",
        Anr(package="com.x"): "Anr(package='com.x')",
        (Level >= "W") & Tag("A"): "((Level >= 'W') & Tag('A'))",
        ~(Level >= "W"): "~(Level >= 'W')",
        ~(Tag("a") | Tag("b")): "~(Tag('a') | Tag('b'))",
        And(Tag("a")): "And(Tag('a'))",
    }
    for condition, text in cases.items():
        assert repr(condition) == text
        assert eval(text) == condition  # noqa: S307


# -- long chains and depth -----------------------------------------------------------


def test_long_and_chain_builds_evaluates_compares_and_prints() -> None:
    terms = [Tag(f"t{i}") for i in range(CHAIN)]
    chain = reduce(and_, terms)
    assert isinstance(chain, And)
    assert chain.conditions == tuple(terms)
    assert chain(entry(tag="t0")) is False

    every_tag = reduce(or_, terms)
    assert every_tag(entry(tag=f"t{CHAIN - 1}")) is True
    assert every_tag(entry(tag="other")) is False
    assert every_tag(entry(tag="t0")) is True

    again = reduce(or_, [Tag(f"t{i}") for i in range(CHAIN)])
    assert again == every_tag
    assert hash(again) == hash(every_tag)
    assert again != reduce(or_, terms[:-1])
    text = repr(every_tag)
    assert text.startswith("(Tag('t0') | Tag('t1')")
    assert text.endswith(f"Tag('t{CHAIN - 1}'))")
    assert len(text.split(" | ")) == CHAIN


def test_long_chain_of_mixed_terms() -> None:
    terms = [
        (Level >= "W") if i % 2 else Message.contains(str(i)) for i in range(CHAIN)
    ]
    chain = reduce(or_, terms)
    assert chain(entry(level="V", message="x2x")) is True
    assert chain(entry(level="V", message="abc")) is False
    assert chain(entry(level="E", message="abc")) is True
    assert chain.fields() == {"level", "message"}


def test_long_chain_json_round_trip() -> None:
    chain = reduce(and_, [Pid(i) for i in range(CHAIN)])
    data = chain.to_json()
    assert len(data["all"]) == CHAIN
    assert Condition.from_json(json.loads(json.dumps(data))) == chain
    wide = Or(*[Tag(f"t{i}") for i in range(CHAIN)])
    assert Condition.from_json(wide.to_json()) == wide


def test_long_chain_of_negations_compiles_and_runs() -> None:
    chain = reduce(and_, [~Tag(f"t{i}") for i in range(CHAIN)])
    assert chain(entry(tag="x")) is True
    assert chain(entry(tag="t5000")) is False
    assert len(chain.packages()) == 0


def _alternate(depth: int) -> Condition:
    condition: Condition = Tag("a")
    for i in range(depth):
        if i % 3 == 0:
            condition = And(condition, Tag("b"))
        elif i % 3 == 1:
            condition = Or(condition, Tag("c"))
        else:
            condition = Not(condition)
    return condition


def test_nesting_up_to_the_limit_works() -> None:
    condition = _alternate(MAX_NESTING)
    assert MAX_NESTING == 32
    assert [condition(entry(tag=tag)) for tag in "abc"] == [False, False, True]
    assert Condition.from_json(condition.to_json()) == condition
    assert eval(repr(condition)) == condition  # noqa: S307


def test_nesting_beyond_the_limit_raises_when_built() -> None:
    condition = _alternate(MAX_NESTING)
    with pytest.raises(ValueError, match="32"):
        Not(Not(condition))
    with pytest.raises(ValueError, match="32"):
        _alternate(MAX_NESTING + 1)
    deep_not = Tag("a")
    for _ in range(MAX_NESTING):
        deep_not = ~deep_not
    with pytest.raises(ValueError, match="32"):
        _ = ~deep_not
    with pytest.raises(ValueError, match="32"):
        Or(deep_not, Tag("a"))


def test_flattening_does_not_count_as_nesting() -> None:
    chain = reduce(and_, [Tag(str(i)) for i in range(100)])
    assert Or(chain, Tag("x"))(entry(tag="x"))
    wrapped = chain
    for _ in range(15):
        wrapped = Not(Or(wrapped, Tag("y")))
    assert wrapped(entry(tag="q")) is True
    assert wrapped(entry(tag="y")) is False


# -- introspection -------------------------------------------------------------------


def test_packages_collects_package_names() -> None:
    assert Tag("a").packages() == frozenset()
    assert Package("com.x", "com.y").packages() == {"com.x", "com.y"}
    assert Crash(package="com.z").packages() == {"com.z"}
    assert Anr(package="com.a").packages() == {"com.a"}
    assert Crash().packages() == frozenset()
    assert Crash(package="com.z:remote").packages() == {"com.z"}
    condition = (Package("com.x") | Crash(package="com.y")) & ~Anr(package="com.w")
    assert condition.packages() == {"com.x", "com.y", "com.w"}


def test_fields_lists_the_entry_fields_read() -> None:
    assert (Level >= "W").fields() == {"level"}
    assert Tag("a").fields() == {"tag"}
    assert Message.contains("a").fields() == {"message"}
    assert Message.matches("a").fields() == {"message"}
    assert Pid(1).fields() == {"pid"}
    assert Tid(1).fields() == {"tid"}
    assert Uid(1).fields() == {"uid"}
    assert Package("a").fields() == {"package"}
    assert Crash().fields() == {"tag", "level", "message"}
    assert Anr(package="a.b").fields() == {"tag", "level", "message"}
    only_level_and_tag = ((Level >= "W") & Tag("a")) | ~Tag("b")
    assert only_level_and_tag.fields() == {"level", "tag"}
    all_names = {f.name for f in dataclasses.fields(LogEntry)}
    assert only_level_and_tag.fields() <= all_names
    assert Crash().fields() <= all_names


# -- compile -------------------------------------------------------------------------


def test_compile_returns_a_cached_plain_function() -> None:
    condition = (Level >= "W") & Tag("a")
    predicate = condition.compile()
    assert callable(predicate)
    assert condition.compile() is predicate
    assert condition(entry(level="E", tag="a")) is True
    assert predicate(entry(level="E", tag="b")) is False
    assert type(predicate).__name__ == "function"


def test_compiled_results_are_real_booleans() -> None:
    conditions = [
        Level >= "W",
        Tag("a"),
        Uid(1),
        Package("a"),
        Message.contains("x"),
        Message.matches("x"),
        Crash(),
        Crash(package="a.b"),
        Anr(),
        Anr(package="a.b"),
        ~Tag("a"),
        Tag("a") & Pid(1),
        Tag("a") | Pid(1),
    ]
    for condition in conditions:
        for e in (entry(), entry(tag="a", pid=1, uid=1, package="a")):
            assert condition(e) in (True, False)
            assert type(condition(e)) is bool, condition


def test_message_text_with_quotes_and_odd_characters_is_safe() -> None:
    text = "'\"\\\n\x00 あ {x} \ud800"
    assert Message.contains(text)(entry(message=f"a{text}b"))
    assert Tag(text)(entry(tag=text))
    assert not Tag(text)(entry(tag="x"))


# -- build_condition -----------------------------------------------------------------


def test_build_condition_without_arguments_is_none() -> None:
    assert build_condition() is None
    assert build_condition(None, level=None, tag=None) is None


def test_build_condition_single_keywords() -> None:
    assert build_condition(level="W") == (Level >= "W")
    assert build_condition(tag="A") == Tag("A")
    assert build_condition(tag=["A", "B"]) == Tag("A", "B")
    assert build_condition(tag=("A", "B")) == Tag("A", "B")
    assert build_condition(message="x") == Message.contains("x")
    assert build_condition(package="com.x") == Package("com.x")
    assert build_condition(package=["com.x", "com.y"]) == Package("com.x", "com.y")
    assert build_condition(pid=5) == Pid(5)
    assert build_condition(pid=[5, 6]) == Pid(5, 6)


def test_build_condition_combines_with_and() -> None:
    where = Tag("w") | Tag("v")
    combined = build_condition(
        where, level="E", tag="t", message="m", package="p", pid=[1, 2]
    )
    assert isinstance(combined, And)
    assert set(combined.conditions) == {
        Level >= "E",
        Tag("t"),
        Message.contains("m"),
        Package("p"),
        Pid(1, 2),
        where,
    }
    assert build_condition(where) is where
    both = build_condition(Tag("a") & Pid(1), level="W")
    assert both is not None
    assert isinstance(both, And)
    assert set(both.conditions) == {Tag("a"), Pid(1), Level >= "W"}
    assert both(entry(tag="a", pid=1, level="E"))
    assert not both(entry(tag="a", pid=1, level="I"))
    assert not both(entry(tag="a", pid=2, level="E"))


def test_build_condition_validates() -> None:
    with pytest.raises(TypeError, match="Condition"):
        build_condition(lambda _: True)  # ty: ignore[invalid-argument-type]
    with pytest.raises(ValueError, match="not a log level"):
        build_condition(level=cast("LogLevel", "X"))
    with pytest.raises(ValueError, match="at least one"):
        build_condition(tag=[])
    with pytest.raises(TypeError):
        build_condition(pid="1")  # ty: ignore[invalid-argument-type]
    with pytest.raises(TypeError):
        build_condition(message=3)  # ty: ignore[invalid-argument-type]


# -- JSON ----------------------------------------------------------------------------

JSON_CASES: list[tuple[Condition, dict[str, Any]]] = [
    (Level >= "W", {"level": "W"}),
    (Level == "E", {"level_eq": "E"}),
    (Level > "I", {"level_gt": "I"}),
    (Level < "E", {"level_lt": "E"}),
    (Level <= "D", {"level_le": "D"}),
    (Level != "V", {"level_ne": "V"}),
    (Tag("A", "B"), {"tag": ["A", "B"]}),
    (Message.contains("text"), {"message": "text"}),
    (Message.matches("a+b"), {"message_matches": "a+b"}),
    (Pid(1, 2), {"pid": [1, 2]}),
    (Tid(3), {"tid": [3]}),
    (Uid(1000), {"uid": [1000]}),
    (Package("com.x"), {"package": ["com.x"]}),
    (Crash(package="com.x"), {"crash": {"package": "com.x"}}),
    (Crash(), {"crash": {}}),
    (Anr(package="com.x:remote"), {"anr": {"package": "com.x:remote"}}),
    (Crash(package="com.x:ishared:w"), {"crash": {"package": "com.x:ishared:w"}}),
    (Anr(), {"anr": {}}),
    (~Tag("a"), {"not": {"tag": ["a"]}}),
    (
        Tag("a") & Tag("b"),
        {"all": [{"tag": ["a"]}, {"tag": ["b"]}]},
    ),
    (
        (Level >= "W") & (Tag("a") | ~Pid(1)),
        {
            "all": [
                {"level": "W"},
                {"any": [{"tag": ["a"]}, {"not": {"pid": [1]}}]},
            ]
        },
    ),
]


@pytest.mark.parametrize(("condition", "expected"), JSON_CASES, ids=repr)
def test_to_json_and_back(condition: Condition, expected: dict[str, Any]) -> None:
    assert condition.to_json() == expected
    restored = Condition.from_json(expected)
    assert restored == condition
    assert restored.to_json() == expected
    assert json.loads(json.dumps(condition.to_json())) == expected


def test_round_trip_preserves_tag_order_and_behaviour() -> None:
    condition = Tag("z", "a", "m")
    assert Condition.from_json(condition.to_json()).to_json() == {
        "tag": ["z", "a", "m"]
    }
    hello = Message.matches(r"he\w+o")
    assert Condition.from_json(hello.to_json())(entry())


def test_from_json_rejects_bad_input_and_names_the_path() -> None:
    cases: list[tuple[Any, str]] = [
        ([], r"^\$: expected an object"),
        ("tag", r"^\$: expected an object"),
        (None, r"^\$: expected an object"),
        ({}, r"^\$: expected exactly one key"),
        ({"tag": ["a"], "pid": [1]}, r"^\$: expected exactly one key"),
        ({"bogus": 1}, r"^\$\.bogus: unknown key"),
        ({"all": []}, r"^\$\.all: expected a non-empty list"),
        ({"any": []}, r"^\$\.any: expected a non-empty list"),
        ({"all": {}}, r"^\$\.all: expected a non-empty list"),
        ({"all": [{"tag": ["a"]}, 5]}, r"^\$\.all\[1\]: expected an object"),
        ({"all": [{"tag": ["a"]}, {"x": 1}]}, r"^\$\.all\[1\]\.x: unknown key"),
        (
            {"any": [{"all": [{"tag": []}]}]},
            r"^\$\.any\[0\]\.all\[0\]\.tag: expected a non-empty list",
        ),
        ({"not": {"tag": "a"}}, r"^\$\.not\.tag: expected a non-empty list of strings"),
        ({"not": []}, r"^\$\.not: expected an object"),
        ({"tag": ["a", 1]}, r"^\$\.tag\[1\]: expected string, got int"),
        ({"pid": [1, "2"]}, r"^\$\.pid\[1\]: expected integer, got str"),
        ({"pid": [True]}, r"^\$\.pid\[0\]: expected integer, got bool"),
        ({"uid": [1.5]}, r"^\$\.uid\[0\]: expected integer, got float"),
        ({"tid": 3}, r"^\$\.tid: expected a non-empty list"),
        ({"package": [None]}, r"^\$\.package\[0\]: expected string"),
        ({"level": "X"}, r"^\$\.level: .*not a log level"),
        ({"level": 3}, r"^\$\.level: expected a string, got int"),
        ({"level_eq": ["E"]}, r"^\$\.level_eq: expected a string"),
        ({"message": 1}, r"^\$\.message: expected a string, got int"),
        ({"message_matches": "("}, r"^\$\.message_matches: .*regular expression"),
        ({"message_matches": None}, r"^\$\.message_matches: expected a string"),
        ({"crash": []}, r"^\$\.crash: expected an object"),
        ({"crash": {"pkg": "a"}}, r"^\$\.crash\.pkg: unknown key"),
        ({"crash": {"package": 1}}, r"^\$\.crash\.package: expected a string"),
        ({"anr": {"package": "not a package"}}, r"^\$\.anr\.package: .*process name"),
        ({1: 2}, r"^\$\.1: unknown key"),
    ]
    for data, pattern in cases:
        with pytest.raises(ValueError, match=pattern):
            Condition.from_json(data)


def test_from_json_limits_hostile_nesting() -> None:
    data: dict[str, Any] = {"tag": ["a"]}
    for i in range(100_000):
        data = {"all": [data]} if i % 2 else {"not": data}
    with pytest.raises(ValueError, match="nested more than 32 levels"):
        Condition.from_json(data)
    ok: dict[str, Any] = {"tag": ["a"]}
    for _ in range(MAX_NESTING):
        ok = {"not": ok}
    assert Condition.from_json(ok).to_json() == ok
    ok = {"not": ok}
    with pytest.raises(ValueError, match="nested more than 32 levels"):
        Condition.from_json(ok)


def test_from_json_nesting_counts_flattened_levels_too() -> None:
    data: dict[str, Any] = {"tag": ["a"]}
    for _ in range(MAX_NESTING + 1):
        data = {"all": [data]}
    with pytest.raises(ValueError, match="nested more than 32 levels"):
        Condition.from_json(data)


# -- Crash and Anr -------------------------------------------------------------------


def java(message: str, *, tag: str = "AndroidRuntime", level: str = "E") -> LogEntry:
    return entry(tag=tag, level=level, message=message)


def native(name: str, *, tag: str = "DEBUG", level: str = "F") -> LogEntry:
    message = f"pid: 5042, tid: 5042, name: ndroid.settings  >>> {name} <<<"
    return entry(tag=tag, level=level, message=message)


def test_crash_without_package_matches_fatal_exception() -> None:
    crash = Crash()
    assert crash(java("FATAL EXCEPTION: main")) is True
    assert crash(java("Process: com.example.app, PID: 1")) is False
    assert crash(java("FATAL EXCEPTION: main", tag="MyApp")) is False
    assert crash(java("FATAL EXCEPTION: main", level="D")) is False
    assert crash(java("Just an error")) is False
    assert crash(native("com.example.app")) is False


def test_anr_without_package_matches_the_prefix() -> None:
    anr = Anr()
    tag = "ActivityManager"
    assert anr(entry(tag=tag, level="E", message="ANR in com.example.app")) is True
    assert anr(entry(tag=tag, level="E", message="ANR in com.example.application"))
    assert not anr(entry(tag="MyApp", level="E", message="ANR in com.example.app"))
    assert not anr(entry(tag=tag, level="I", message="ANR in com.example.app"))
    assert not anr(entry(tag=tag, level="E", message="Something about ANR"))
    assert not anr(entry(tag=tag, level="E", message="Reason: ANR in com.example.app"))


def test_crash_with_package_matches_the_java_process_line() -> None:
    crash = Crash(package="com.example.app")
    assert crash(java("Process: com.example.app, PID: 5576")) is True
    assert crash(java("Process: com.example.app:remote, PID: 5576")) is True
    assert crash(java("Process: com.example.application, PID: 5576")) is False
    assert crash(java("Process: com.example, PID: 5576")) is False
    assert crash(java("Process: com.example.app.x, PID: 5576")) is False
    assert crash(java("FATAL EXCEPTION: main")) is False
    assert crash(java("Process: com.example.app, PID: 5576", level="W")) is False
    assert crash(java("Process: com.example.app, PID: 5576", tag="Other")) is False
    assert crash(java("Process: com.example.app")) is False
    assert crash(java("Caused by: Process: com.example.app, PID: 5576")) is False
    secondary = Crash(package="com.example.app:remote")
    assert secondary(java("Process: com.example.app:remote, PID: 1")) is True
    assert secondary(java("Process: com.example.app, PID: 1")) is False


# Process names Android builds for isolated services, with more than one ':'.
_SHARED_ISOLATED = "com.example.app:ishared:worker"
_ISOLATED_IN_REMOTE = "com.example.app:remote:com.example.app.Service"
_NESTED_ISOLATED = "com.example.app:com.example.app.Outer$Worker"
_CHROME_SANDBOX = (
    "com.android.chrome:sandboxed_process0:"
    "org.chromium.content.app.SandboxedProcessService0:0"
)


def test_crash_and_anr_select_a_process_name_with_several_colons() -> None:
    for name in (
        _SHARED_ISOLATED,
        _ISOLATED_IN_REMOTE,
        _NESTED_ISOLATED,
        _CHROME_SANDBOX,
    ):
        crash = Crash(package=name)
        assert crash(java(f"Process: {name}, PID: 7")) is True
        assert crash(native(name)) is True
        assert crash(java(f"Process: {name}:0, PID: 7")) is True
        assert crash(java(f"Process: {name}0, PID: 7")) is False
        assert crash(java("Process: com.example.app, PID: 7")) is False
        anr = Anr(package=name)
        assert anr(
            entry(tag="ActivityManager", level="E", message=f"ANR in {name} (x)")
        )
        assert not anr(
            entry(tag="ActivityManager", level="E", message="ANR in com.example.app")
        )
        assert crash.packages() == anr.packages() == {name.partition(":")[0]}
    worker = Crash(package="com.example.app:ishared:worker")
    assert worker(java("Process: com.example.app:ishared:other, PID: 7")) is False
    shared = Crash(package="com.example.app:ishared")
    assert shared(java(f"Process: {_SHARED_ISOLATED}, PID: 7")) is True


def test_crash_with_package_matches_the_native_tombstone_line() -> None:
    crash = Crash(package="com.example.app")
    assert crash(native("com.example.app")) is True
    assert crash(native("com.example.app:remote")) is True
    assert crash(native("com.example.application")) is False
    assert crash(native("com.example.app", level="E")) is False
    assert crash(native("com.example.app", tag="libc")) is False
    abort = "Abort message: pid: 1, tid: 1, name: x  >>> com.example.app <<<"
    assert crash(entry(tag="DEBUG", level="F", message=abort)) is False


def test_anr_with_package_matches_the_named_process() -> None:
    anr = Anr(package="com.example.app")

    def line(message: str, *, tag: str = "ActivityManager") -> LogEntry:
        return entry(tag=tag, level="E", message=message)

    assert anr(line("ANR in com.example.app (com.example.app/.Main)")) is True
    assert anr(line("ANR in com.example.app")) is True
    assert anr(line("ANR in com.example.app(com.example.app/.Main)")) is True
    assert anr(line("ANR in com.example.app:remote (x)")) is True
    assert anr(line("ANR in com.example.application (x)")) is False
    assert anr(line("ANR in com.example (x)")) is False
    assert anr(line("ANR in Window{1 u0 com.example.app/.Main}")) is False
    assert anr(line("ANR in com.example.app", tag="WindowManager")) is False
    assert anr(line("Reason: ANR in com.example.app")) is False
    assert anr(line("ANR incom.example.app")) is False


def test_crash_and_anr_validate_their_package() -> None:
    for cls in (Crash, Anr):
        assert cls(package="com.example")._package == "com.example"
        assert cls(package="com.example:remote")._package == "com.example:remote"
        assert cls(package=_SHARED_ISOLATED)._package == _SHARED_ISOLATED
        assert cls(None)._package is None
        bad_names = (
            "",
            "1com",
            "com..x",
            "com.x y",
            "com.x;rm",
            "com.x:",
            "com.x::y",
            "com.x:y:",
            "com.x:y z",
            "com.x:y;rm",
            "com.x:y'z",
            'com.x:y"z',
            "com.x:y\n",
            "com.x:y/z",
            ":remote",
            "-a",
        )
        for bad in bad_names:
            with pytest.raises(ValueError, match="not a package or process name"):
                cls(package=bad)
        with pytest.raises(TypeError):
            cls(package=["com.example"])
        with pytest.raises(TypeError):
            cls(tag="x")


def test_crash_and_anr_repr() -> None:
    assert repr(Crash()) == "Crash()"
    assert repr(Crash(package="com.example")) == "Crash(package='com.example')"
    assert repr(Anr(package="a.b")) == "Anr(package='a.b')"


# -- values are plain str and int -----------------------------------------------------


class _Name(enum.StrEnum):
    A = "A"
    W = "W"


class _Number(enum.IntEnum):
    X = 7


class _Evil(str):
    __slots__ = ()

    def __repr__(self) -> str:
        return "__import__('os').getcwd() and True"


_LEVEL_W = cast("LogLevel", _Name.W)
_LEVEL_EVIL = cast("LogLevel", _Evil("W"))


def test_str_and_int_subclasses_become_plain_values() -> None:
    tag = Tag(_Name.A)
    assert repr(tag) == "Tag('A')"
    assert type(tag._values[0]) is str
    assert tag(entry(tag="A"))
    assert tag == Tag("A")
    assert Pid(_Number.X)(entry(pid=7))
    assert repr(Pid(_Number.X)) == "Pid(7)"
    assert type(Tid(_Number.X)._values[0]) is int
    assert Uid(_Number.X)(entry(uid=7))
    assert Package(_Name.A)(entry(package="A"))
    assert Message.contains(_Name.A)(entry(message="xAx"))
    assert Message.matches(_Name.A)(entry(message="xAx"))
    assert (Level == _LEVEL_W)(entry(level="W"))
    assert (Level != _LEVEL_W)(entry(level="E"))
    assert (Level >= _LEVEL_W)(entry(level="F"))
    assert repr(Level >= _LEVEL_W) == "Level >= 'W'"
    assert Crash(package=_Name.A).to_json() == {"crash": {"package": "A"}}


def test_a_str_subclass_cannot_inject_code_through_its_repr() -> None:
    evil = _Evil("A")
    assert Tag(evil)(entry(tag="A"))
    assert not Tag(evil)(entry(tag="B"))
    assert Message.contains(evil)(entry(message="A"))
    assert (Level >= _LEVEL_EVIL)(entry(level="W"))


def test_huge_integers_are_rejected_when_built() -> None:
    for cls in (Pid, Tid, Uid):
        with pytest.raises(ValueError, match="integers"):
            cls(10**5000)
        with pytest.raises(ValueError, match="integers"):
            cls(-(2**63))
        assert cls(2**63 - 1)(entry(pid=2**63 - 1, tid=2**63 - 1, uid=2**63 - 1))


# -- Package names ------------------------------------------------------------------


def test_package_validates_its_names() -> None:
    assert Package("com.x", "a_b.c1").packages() == {"com.x", "a_b.c1"}
    for bad in ("", "a b; rm", "1com", "com..x", "com.x;ls", "-a"):
        with pytest.raises(ValueError, match="not a package name"):
            Package(bad)
    with pytest.raises(ValueError, match=r"Crash\(package"):
        Package("com.x:remote")
    with pytest.raises(ValueError, match=r"Crash\(package"):
        Package(_SHARED_ISOLATED)


def test_from_json_package_errors_name_the_path() -> None:
    with pytest.raises(ValueError, match=r"^\$\.package: .*not a package name"):
        Condition.from_json({"package": ["com.x", "a b; rm"]})
    with pytest.raises(ValueError, match=r"^\$\.all\[1\]\.package: .*process name"):
        Condition.from_json({"all": [{"tag": ["a"]}, {"package": ["com.x:remote"]}]})


# -- copy and pickle ----------------------------------------------------------------


def _samples() -> list[Condition]:
    return [
        Tag("a"),
        Level >= "W",
        Message.matches("a+"),
        Crash(package="com.x"),
        (Tag("a") & Pid(1)) | ~Anr(),
    ]


def test_conditions_can_be_copied() -> None:
    for condition in _samples():
        assert copy.copy(condition) == condition
        assert copy.deepcopy(condition) == condition
        assert copy.deepcopy({"k": [condition]})["k"][0] == condition


@pytest.mark.parametrize("protocol", range(pickle.HIGHEST_PROTOCOL + 1))
def test_conditions_can_be_pickled(protocol: int) -> None:
    for condition in _samples():
        clone = pickle.loads(pickle.dumps(condition, protocol))  # noqa: S301
        assert clone == condition
        assert hash(clone) == hash(condition)
        assert clone(entry(tag="a", pid=1)) == condition(entry(tag="a", pid=1))
