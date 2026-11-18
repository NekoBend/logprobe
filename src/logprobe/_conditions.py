# ruff: noqa: SLF001, ARG002
# Conditions read each other's private state (operands, nesting) and every
# component implements the same private hooks, some without using the argument.
"""Filter conditions: small immutable predicates over log entries.

Conditions are built from components (:data:`Level`, :class:`Tag`,
:data:`Message`, :class:`Pid`, :class:`Tid`, :class:`Uid`, :class:`Package`,
:class:`Crash`, :class:`Anr`) and combined with ``&``, ``|`` and ``~``::

    (Level >= "W") & Tag("ActivityManager", "WindowManager")

Arbitrary callables are not conditions. A condition is compiled once into a
plain function (:meth:`Condition.compile`); ``And`` and ``Or`` chains become a
single Python expression, so evaluating an entry does not walk a tree.

Chains of any length are safe: ``And`` and ``Or`` flatten their operands, and
the nesting of different operators (``And`` in ``Or`` in ``Not`` ...) is
limited to :data:`MAX_NESTING` levels, so no operation recurses deeply.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from itertools import chain
from typing import TYPE_CHECKING, Any, ClassVar, Final, NoReturn

if TYPE_CHECKING:
    from collections.abc import Callable

    from ._entry import LogEntry, LogLevel

__all__ = [
    "MAX_NESTING",
    "And",
    "Anr",
    "Condition",
    "Crash",
    "Level",
    "Message",
    "Not",
    "Or",
    "Package",
    "Pid",
    "Tag",
    "Tid",
    "Uid",
    "build_condition",
]

#: The deepest nesting of ``And``, ``Or`` and ``Not`` a condition may have.
MAX_NESTING: Final = 32

_LEVELS: Final = "VDIWEF"
# The terms of one generated function: longer operand lists are split into
# several functions so that no source expression grows without bound.
_CHUNK: Final = 128

_PLAIN_NAME: Final = r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*"
_PLAIN_NAME_RE: Final = re.compile(_PLAIN_NAME)
# A package name, or a process name: the package followed by ":"-separated
# parts, as Android names secondary and isolated processes (for example
# "com.example.app:remote", "com.example.app:ishared:worker", or
# "com.example.app:com.example.app.Outer$Worker" for an isolated service that
# is a nested class).
_PACKAGE_NAME: Final = re.compile(_PLAIN_NAME + r"(?::[A-Za-z0-9_.$]+)*")

# The Java crash block's process line, e.g. "Process: com.android.settings,
# PID: 5576".
_JAVA_CRASH_PROCESS: Final = re.compile(r"Process: (?P<name>[^\s,]+), PID: [0-9]+")
# The tombstone line of a native crash, logged as DEBUG at level F, e.g.
# "pid: 5042, tid: 5042, name: ndroid.settings  >>> com.android.settings <<<".
_NATIVE_CRASH_TAG: Final = "DEBUG"
_NATIVE_CRASH_LEVEL: Final = "F"
_NATIVE_CRASH_PROCESS: Final = re.compile(
    r"pid: [0-9]+, tid: [0-9]+, name: .*  >>> (?P<name>\S+) <<<"
)
_CRASH_TAG: Final = "AndroidRuntime"
_CRASH_LEVEL: Final = "E"
_CRASH_MESSAGE: Final = "FATAL EXCEPTION"
_ANR_TAG: Final = "ActivityManager"
_ANR_LEVEL: Final = "E"
_ANR_PREFIX: Final = "ANR in"
# The process name follows the prefix after at least one space.
_ANR_NAMED: Final = re.compile(re.escape(_ANR_PREFIX) + r"\s+(?P<name>[^\s(]+)")

_NO_FIELDS: Final[frozenset[str]] = frozenset()
# Ids are well below this; it keeps the source of a predicate small.
_INT_LIMIT: Final = 2**63


def _names_package(name: str, package: str) -> bool:
    """Whether the process ``name`` is ``package`` or one of its ``:`` processes."""
    return name == package or name.startswith(package + ":")


def _check_process_package(package: str | None) -> str | None:
    if package is None:
        return None
    if not isinstance(package, str):
        msg = f"package must be a str or None, not {type(package).__name__}"
        raise TypeError(msg)
    if not _PACKAGE_NAME.fullmatch(package):
        msg = (
            f"{package!r} is not a package or process name: dot-separated "
            "segments of ASCII letters, digits and '_', each starting with a "
            "letter, optionally followed by ':'-separated process parts of "
            "ASCII letters, digits, '_', '.' and '$'"
        )
        raise ValueError(msg)
    return str.__str__(package)


def _crash_with_package(package: str) -> Callable[[LogEntry], bool]:
    def crash(entry: LogEntry) -> bool:
        if entry.tag == _CRASH_TAG and entry.level == _CRASH_LEVEL:
            found = _JAVA_CRASH_PROCESS.match(entry.message)
            if found is not None and _names_package(found["name"], package):
                return True
        if entry.tag == _NATIVE_CRASH_TAG and entry.level == _NATIVE_CRASH_LEVEL:
            found = _NATIVE_CRASH_PROCESS.match(entry.message)
            return found is not None and _names_package(found["name"], package)
        return False

    return crash


def _anr_with_package(package: str) -> Callable[[LogEntry], bool]:
    def anr(entry: LogEntry) -> bool:
        if entry.tag != _ANR_TAG or entry.level != _ANR_LEVEL:
            return False
        found = _ANR_NAMED.match(entry.message)
        return found is not None and _names_package(found["name"], package)

    return anr


class _Emitter:
    """Collects the objects and helper functions a generated predicate uses."""

    __slots__ = ("count", "namespace")

    def __init__(self) -> None:
        self.namespace: dict[str, object] = {}
        self.count = 0

    def bind(self, value: object) -> str:
        """Make ``value`` available to the generated code; return its name."""
        name = f"_k{self.count}"
        self.count += 1
        self.namespace[name] = value
        return name

    def build(self, expression: str) -> Callable[[LogEntry], bool]:
        """Compile ``lambda e: <expression>``.

        ``expression`` is assembled only from ``repr`` of exact ``str`` and
        ``int`` values (conditions convert what they are given to those types
        when they are made) and the names of bound objects.
        """
        return eval("lambda e: " + expression, self.namespace)  # noqa: S307

    def join(self, keyword: str, parts: list[str]) -> str:
        """Join boolean expressions with ``and`` or ``or``, splitting long lists."""
        while len(parts) > _CHUNK:
            parts = [
                self.bind(
                    self.build("(" + f" {keyword} ".join(parts[i : i + _CHUNK]) + ")")
                )
                + "(e)"
                for i in range(0, len(parts), _CHUNK)
            ]
        return "(" + f" {keyword} ".join(parts) + ")"


class Condition(ABC):
    """A predicate over log entries, built from components and ``& | ~``.

    ``condition(entry)`` is True when the entry matches. Conditions are
    immutable, hashable, compare by value and have a readable ``repr``.
    ``a & b`` is :class:`And`, ``a | b`` is :class:`Or` and ``~a`` is
    :class:`Not`. A condition has no truth value (``a and b`` raises
    ``TypeError``): use the operators.

    Conditions are not meant to be subclassed outside this package.
    """

    __slots__ = ("_compiled", "_hash", "_nesting")

    # How deep And, Or and Not nest in this condition; 0 for components.
    _nesting: int
    _compiled: Callable[[LogEntry], bool] | None
    _hash: int | None

    def __new__(cls, *_args: object, **_kwargs: object) -> Any:  # noqa: ANN401
        self = object.__new__(cls)
        object.__setattr__(self, "_compiled", None)
        object.__setattr__(self, "_hash", None)
        object.__setattr__(self, "_nesting", 0)
        return self

    def __setattr__(self, name: str, value: object) -> NoReturn:
        msg = f"{type(self).__name__} is immutable"
        raise AttributeError(msg)

    def __delattr__(self, name: str) -> NoReturn:
        msg = f"{type(self).__name__} is immutable"
        raise AttributeError(msg)

    def __copy__(self) -> Condition:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> Condition:
        return self

    def __reduce__(self) -> tuple[Callable[[object], Condition], tuple[object]]:
        return (Condition.from_json, (self.to_json(),))

    def __and__(self, other: Condition) -> And:
        if not isinstance(other, Condition):
            return NotImplemented
        return And(self, other)

    def __or__(self, other: Condition) -> Or:
        if not isinstance(other, Condition):
            return NotImplemented
        return Or(self, other)

    def __invert__(self) -> Not:
        return Not(self)

    def __bool__(self) -> NoReturn:
        msg = "a Condition has no truth value: combine conditions with &, | and ~"
        raise TypeError(msg)

    def __call__(self, entry: LogEntry, /) -> bool:
        """Return whether ``entry`` matches (calls the compiled predicate)."""
        predicate = self._compiled
        if predicate is None:
            predicate = self.compile()
        return predicate(entry)

    def compile(self) -> Callable[[LogEntry], bool]:
        """Return a plain function ``entry -> bool``, built once.

        ``And`` and ``Or`` terms are evaluated in written order and stop at
        the first decisive one.
        """
        predicate = self._compiled
        if predicate is None:
            emitter = _Emitter()
            predicate = emitter.build(self._emit(emitter))
            object.__setattr__(self, "_compiled", predicate)
        return predicate

    def packages(self) -> frozenset[str]:
        """The package names the condition depends on.

        Those of :class:`Package`, and of :class:`Crash` and :class:`Anr` with
        a ``package`` (for those two, the part before the first ``:``).
        """
        return _NO_FIELDS

    def fields(self) -> frozenset[str]:
        """The names of the :class:`~logprobe.LogEntry` fields it reads."""
        return _NO_FIELDS

    def to_json(self) -> dict[str, Any]:
        """The condition as a JSON-compatible dict; see :meth:`from_json`."""
        return self._json()

    @staticmethod
    def from_json(obj: object) -> Condition:
        """Build a condition from the dict form of :meth:`to_json`.

        The keys mirror the keyword shortcuts. Every object has exactly one
        key: ``all`` and ``any`` (non-empty lists of objects), ``not``,
        ``level`` (the minimum), ``level_eq``, ``level_gt``, ``level_lt``,
        ``level_le``, ``level_ne``, ``tag``, ``pid``, ``tid``, ``uid`` and
        ``package`` (non-empty lists), ``message``, ``message_matches``,
        ``crash`` and ``anr`` (an object with an optional ``package``).

        Raises:
            ValueError: ``obj`` is malformed; the message names the path of
                the bad element, such as ``$.all[1].tag``.
        """
        return _from_json(obj, "$", 0)

    def _compile_membership(
        self, member: Callable[[LogEntry, frozenset[str]], bool | None]
    ) -> Callable[[LogEntry], bool | None]:
        """Return a function ``entry -> True | False | None`` (three-valued).

        Like :meth:`compile`, but :class:`Package` is decided by ``member``
        instead of by ``entry.package``. ``member(entry, names)`` answers
        whether the watched packages that own the entry's uid include one of
        ``names``: ``True`` if so, ``False`` if the owners are known and none
        of ``names`` is among them, ``None`` while the owners are not known
        yet. A uid may be owned by several packages, so ``Package(a)`` and
        ``Package(b)`` can both match the same entry.

        The result is ``None`` when an undecided :class:`Package` term is not
        outweighed by a decisive term under three-valued (Kleene) logic:
        ``Package(a) | Tag("x")`` is ``True`` for an entry tagged ``x`` however
        ``member`` answers. The logic is purely structural, so a condition that
        only looks owner-dependent, such as ``Package(a) | ~Package(a)``, is
        still ``None`` while the owners are unknown. ``And``, ``Or`` and
        ``Not`` keep the written order and early exit of :meth:`compile`.
        :class:`Crash` and :class:`Anr` read the message text and never call
        ``member``.

        The combining function is built on each call and not cached itself, but
        the owner-free parts are compiled once: a single child through its own
        :meth:`compile` cache, a run of adjacent children through a cache on
        the enclosing :class:`And` or :class:`Or`. A condition without a
        :class:`Package` term yields the cached :meth:`compile` function unchanged.
        """
        return self._membership(member)

    def _has_package(self) -> bool:
        """Whether a :class:`Package` term is somewhere below this node.

        Unlike :meth:`packages`, ``Crash`` and ``Anr`` with a package do not
        count: they read the message text and never ask for the owners.
        """
        return False

    def _package_names(self) -> frozenset[str]:
        """The names of the :class:`Package` terms below this node.

        Unlike :meth:`packages`, the packages of ``Crash`` and ``Anr`` are not
        included: those terms read the message text.
        """
        return _NO_FIELDS

    def _membership(
        self, member: Callable[[LogEntry, frozenset[str]], bool | None]
    ) -> Callable[[LogEntry], bool | None]:
        """The three-valued function; conditions that ignore owners use ``compile``."""
        return self.compile()

    @abstractmethod
    def _emit(self, emitter: _Emitter) -> str:
        """A Python boolean expression over ``e``, the entry."""

    @abstractmethod
    def _json(self) -> dict[str, Any]: ...

    @abstractmethod
    def _key(self) -> tuple[object, ...]:
        """What equality and hashing compare."""

    @abstractmethod
    def _text(self) -> str: ...

    def _operand_text(self) -> str:
        """``_text`` as an operand of ``&``, ``|`` or ``~``."""
        return self._text()

    def __eq__(self, other: object) -> bool:
        if self is other:
            return True
        if type(other) is not type(self):
            return NotImplemented
        return self._key() == other._key()

    def __hash__(self) -> int:
        value = self._hash
        if value is None:
            value = hash((type(self), self._key()))
            object.__setattr__(self, "_hash", value)
        return value

    def __repr__(self) -> str:
        return self._text()


# -- operators -------------------------------------------------------------------


class _Junction(Condition):
    """The shared part of :class:`And` and :class:`Or`."""

    __slots__ = ("_children", "_inner", "_runs")

    _KEYWORD: ClassVar[str]
    _SYMBOL: ClassVar[str]
    _JSON_KEY: ClassVar[str]
    _DECISIVE: ClassVar[bool]
    _children: tuple[Condition, ...]
    _inner: int
    # Compiled runs of adjacent owner-free children for _compile_membership,
    # keyed by the index of the run's first child; filled on first use.
    _runs: dict[int, Callable[[LogEntry], bool]]

    def __init__(self, *operands: Condition) -> None:
        if not operands:
            msg = f"{type(self).__name__}() needs at least one condition"
            raise ValueError(msg)
        same = type(self)
        parts: list[tuple[Condition, ...]] = []
        inner = 0
        for operand in operands:
            if not isinstance(operand, Condition):
                msg = (
                    f"{type(self).__name__}() takes conditions, not "
                    f"{type(operand).__name__}; callables are not conditions"
                )
                raise TypeError(msg)
            if type(operand) is same:
                parts.append(operand._children)
                inner = max(inner, operand._inner)
            else:
                parts.append((operand,))
                inner = max(inner, operand._nesting)
        if inner + 1 > MAX_NESTING:
            msg = f"conditions nest more than {MAX_NESTING} levels deep"
            raise ValueError(msg)
        object.__setattr__(self, "_children", tuple(chain.from_iterable(parts)))
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_runs", {})
        object.__setattr__(self, "_nesting", inner + 1)

    @property
    def conditions(self) -> tuple[Condition, ...]:
        """The operands, flattened, in written order."""
        return self._children

    def packages(self) -> frozenset[str]:
        return frozenset().union(*(c.packages() for c in self._children))

    def fields(self) -> frozenset[str]:
        return frozenset().union(*(c.fields() for c in self._children))

    def _emit(self, emitter: _Emitter) -> str:
        return emitter.join(self._KEYWORD, [c._emit(emitter) for c in self._children])

    def _membership(
        self, member: Callable[[LogEntry, frozenset[str]], bool | None]
    ) -> Callable[[LogEntry], bool | None]:
        if not self._has_package():
            return self.compile()
        # Each run of consecutive owner-free children becomes one compiled
        # junction of the same kind, which keeps the written order, the early
        # exit and the order of calls to ``member``.
        terms: list[Callable[[LogEntry], bool | None]] = []
        start = 0
        children = self._children
        for index, child in enumerate(children):
            if child._has_package():
                if start < index:
                    terms.append(self._compile_run(start, index))
                terms.append(child._membership(member))
                start = index + 1
        if start < len(children):
            terms.append(self._compile_run(start, len(children)))
        # And stops at the first False, Or at the first True; an undecided term
        # only matters when no later term decides.
        decisive = self._DECISIVE

        def judge(entry: LogEntry) -> bool | None:
            undecided = False
            for term in terms:
                verdict = term(entry)
                if verdict is None:
                    undecided = True
                elif verdict is decisive:
                    return decisive
            return None if undecided else not decisive

        return judge

    def _compile_run(self, start: int, stop: int) -> Callable[[LogEntry], bool]:
        """Compile ``children[start:stop]``, all owner-free, as one junction.

        A single child reuses its own :meth:`compile` cache; a longer run is
        cached here, keyed by ``start``, because it does not depend on
        ``member`` and the same junction may be compiled again.
        """
        if stop - start == 1:
            return self._children[start].compile()
        function = self._runs.get(start)
        if function is None:
            function = type(self)(*self._children[start:stop]).compile()
            self._runs[start] = function
        return function

    def _has_package(self) -> bool:
        return any(c._has_package() for c in self._children)

    def _package_names(self) -> frozenset[str]:
        return frozenset().union(*(c._package_names() for c in self._children))

    def _json(self) -> dict[str, Any]:
        return {self._JSON_KEY: [c._json() for c in self._children]}

    def _key(self) -> tuple[object, ...]:
        return self._children

    def _text(self) -> str:
        children = self._children
        if len(children) == 1:
            return f"{type(self).__name__}({children[0]._text()})"
        separator = f" {self._SYMBOL} "
        return "(" + separator.join(c._operand_text() for c in children) + ")"


class And(_Junction):
    """Matches when every operand matches (``a & b``).

    Operands that are themselves ``And`` are flattened:
    ``And(And(a, b), c)`` holds ``[a, b, c]``. Terms are evaluated in written
    order and evaluation stops at the first that does not match.

    ``a & b`` copies the operands of ``a``, so building a long chain one
    operator at a time takes quadratic time. Build one with ``And(*terms)``
    instead (and use ``Tag(*names)`` for several tags).
    """

    __slots__ = ()

    _KEYWORD = "and"
    _SYMBOL = "&"
    _JSON_KEY = "all"
    _DECISIVE = False


class Or(_Junction):
    """Matches when any operand matches (``a | b``).

    Operands that are themselves ``Or`` are flattened. Terms are evaluated in
    written order and evaluation stops at the first that matches.

    ``a | b`` copies the operands of ``a``, so building a long chain one
    operator at a time takes quadratic time. Build one with ``Or(*terms)``
    instead (and use ``Tag(*names)`` for several tags).
    """

    __slots__ = ()

    _KEYWORD = "or"
    _SYMBOL = "|"
    _JSON_KEY = "any"
    _DECISIVE = True


class Not(Condition):
    """Matches when the operand does not (``~a``)."""

    __slots__ = ("_operand",)

    _operand: Condition

    def __init__(self, operand: Condition) -> None:
        if not isinstance(operand, Condition):
            msg = (
                f"Not() takes a condition, not {type(operand).__name__}; "
                "callables are not conditions"
            )
            raise TypeError(msg)
        if operand._nesting + 1 > MAX_NESTING:
            msg = f"conditions nest more than {MAX_NESTING} levels deep"
            raise ValueError(msg)
        object.__setattr__(self, "_operand", operand)
        object.__setattr__(self, "_nesting", operand._nesting + 1)

    @property
    def condition(self) -> Condition:
        """The negated condition."""
        return self._operand

    def packages(self) -> frozenset[str]:
        return self._operand.packages()

    def fields(self) -> frozenset[str]:
        return self._operand.fields()

    def _emit(self, emitter: _Emitter) -> str:
        return f"(not {self._operand._emit(emitter)})"

    def _membership(
        self, member: Callable[[LogEntry, frozenset[str]], bool | None]
    ) -> Callable[[LogEntry], bool | None]:
        if not self._operand._has_package():
            return self.compile()
        operand = self._operand._membership(member)

        def negate(entry: LogEntry) -> bool | None:
            verdict = operand(entry)
            return None if verdict is None else not verdict

        return negate

    def _has_package(self) -> bool:
        return self._operand._has_package()

    def _package_names(self) -> frozenset[str]:
        return self._operand._package_names()

    def _json(self) -> dict[str, Any]:
        return {"not": self._operand._json()}

    def _key(self) -> tuple[object, ...]:
        return (self._operand,)

    def _text(self) -> str:
        return "~" + self._operand._operand_text()


# -- Level -------------------------------------------------------------------------

_LEVEL_JSON_KEYS: Final = {
    "ge": "level",
    "gt": "level_gt",
    "le": "level_le",
    "lt": "level_lt",
    "eq": "level_eq",
    "ne": "level_ne",
}
_LEVEL_SYMBOLS: Final = {
    "ge": ">=",
    "gt": ">",
    "le": "<=",
    "lt": "<",
    "eq": "==",
    "ne": "!=",
}


def _check_level(level: object) -> str:
    if not isinstance(level, str):
        msg = f"a level must be a str, not {type(level).__name__}"
        raise TypeError(msg)
    if len(level) != 1 or level not in _LEVELS:
        msg = f"{level!r} is not a log level: use one of V, D, I, W, E, F"
        raise ValueError(msg)
    return str.__str__(level)


class _LevelTest(Condition):
    """A comparison of the entry's level with a level (``Level >= "W"``)."""

    __slots__ = ("_accepted", "_level", "_operator")

    _level: str
    _operator: str
    _accepted: str

    def __init__(self, operator: str, level: str) -> None:
        level = _check_level(level)
        position = _LEVELS.index(level)
        accepted = {
            "ge": _LEVELS[position:],
            "gt": _LEVELS[position + 1 :],
            "le": _LEVELS[: position + 1],
            "lt": _LEVELS[:position],
            "eq": level,
            "ne": _LEVELS.replace(level, ""),
        }[operator]
        object.__setattr__(self, "_operator", operator)
        object.__setattr__(self, "_level", level)
        object.__setattr__(self, "_accepted", accepted)

    def fields(self) -> frozenset[str]:
        return frozenset({"level"})

    def _emit(self, emitter: _Emitter) -> str:
        if self._operator == "ne":
            return f"e.level != {self._level!r}"
        accepted = self._accepted
        if len(accepted) == 1:
            return f"e.level == {accepted!r}"
        if not accepted:
            return "False"
        return f"e.level in {{{', '.join(map(repr, accepted))}}}"

    def _json(self) -> dict[str, Any]:
        return {_LEVEL_JSON_KEYS[self._operator]: self._level}

    def _key(self) -> tuple[object, ...]:
        return (self._operator, self._level)

    def _text(self) -> str:
        return f"Level {_LEVEL_SYMBOLS[self._operator]} {self._level!r}"

    def _operand_text(self) -> str:
        return f"({self._text()})"


class _LevelField:
    """The ``Level`` singleton: comparing it with a level makes a condition.

    The order is V < D < I < W < E < F: ``Level >= "W"`` matches W, E and F,
    ``Level == "E"`` only E, ``Level != "V"`` everything but V.
    """

    __slots__ = ()

    def __ge__(self, level: LogLevel) -> Condition:
        return _LevelTest("ge", level)

    def __gt__(self, level: LogLevel) -> Condition:
        return _LevelTest("gt", level)

    def __le__(self, level: LogLevel) -> Condition:
        return _LevelTest("le", level)

    def __lt__(self, level: LogLevel) -> Condition:
        return _LevelTest("lt", level)

    def __eq__(self, level: object) -> Condition:  # ty: ignore[invalid-method-override]
        return _LevelTest("eq", level)

    def __ne__(self, level: object) -> Condition:  # ty: ignore[invalid-method-override]
        return _LevelTest("ne", level)

    __hash__ = object.__hash__

    def __repr__(self) -> str:
        return "Level"


#: Compare with a level letter to make a condition: ``Level >= "W"``.
Level: Final = _LevelField()


# -- Tag, Pid, Tid, Uid, Package ---------------------------------------------------


class _Members(Condition):
    """An entry field that must be one of some values."""

    __slots__ = ("_values",)

    _FIELD: ClassVar[str]
    _NAME: ClassVar[str]
    _KIND: ClassVar[type]
    _values: tuple[Any, ...]

    def __init__(self, *values: Any) -> None:  # noqa: ANN401
        if not values:
            msg = f"{self._NAME}() needs at least one value"
            raise ValueError(msg)
        kind = self._KIND
        exact: list[Any] = []
        for value in values:
            if not isinstance(value, kind) or isinstance(value, bool):
                msg = (
                    f"{self._NAME}() takes {kind.__name__} values, "
                    f"not {type(value).__name__}"
                )
                raise TypeError(msg)
            # A subclass (an enum member, say) becomes the plain built-in value,
            # which is what the generated code and the JSON form hold.
            if kind is str:
                value = str.__str__(value)
            else:
                value = int.__int__(value)
                if not -_INT_LIMIT < value < _INT_LIMIT:
                    msg = f"{self._NAME}() takes integers below 2**63 in size"
                    raise ValueError(msg)
            exact.append(value)
        object.__setattr__(self, "_values", tuple(dict.fromkeys(exact)))

    def fields(self) -> frozenset[str]:
        return frozenset({self._FIELD})

    def _emit(self, emitter: _Emitter) -> str:
        values = self._values
        if len(values) == 1:
            return f"e.{self._FIELD} == {values[0]!r}"
        return f"e.{self._FIELD} in {{{', '.join(map(repr, values))}}}"

    def _json(self) -> dict[str, Any]:
        return {self._FIELD: list(self._values)}

    def _key(self) -> tuple[object, ...]:
        return (frozenset(self._values),)

    def _text(self) -> str:
        return f"{self._NAME}({', '.join(map(repr, self._values))})"


class Tag(_Members):
    """Matches entries whose tag is exactly one of ``names``."""

    __slots__ = ()

    _FIELD = "tag"
    _NAME = "Tag"
    _KIND = str

    def __init__(self, *names: str) -> None:
        super().__init__(*names)


class Pid(_Members):
    """Matches entries whose process id is one of ``pids``."""

    __slots__ = ()

    _FIELD = "pid"
    _NAME = "Pid"
    _KIND = int

    def __init__(self, *pids: int) -> None:
        super().__init__(*pids)


class Tid(_Members):
    """Matches entries whose thread id is one of ``tids``."""

    __slots__ = ()

    _FIELD = "tid"
    _NAME = "Tid"
    _KIND = int

    def __init__(self, *tids: int) -> None:
        super().__init__(*tids)


class Uid(_Members):
    """Matches entries whose uid is one of ``uids``.

    An entry without a uid never matches.
    """

    __slots__ = ()

    _FIELD = "uid"
    _NAME = "Uid"
    _KIND = int

    def __init__(self, *uids: int) -> None:
        super().__init__(*uids)


class Package(_Members):
    """Matches entries attributed to one of the packages (``entry.package``).

    An entry that carries no package never matches.

    A stream or a dump with this condition finds the package of each line
    from its uid and the device's list of installed packages, and sets
    ``entry.package`` of the entries it delivers. Only the names of
    ``Package`` terms are watched. Not promised:

    - Every line getting a verdict with its app: a stream counts the lines it
      had to judge without a usable list, or without a list that could check
      their app, in ``DeviceSummary.unattributed`` (see `logprobe.stream`);
      the points below say which lines it does not count.
    - Telling apart packages that share a uid: they match each other's lines.
      A watched package that runs under a system uid (below 10000) matches
      every process of that uid (a WARNING says so). ``entry.package`` is the
      first watched owner by name.
    - Lines of an app's isolated processes (app ids 90000 to 99999, for
      example a WebView renderer) are not attributed to the app, and not
      counted as unattributed either.
    - Other users of the device are matched by app id (the uid modulo
      100000). How an app installed only for a secondary user is listed is
      not verified; its lines may not be attributed.
    - Lines of a removed app in the backlog belong to no watched package.
      With ``since`` None a stream tells the backlog by the device clock read
      just before the list; a clock step back can make lines of a newly
      installed app look older, and they are then judged as belonging to no
      watched package. If the next list shows a watched package under their
      uid, they are counted as unattributed (with a WARNING).
    - When a watched app gets a new uid (a reinstall) or is removed, the lines
      judged with the old uid since the previous list are counted as
      unattributed, even when they were judged right. Until a list that starts
      30 seconds or more after that one (normally the next list taken every 30
      seconds; a list taken for a read in between does not end it), or that
      shows a watched app under the old uid, every line of the old uid that is
      read after that (a system uid too, whatever else the condition asks) is
      delivered as if no package owned it and counted too (a reader that is
      behind the device may still read late lines of the app). When a
      watched app turns up under a uid whose lines were judged as not its own
      since the previous list (a uid that was freed and given again, an app
      that appeared after its lines, or one that joined a shared uid, also
      one of another watched app or a system uid), those lines are counted
      the same way. The lines of one uid are counted once per list, and
      every line of that uid counts, whether or not the condition had to ask
      about its package. The lines read while the list taken every 30 seconds
      runs are judged with the previous list; when the new list may have been
      taken before them, they are counted by the list after it. No line is
      counted twice.
    - A watched app that no list ever names, because it was installed after
      one list and removed before the list taken for a read of its lines (a
      stream that is behind the device, or a reconnect that reads the missed
      lines again), is not attributed: its lines are delivered as if no
      package owned them. Those whose verdict depends on their app are
      counted as unattributed when they were logged at or after the device
      clock read before the first list, or always with ``since="now"`` or
      when that clock could not be read (a WARNING names the cause of the
      device's first unattributed line: for such a line, that the app of its
      uid could not be checked). This holds for every app id from 10000 to
      19999 that the list taken for a read does not name, until a list names
      it: the lines of an app that is not watched, installed and removed while
      the stream was behind, are counted too, and the lines of an app id that
      no list ever names (perhaps an app installed only for another user,
      which is not verified) are counted for as long as the stream runs. When
      the list taken for the read names the app id (another app got it after
      the watched app was removed), the lines are judged as that app's, and
      the reuse alone does not count them; they are still counted when the
      app id is one a watched package recently left. A line's verdict depends on its app when the condition,
      evaluated with the line's app unknown (three-valued: true, false or
      undecided), is undecided. A line that a term without packages excludes
      (``Tag("other")`` under ``Package(A) & Tag("keep")``) is not delivered
      whether or not it is A's, so not counting it loses nothing. The
      evaluation looks only at the terms, so such a line under
      ``Package(A) | ~Package(A)`` is counted although it is delivered either
      way. Lines that look older than that clock (after a clock step back)
      are not counted either.
    - A dump judges by the list read just before it.
    - A stream does not read a device while it takes the device's package
      list at the start (at most 5 seconds) or for a read with a line whose
      app id the latest list cannot explain: reading pauses only for such a
      read, normally 0.03-0.14 seconds and at most 2 seconds, counted from
      when its bytes arrived. An older logd may skip lines then, and
      ``detect_skips`` does not see it. The list taken every 30 seconds runs
      in the background: the lines read meanwhile are judged with the
      previous list, and the new one applies from the next network read on,
      or from a read that waits for it. The asyncio stream judges a network
      read in parts of about 8 KiB, so a network read whose later part waits
      for that list has its earlier parts judged with the previous list,
      where the blocking stream judges the whole of it with the new one (it
      also judges a network read of more than 2048 lines in parts). The two
      may then deliver different lines and count different lines as
      unattributed; each counts every line it judged with a list that the
      new one shows was outdated.
    - ``Crash`` and ``Anr`` with a package read the message text, not the uid.
    """

    __slots__ = ()

    _FIELD = "package"
    _NAME = "Package"
    _KIND = str

    def __init__(self, *names: str) -> None:
        super().__init__(*names)
        for name in self._values:
            if _PLAIN_NAME_RE.fullmatch(name) is None:
                msg = (
                    f"{name!r} is not a package name: dot-separated segments of "
                    "ASCII letters, digits and '_', each starting with a letter"
                )
                if _PACKAGE_NAME.fullmatch(name):
                    msg += (
                        "; a process name never matches entry.package, use "
                        "Crash(package=...) or Anr(package=...) to name a process"
                    )
                raise ValueError(msg)

    def packages(self) -> frozenset[str]:
        return frozenset(self._values)

    def _has_package(self) -> bool:
        return True

    def _package_names(self) -> frozenset[str]:
        return frozenset(self._values)

    def _membership(
        self, member: Callable[[LogEntry, frozenset[str]], bool | None]
    ) -> Callable[[LogEntry], bool | None]:
        names = frozenset(self._values)

        def owned(entry: LogEntry) -> bool | None:
            return member(entry, names)

        return owned


# -- Message -----------------------------------------------------------------------


class _MessageContains(Condition):
    __slots__ = ("_needle",)

    _needle: str

    def __init__(self, text: str) -> None:
        if not isinstance(text, str):
            msg = f"Message.contains() takes a str, not {type(text).__name__}"
            raise TypeError(msg)
        object.__setattr__(self, "_needle", str.__str__(text))

    def fields(self) -> frozenset[str]:
        return frozenset({"message"})

    def _emit(self, emitter: _Emitter) -> str:
        return f"{self._needle!r} in e.message"

    def _json(self) -> dict[str, Any]:
        return {"message": self._needle}

    def _key(self) -> tuple[object, ...]:
        return (self._needle,)

    def _text(self) -> str:
        return f"Message.contains({self._needle!r})"


class _MessageMatches(Condition):
    __slots__ = ("_pattern", "_regex")

    _pattern: str
    _regex: re.Pattern[str]

    def __init__(self, pattern: str) -> None:
        if not isinstance(pattern, str):
            msg = f"Message.matches() takes a str, not {type(pattern).__name__}"
            raise TypeError(msg)
        pattern = str.__str__(pattern)
        try:
            regex = re.compile(pattern)
        except (re.error, RecursionError, OverflowError) as error:
            msg = f"{pattern!r} is not a regular expression: {error}"
            raise ValueError(msg) from error
        object.__setattr__(self, "_pattern", pattern)
        object.__setattr__(self, "_regex", regex)

    def fields(self) -> frozenset[str]:
        return frozenset({"message"})

    def _emit(self, emitter: _Emitter) -> str:
        return f"{emitter.bind(self._regex.search)}(e.message) is not None"

    def _json(self) -> dict[str, Any]:
        return {"message_matches": self._pattern}

    def _key(self) -> tuple[object, ...]:
        return (self._pattern,)

    def _text(self) -> str:
        return f"Message.matches({self._pattern!r})"


class _MessageField:
    """The ``Message`` singleton, with ``contains`` and ``matches``."""

    __slots__ = ()

    def contains(self, text: str) -> Condition:
        """Match entries whose message contains ``text``."""
        return _MessageContains(text)

    def matches(self, pattern: str) -> Condition:
        """Match entries whose message has a match of the regex ``pattern``.

        The pattern is compiled once, when the condition is made, and searched
        (``re.search``), not anchored.

        Raises:
            ValueError: ``pattern`` is not a valid regular expression.
        """
        return _MessageMatches(pattern)

    def __repr__(self) -> str:
        return "Message"


#: Message conditions: ``Message.contains("text")``, ``Message.matches("re")``.
Message: Final = _MessageField()


# -- Crash and Anr -----------------------------------------------------------------


class _ProcessLine(Condition):
    """A condition on the line Android logs about one process, by its text."""

    __slots__ = ("_package",)

    _NAME: ClassVar[str]
    _package: str | None

    def __init__(self, package: str | None = None) -> None:
        object.__setattr__(self, "_package", _check_process_package(package))

    def packages(self) -> frozenset[str]:
        if self._package is None:
            return _NO_FIELDS
        return frozenset({self._package.partition(":")[0]})

    def fields(self) -> frozenset[str]:
        return frozenset({"tag", "level", "message"})

    def _json(self) -> dict[str, Any]:
        return {
            self._NAME.lower(): {}
            if self._package is None
            else {"package": self._package}
        }

    def _key(self) -> tuple[object, ...]:
        return (self._package,)

    def _text(self) -> str:
        if self._package is None:
            return f"{self._NAME}()"
        return f"{self._NAME}(package={self._package!r})"


class Crash(_ProcessLine):
    """Matches the line Android logs when an app crashes.

    Without ``package``: the ``FATAL EXCEPTION: <thread>`` line of a Java
    crash (tag ``AndroidRuntime``, level E), of any app.

    With ``package``, the line that names the crashed process, read from the
    message, so no package attribution is needed and it works offline:

    - a Java crash: the ``Process: <name>, PID: <pid>`` line (tag
      ``AndroidRuntime``, level E);
    - a native crash: the tombstone line
      ``pid: <pid>, tid: <tid>, name: <thread>  >>> <name> <<<`` (tag
      ``DEBUG``, level F).

    ``<name>`` matches when it is ``package`` or starts with ``package + ":"``
    (a secondary process of the app), so ``com.example.app`` does not match
    ``com.example.application``. ``package`` may itself be a process name
    (``com.example.app:remote``, ``com.example.app:ishared:worker``); it then
    also matches the processes whose names continue it after a ``:``.

    Raises:
        ValueError: ``package`` is not a package name.
        TypeError: ``package`` is not a str or None.
    """

    __slots__ = ()

    _NAME = "Crash"

    def _emit(self, emitter: _Emitter) -> str:
        if self._package is None:
            return (
                f"(e.tag == {_CRASH_TAG!r} and e.level == {_CRASH_LEVEL!r} "
                f"and {_CRASH_MESSAGE!r} in e.message)"
            )
        return emitter.bind(_crash_with_package(self._package)) + "(e)"


class Anr(_ProcessLine):
    """Matches the line Android logs when an app does not respond (ANR).

    An entry with tag ``ActivityManager`` and level E whose message starts with
    ``ANR in``. system_server logs the line, not the app, so
    ``Package(app) & Anr()`` does not find the app's ANRs; use
    ``Anr(package=app)``.

    With ``package``, the text after the prefix names the process
    (``ANR in <name> (<component>)``): ``<name>`` ends at a space, ``(`` or
    the end of the message, and matches when it is ``package`` or starts with
    ``package + ":"``. ``package`` may itself be a process name, as for
    :class:`Crash`. No package attribution is needed and it works offline.

    Raises:
        ValueError: ``package`` is not a package name.
        TypeError: ``package`` is not a str or None.
    """

    __slots__ = ()

    _NAME = "Anr"

    def _emit(self, emitter: _Emitter) -> str:
        if self._package is None:
            return (
                f"(e.tag == {_ANR_TAG!r} and e.level == {_ANR_LEVEL!r} "
                f"and e.message.startswith({_ANR_PREFIX!r}))"
            )
        return emitter.bind(_anr_with_package(self._package)) + "(e)"


# -- keyword shortcuts -------------------------------------------------------------


def _one_or_many(value: object) -> tuple[Any, ...]:
    if isinstance(value, list | tuple):
        return tuple(value)
    return (value,)


def build_condition(
    where: Condition | None = None,
    *,
    level: LogLevel | None = None,
    tag: str | list[str] | tuple[str, ...] | None = None,
    message: str | None = None,
    package: str | list[str] | tuple[str, ...] | None = None,
    pid: int | list[int] | tuple[int, ...] | None = None,
) -> Condition | None:
    """Combine ``where`` and the keyword shortcuts with AND; None if all are None.

    ``level="W"`` is ``Level >= "W"``; ``tag``, ``package`` and ``pid`` take
    one value or a list (any of them matches); ``message`` is
    ``Message.contains``. The cheap field tests come first and ``where`` last;
    conditions have no side effects, so the order changes speed only.

    Raises:
        TypeError: ``where`` is not a :class:`Condition` (callables are not
            accepted) or a value has the wrong type.
        ValueError: A value is not valid, such as an unknown level or an empty list.
    """
    if where is not None and not isinstance(where, Condition):
        msg = f"where must be a Condition, not {type(where).__name__}"
        raise TypeError(msg)
    terms: list[Condition] = []
    if level is not None:
        terms.append(Level >= level)
    if tag is not None:
        terms.append(Tag(*_one_or_many(tag)))
    if pid is not None:
        terms.append(Pid(*_one_or_many(pid)))
    if package is not None:
        terms.append(Package(*_one_or_many(package)))
    if message is not None:
        terms.append(Message.contains(message))
    if where is not None:
        terms.append(where)
    if not terms:
        return None
    if len(terms) == 1:
        return terms[0]
    return And(*terms)


# -- JSON --------------------------------------------------------------------------


def _fail(path: str, problem: str) -> NoReturn:
    raise ValueError(f"{path}: {problem}")


def _json_list(value: object, path: str, kind: type, kind_name: str) -> list[Any]:
    if not isinstance(value, list) or not value:
        _fail(path, f"expected a non-empty list of {kind_name}s")
    for index, item in enumerate(value):
        if not isinstance(item, kind) or isinstance(item, bool):
            _fail(
                f"{path}[{index}]", f"expected {kind_name}, got {type(item).__name__}"
            )
    return value


def _json_str(value: object, path: str) -> str:
    if not isinstance(value, str):
        _fail(path, f"expected a string, got {type(value).__name__}")
    return value


def _json_process(cls: type[_ProcessLine], value: object, path: str) -> Condition:
    if not isinstance(value, dict):
        _fail(path, f"expected an object, got {type(value).__name__}")
    for key in value:
        if key != "package":
            _fail(f"{path}.{key}", "unknown key (only 'package' is allowed)")
    if "package" not in value:
        return cls()
    package = _json_str(value["package"], f"{path}.package")
    try:
        return cls(package)
    except ValueError as error:
        _fail(f"{path}.package", str(error))


_LEVEL_FROM_KEY: Final = {key: op for op, key in _LEVEL_JSON_KEYS.items()}
_MEMBERS_FROM_KEY: Final[dict[str, tuple[type[_Members], type, str]]] = {
    "tag": (Tag, str, "string"),
    "pid": (Pid, int, "integer"),
    "tid": (Tid, int, "integer"),
    "uid": (Uid, int, "integer"),
    "package": (Package, str, "string"),
}


_TEXT_FROM_KEY: Final[dict[str, Callable[[str], Condition]]] = {
    "message": Message.contains,
    "message_matches": Message.matches,
}
_PROCESS_FROM_KEY: Final[dict[str, type[_ProcessLine]]] = {"crash": Crash, "anr": Anr}


def _leaf_from_json(key: str, value: object, where: str) -> Condition:
    if key in _LEVEL_FROM_KEY:
        level = _json_str(value, where)
        try:
            return _LevelTest(_LEVEL_FROM_KEY[key], level)
        except ValueError as error:
            _fail(where, str(error))
    if key in _MEMBERS_FROM_KEY:
        cls, kind, kind_name = _MEMBERS_FROM_KEY[key]
        items = _json_list(value, where, kind, kind_name)
        try:
            return cls(*items)
        except ValueError as error:
            _fail(where, str(error))
    if key in _TEXT_FROM_KEY:
        text = _json_str(value, where)
        try:
            return _TEXT_FROM_KEY[key](text)
        except ValueError as error:
            _fail(where, str(error))
    if key in _PROCESS_FROM_KEY:
        return _json_process(_PROCESS_FROM_KEY[key], value, where)
    return _fail(where, "unknown key")


def _from_json(obj: object, path: str, nesting: int) -> Condition:
    """Build a condition; recursion is bounded by ``MAX_NESTING``."""
    if not isinstance(obj, dict):
        _fail(path, f"expected an object, got {type(obj).__name__}")
    if len(obj) != 1:
        _fail(path, f"expected exactly one key, got {list(obj)!r}")
    ((key, value),) = obj.items()
    where = f"{path}.{key}"
    if key not in ("all", "any", "not"):
        return _leaf_from_json(key, value, where)
    if nesting >= MAX_NESTING:
        _fail(path, f"nested more than {MAX_NESTING} levels deep")
    if key == "not":
        return Not(_from_json(value, where, nesting + 1))
    if not isinstance(value, list) or not value:
        _fail(where, "expected a non-empty list of objects")
    operands = [
        _from_json(item, f"{where}[{i}]", nesting + 1) for i, item in enumerate(value)
    ]
    return And(*operands) if key == "all" else Or(*operands)
