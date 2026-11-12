"""Apply a decision's obligations to a result: mask columns, then filter rows.

Row filters are SQL predicates so a query engine can push them down. For tools that
return rows themselves, ``RowsEnforcer`` evaluates them in Python over a small, defined
dialect (the open question in the plan was that free SQL needs one)::

    filter     := or
    or         := and ("OR" and)*
    and        := not ("AND" not)*
    not        := "NOT" not | "(" or ")" | comparison
    comparison := column ("=" | "!=" | "<>" | "<" | "<=" | ">" | ">=") literal
                | column ["NOT"] "IN" "(" literal ("," literal)* ")"
                | column "IS" ["NOT"] "NULL"
    literal    := 'string' (with '' for a quote) | number | TRUE | FALSE | NULL

Anything outside it raises ``RowFilterError``, and the caller returns nothing: a filter
Trellis can't apply is never skipped (fail closed). A row without a column the filter
names is dropped, not kept.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import Any, Protocol

MASK = "***"

Row = dict[str, Any]
Predicate = Callable[[Row], bool]


class RowFilterError(ValueError):
    """The filter is outside the dialect, so no rows are returned."""


class Enforcer(Protocol):
    """Applies a decision's obligations (masks, row filter) to a result."""

    def apply(self, obligations: dict[str, Any], result: Any) -> Any: ...


_TOKEN = re.compile(
    r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<num>-?\d+(?:\.\d+)?)|(?P<op><>|!=|<=|>=|=|<|>)"
    r"|(?P<punct>[(),])|(?P<word>[A-Za-z_][A-Za-z0-9_.]*))"
)
_KEYWORDS = {"AND", "OR", "NOT", "IN", "IS", "NULL", "TRUE", "FALSE"}
_MISSING = object()


def _tokens(text: str) -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    pos = 0
    text = text.rstrip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise RowFilterError(f"can't read the row filter at {text[pos : pos + 20]!r}")
        pos = m.end()
        if m.group("str") is not None:
            out.append(("lit", m.group("str")[1:-1].replace("''", "'")))
        elif m.group("num") is not None:
            n = m.group("num")
            out.append(("lit", float(n) if "." in n else int(n)))
        elif m.group("op") is not None:
            out.append(("op", m.group("op")))
        elif m.group("punct") is not None:
            out.append((m.group("punct"), m.group("punct")))
        else:
            word = m.group("word")
            up = word.upper()
            if up in ("TRUE", "FALSE"):
                out.append(("lit", up == "TRUE"))
            elif up in _KEYWORDS:
                out.append((up, up))
            else:
                out.append(("col", word))
    return out


class _Parser:
    def __init__(self, text: str) -> None:
        self.toks = _tokens(text)
        self.i = 0

    def peek(self) -> str | None:
        return self.toks[self.i][0] if self.i < len(self.toks) else None

    def take(self, kind: str) -> Any:
        if self.peek() != kind:
            got = self.toks[self.i][1] if self.i < len(self.toks) else "the end"
            raise RowFilterError(f"expected {kind} in the row filter, got {got}")
        self.i += 1
        return self.toks[self.i - 1][1]

    def parse(self) -> Predicate:
        pred = self.or_()
        if self.i != len(self.toks):
            raise RowFilterError(f"unexpected {self.toks[self.i][1]!r} in the row filter")
        return pred

    def or_(self) -> Predicate:
        parts = [self.and_()]
        while self.peek() == "OR":
            self.take("OR")
            parts.append(self.and_())
        return parts[0] if len(parts) == 1 else (lambda r: any(p(r) for p in parts))

    def and_(self) -> Predicate:
        parts = [self.not_()]
        while self.peek() == "AND":
            self.take("AND")
            parts.append(self.not_())
        return parts[0] if len(parts) == 1 else (lambda r: all(p(r) for p in parts))

    def not_(self) -> Predicate:
        if self.peek() == "NOT":
            self.take("NOT")
            inner = self.not_()
            return lambda r: not inner(r)
        if self.peek() == "(":
            self.take("(")
            inner = self.or_()
            self.take(")")
            return inner
        return self.comparison()

    def literal(self) -> Any:
        if self.peek() == "NULL":
            self.take("NULL")
            return None
        return self.take("lit")

    def comparison(self) -> Predicate:
        col = self.take("col")
        kind = self.peek()
        if kind == "IS":
            self.take("IS")
            negate = self.peek() == "NOT"
            if negate:
                self.take("NOT")
            self.take("NULL")
            return lambda r: _has(r, col) and ((r[col] is None) != negate)
        if kind in ("IN", "NOT"):
            negate = kind == "NOT"
            if negate:
                self.take("NOT")
            self.take("IN")
            self.take("(")
            values = [self.literal()]
            while self.peek() == ",":
                self.take(",")
                values.append(self.literal())
            self.take(")")
            return lambda r: _has(r, col) and r[col] is not None and ((r[col] in values) != negate)
        op = self.take("op")
        value = self.literal()
        return lambda r: _has(r, col) and _compare(r[col], op, value)


def _has(row: Row, col: str) -> bool:
    return row.get(col, _MISSING) is not _MISSING


def _compare(left: Any, op: str, right: Any) -> bool:
    if left is None or right is None:
        return False  # SQL: a comparison with NULL is never true
    try:
        if op == "=":
            return bool(left == right)
        if op in ("!=", "<>"):
            return bool(left != right)
        if op == "<":
            return bool(left < right)
        if op == "<=":
            return bool(left <= right)
        if op == ">":
            return bool(left > right)
        return bool(left >= right)
    except TypeError:
        return False


def compile_filter(text: str) -> Predicate:
    return _Parser(text).parse()


class RowsEnforcer:
    """Enforces obligations on a list of row dicts, as an MCP tool or a test returns them."""

    def apply(self, obligations: dict[str, Any], result: Iterable[Row]) -> list[Row]:
        mask: dict[str, str] = obligations.get("mask") or {}
        row_filter: str | None = obligations.get("row_filter")
        keep = compile_filter(row_filter) if row_filter else None
        out = []
        for row in result:
            if keep is not None and not keep(row):
                continue
            out.append({k: (MASK if k in mask else v) for k, v in row.items()})
        return out
