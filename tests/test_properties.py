"""Property tests: a call is allowed exactly when all three checks allow it, and each check
answers only from its own limit, whatever the other two say."""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from trellisd.config import TrellisConfig
from trellisd.db import Database
from trellisd.engine import Engine
from trellisd.grants import GrantStore

from conftest import NOW

TAGS = ["a", "b", "c", "d"]
tagsets = st.frozensets(st.sampled_from(TAGS))
nonempty = st.frozensets(st.sampled_from(TAGS), min_size=1)

STORE = GrantStore(Database(":memory:"))


def build(
    table: frozenset[str], rule: frozenset[str], ceiling: frozenset[str], never: frozenset[str]
) -> Engine:
    cfg = TrellisConfig.model_validate(
        {
            "people": {"p@x": {"groups": ["g"]}},
            "agents": {
                "bot": {"owner": "o", "ceiling": {"tags": sorted(ceiling), "never": sorted(never)}}
            },
            "access": [{"id": "r", "who": ["group:g"], "tags": sorted(rule)}] if rule else [],
            "catalog": {"ds.t": {"tags": sorted(table), "columns": {"x": []}}},
        }
    )
    return Engine(cfg)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(table=nonempty, rule=tagsets, ceiling=tagsets, never=tagsets, scope=nonempty)
def test_allowed_iff_all_three_allow(
    table: frozenset[str],
    rule: frozenset[str],
    ceiling: frozenset[str],
    never: frozenset[str],
    scope: frozenset[str],
) -> None:
    engine = build(table, rule, ceiling, never)
    grant = STORE.build(
        kind="personal",
        subject="p@x",
        agent="bot",
        scope=scope,
        actions=("read",),
        issued_by="p@x",
        now=NOW,
    )
    d = engine.decide(grant, "read", "ds.t", now=NOW)

    person = bool(rule & table)
    ceil = bool(ceiling) and table <= ceiling and not (table & never)
    task = bool(scope & table)
    assert tuple(c.allowed for c in d.checks) == (person, ceil, task)
    assert d.allowed == (person and ceil and task)
    assert set(d.denied_by) == {
        n for n, ok in (("person", person), ("ceiling", ceil), ("task", task)) if not ok
    }


@settings(max_examples=150, deadline=None)
@given(table=nonempty, scope=nonempty)
def test_a_permit_for_one_limit_never_satisfies_another(
    table: frozenset[str], scope: frozenset[str]
) -> None:
    # The person may read everything and the ceiling covers everything; only the task scope
    # varies. A task scope that misses the table must still refuse, even though permits
    # covering the same resource exist in the other two sets.
    engine = build(table, frozenset(TAGS), frozenset(TAGS), frozenset())
    grant = STORE.build(
        kind="personal",
        subject="p@x",
        agent="bot",
        scope=scope,
        actions=("read",),
        issued_by="p@x",
        now=NOW,
    )
    d = engine.decide(grant, "read", "ds.t", now=NOW)
    assert d.allowed == bool(scope & table)
    # And the other way round: a scope that covers everything doesn't stand in for the
    # person's access or the ceiling.
    empty = build(table, frozenset(), frozenset(), frozenset())
    wide = STORE.build(
        kind="personal",
        subject="p@x",
        agent="bot",
        scope=frozenset(TAGS),
        actions=("read",),
        issued_by="p@x",
        now=NOW,
    )
    d = empty.decide(wide, "read", "ds.t", now=NOW)
    assert d.denied_by == ("person", "ceiling")
