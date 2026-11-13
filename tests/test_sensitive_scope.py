"""The task check and sensitive tags: a scope must name a sensitive tag to reach what carries it.

From the task-template experiment: with a scope of [hr], a tool tagged hr and pii got through,
and pii fields of an hr tool weren't masked, because the check needed only one matching tag.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from trellisd import GrantError, Trellis
from trellisd.config import TrellisConfig

ANA = "ana@example.com"

TOOLS: dict[str, dict[str, Any]] = {
    "mcp://hr/headcount": {"tags": ["hr", "internal"]},
    "mcp://hr/payroll": {"tags": ["hr", "confidential"], "fields": {"team": [], "salary": ["pii"]}},
    "mcp://hr/performance_reviews": {"tags": ["hr", "confidential", "pii"]},
    "mcp://clinic/visits": {"tags": ["health", "phi"]},
}


def config(**extra: Any) -> TrellisConfig:
    contracts = {
        f"urn:contract:{a.removeprefix('mcp://').replace('/', '.')}": {
            "contract": f"urn:contract:{a.removeprefix('mcp://').replace('/', '.')}",
            "kind": "mcp_tool",
            "bindings": [a],
            "owner": "owner@example.com",
            "tags": t["tags"],
            "elements": t.get("fields", {}),
            "access": {"ana": {"who": [f"user:{ANA}"], "actions": ["read"]}},
        }
        for a, t in TOOLS.items()
    }
    return TrellisConfig.model_validate(
        {
            "agents": {
                "bot": {
                    "owner": "owner@example.com",
                    "ceiling": {"tags": ["hr", "health", "pii", "phi", "confidential"]},
                }
            },
            "contracts": contracts,
            **extra,
        }
    )


@pytest.fixture
def trellis() -> Any:
    with Trellis(config(), "sqlite:///:memory:") as t:
        yield t


def grant(t: Trellis, *scope: str) -> str:
    return t.issue_grant(person=ANA, agent="bot", task="Headcount review", scope=set(scope)).token


def test_a_domain_scope_reaches_plain_tools_of_that_domain(trellis: Trellis) -> None:
    assert trellis.authorize(grant(trellis, "hr"), "read", "mcp://hr/headcount").allowed


def test_a_domain_scope_does_not_reach_a_tool_that_is_also_pii(trellis: Trellis) -> None:
    d = trellis.authorize(grant(trellis, "hr"), "read", "mcp://hr/performance_reviews")
    assert not d.allowed
    assert d.denied_by == ("task",)
    assert "is pii, and the grant covers hr without pii" in d.reason


def test_a_domain_scope_masks_pii_fields(trellis: Trellis) -> None:
    d = trellis.authorize(grant(trellis, "hr"), "read", "mcp://hr/payroll")
    assert d.allowed
    assert list(d.masked) == ["salary"]
    assert d.masked["salary"].startswith("the grant's scope doesn't include pii")
    assert "urn:contract:hr.payroll" in d.masked["salary"]  # and where the pii tag came from


def test_naming_pii_in_the_scope_reaches_it(trellis: Trellis) -> None:
    token = grant(trellis, "hr", "pii")
    assert trellis.authorize(token, "read", "mcp://hr/performance_reviews").allowed
    d = trellis.authorize(token, "read", "mcp://hr/payroll")
    assert d.allowed
    assert d.masked == {}


def test_pii_alone_is_not_a_task(trellis: Trellis) -> None:
    with pytest.raises(GrantError, match="names only pii; a task needs a domain"):
        grant(trellis, "pii")


def test_other_tags_can_be_made_sensitive() -> None:
    with Trellis(config(sensitive=["pii", "phi"]), "sqlite:///:memory:") as t:
        assert not t.authorize(grant(t, "health"), "read", "mcp://clinic/visits").allowed
        assert t.authorize(grant(t, "health", "phi"), "read", "mcp://clinic/visits").allowed
    with Trellis(config(), "sqlite:///:memory:") as t:  # phi isn't sensitive by default
        assert t.authorize(grant(t, "health"), "read", "mcp://clinic/visits").allowed


def test_sensitive_can_be_turned_off() -> None:
    with Trellis(config(sensitive=[]), "sqlite:///:memory:") as t:
        assert t.authorize(grant(t, "hr"), "read", "mcp://hr/performance_reviews").allowed


# -- the property: a grant never reaches a sensitive tag its scope doesn't name --------------

DOMAINS = ["finance", "hr", "sales"]
SENSITIVE = ["pii", "phi"]
ALL = DOMAINS + SENSITIVE


@settings(max_examples=60, deadline=None)
@given(
    tags=st.sets(st.sampled_from(ALL), min_size=1),
    fields=st.dictionaries(
        st.sampled_from(["a", "b", "c"]), st.sets(st.sampled_from(ALL)), max_size=3
    ),
    scope=st.sets(st.sampled_from(DOMAINS), min_size=1) | st.just(set()),
    extra=st.sets(st.sampled_from(SENSITIVE)),
)
def test_no_grant_reaches_an_unnamed_sensitive_tag(
    tags: set[str], fields: dict[str, set[str]], scope: set[str], extra: set[str]
) -> None:
    scope = scope or {"finance"}
    scope |= extra
    cfg = TrellisConfig.model_validate(
        {
            "sensitive": SENSITIVE,
            "agents": {"bot": {"owner": "o@example.com", "ceiling": {"tags": ALL}}},
            "contracts": {
                "urn:contract:t": {
                    "contract": "urn:contract:t",
                    "kind": "mcp_tool",
                    "bindings": ["mcp://s/t"],
                    "owner": "o@example.com",
                    "tags": sorted(tags),
                    "elements": {k: sorted(v) for k, v in fields.items()},
                    "access": {"ana": {"who": [f"user:{ANA}"], "actions": ["read"]}},
                },
                # a resource for every tag, so Ana can reach (and grant) any of them
                **{
                    f"urn:contract:{t}": {
                        "contract": f"urn:contract:{t}",
                        "kind": "mcp_tool",
                        "bindings": [f"mcp://reach/{t}"],
                        "owner": "o@example.com",
                        "tags": [t, "finance"] if t in SENSITIVE else [t],
                        "access": {"ana": {"who": [f"user:{ANA}"], "actions": ["read"]}},
                    }
                    for t in ALL
                },
            },
        }
    )
    with Trellis(cfg, "sqlite:///:memory:") as t:
        token = t.issue_grant(person=ANA, agent="bot", task="x", scope=scope).token
        d = t.authorize(token, "read", "mcp://s/t")
        unnamed = (tags & set(SENSITIVE)) - scope
        if unnamed:
            assert not d.allowed  # the tool carries a sensitive tag the scope didn't name
            return
        if not d.allowed:
            return
        for col, ctags in fields.items():
            if (ctags & set(SENSITIVE)) - scope:
                assert col in d.masked, (col, ctags, scope)  # and so does this field
