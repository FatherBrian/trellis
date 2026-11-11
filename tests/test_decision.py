"""The intersection of human access, agent ceiling and task scope, denied by default."""

from __future__ import annotations

from datetime import timedelta

from writ import Authorizer, GrantStore, Principal, RequestContext

from conftest import ALICE, BOB, JOURNAL, NOW, issue

CTX = RequestContext(now=NOW + timedelta(minutes=5))


def test_allows_inside_the_intersection_and_masks_what_falls_outside(
    authorizer: Authorizer, grants: GrantStore
) -> None:
    issued = issue(grants, {"finance"})
    d = authorizer.authorize(Principal.from_grant(issued.grant), "read", JOURNAL, CTX)

    assert d.allowed
    assert d.effective_tags == {"finance"}
    # pii is outside the task scope; export_controlled is above report-bot's ceiling.
    assert set(d.masks) == {"approver_email", "part_number"}
    assert d.annotations == {"log": "required"}
    assert d.policy_ids == ("finance-read",)


def test_column_condition_masks_pii_even_when_the_grant_covers_it(
    authorizer: Authorizer, grants: GrantStore
) -> None:
    issued = issue(grants, {"finance", "pii"})
    d = authorizer.authorize(Principal.from_grant(issued.grant), "read", JOURNAL, CTX)

    assert d.allowed
    assert d.effective_tags == {"finance", "pii"}
    assert "approver_email" in d.masks
    assert "column.tags excludes pii" in d.reason


def test_agent_ceiling_wins_over_human_clearance(
    authorizer: Authorizer, grants: GrantStore
) -> None:
    # Alice is cleared for export_controlled and asks for it, but report-bot never may.
    issued = issue(grants, {"finance", "export_controlled"})
    ctx = CTX.model_copy(update={"columns": ("entry_id", "part_number")})
    d = authorizer.authorize(Principal.from_grant(issued.grant), "read", JOURNAL, ctx)

    assert not d.allowed
    assert "part_number" in d.reason
    assert "above report-bot's ceiling" in d.reason


def test_human_access_limits_the_agent(authorizer: Authorizer, grants: GrantStore) -> None:
    # Bob is not cleared for finance, so a grant from Bob cannot reach finance data.
    issued = issue(grants, {"finance"}, human=BOB)
    d = authorizer.authorize(Principal.from_grant(issued.grant), "read", JOURNAL, CTX)

    assert not d.allowed
    assert f"{BOB} is not cleared for it" in d.reason


def test_task_scope_limits_the_agent(authorizer: Authorizer, grants: GrantStore) -> None:
    issued = issue(grants, {"pii"})
    d = authorizer.authorize(Principal.from_grant(issued.grant), "read", JOURNAL, CTX)

    assert not d.allowed
    assert "did not request it" in d.reason


def test_action_without_a_policy_is_denied(authorizer: Authorizer, grants: GrantStore) -> None:
    issued = issue(grants, {"finance"})
    d = authorizer.authorize(Principal.from_grant(issued.grant), "export", JOURNAL, CTX)

    assert not d.allowed
    assert d.reason.startswith("no policy allows")


def test_unknown_and_untagged_resources_are_denied(
    authorizer: Authorizer, grants: GrantStore
) -> None:
    principal = Principal.from_grant(issue(grants, {"finance"}).grant)

    assert not authorizer.authorize(principal, "read", "nope.nothing", CTX).allowed
    untagged = authorizer.authorize(principal, "read", "scratch.unclassified", CTX)
    assert not untagged.allowed
    assert "no tags" in untagged.reason


def test_expired_grant_is_denied(authorizer: Authorizer, grants: GrantStore) -> None:
    issued = issue(grants, {"finance"}, ttl_minutes=10)
    late = RequestContext(now=NOW + timedelta(minutes=11))
    d = authorizer.authorize(Principal.from_grant(issued.grant), "read", JOURNAL, late)

    assert not d.allowed
    assert "expired" in d.reason


def test_revoked_grant_is_denied(authorizer: Authorizer, grants: GrantStore) -> None:
    issued = issue(grants, {"finance"})
    grants.revoke(issued.grant.id, now=NOW)
    d = authorizer.authorize(Principal.from_grant(issued.grant), "read", JOURNAL, CTX)

    assert not d.allowed
    assert "revoked" in d.reason


def test_principal_must_match_the_grant(authorizer: Authorizer, grants: GrantStore) -> None:
    issued = issue(grants, {"finance"})
    spoofed = Principal(agent="report-bot", human=BOB, grant_id=issued.grant.id)

    assert not authorizer.authorize(spoofed, "read", JOURNAL, CTX).allowed


def test_unregistered_agent_is_denied(authorizer: Authorizer, grants: GrantStore) -> None:
    issued = grants.issue(human=ALICE, agent="rogue-bot", task="t", scope={"finance"}, now=NOW)
    d = authorizer.authorize(Principal.from_grant(issued.grant), "read", JOURNAL, CTX)

    assert not d.allowed
    assert "no registered ceiling" in d.reason
