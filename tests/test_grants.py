from __future__ import annotations

from datetime import timedelta

import pytest

from writ import GrantError, GrantStore

from conftest import ALICE, NOW, issue


def test_token_resolves_to_its_grant_until_it_expires(grants: GrantStore) -> None:
    issued = issue(grants, {"finance"}, ttl_minutes=30)

    assert grants.resolve(issued.token, now=NOW + timedelta(minutes=29)) == issued.grant
    with pytest.raises(GrantError, match="expired"):
        grants.resolve(issued.token, now=NOW + timedelta(minutes=30))


def test_revoke_stops_the_token(grants: GrantStore) -> None:
    issued = issue(grants, {"finance"})
    grants.revoke(issued.grant.id, now=NOW)

    with pytest.raises(GrantError, match="revoked"):
        grants.resolve(issued.token, now=NOW + timedelta(minutes=1))


def test_unknown_token_is_rejected(grants: GrantStore) -> None:
    with pytest.raises(GrantError, match="unknown token"):
        grants.resolve("writ_not-a-token", now=NOW)


@pytest.mark.parametrize(
    ("scope", "ttl", "message"),
    [
        (set(), timedelta(hours=1), "at least one tag"),
        ({"finance"}, timedelta(0), "positive"),
        ({"finance"}, timedelta(days=2), "exceeds the maximum"),
    ],
)
def test_issue_validates_scope_and_ttl(
    grants: GrantStore, scope: set[str], ttl: timedelta, message: str
) -> None:
    with pytest.raises(GrantError, match=message):
        grants.issue(human=ALICE, agent="report-bot", task="t", scope=scope, ttl=ttl, now=NOW)
