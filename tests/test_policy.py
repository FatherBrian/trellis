from __future__ import annotations

from pathlib import Path

import pytest

from moat import PolicyError, load_policies

from conftest import EXAMPLES


def test_example_policies_load() -> None:
    bundle = load_policies(EXAMPLES / "policies.yaml")

    assert bundle.agents["report-bot"].ceiling == {"finance", "pii"}
    (policy,) = bundle.policies
    assert policy.action == ("read", "query")
    assert [str(c) for c in policy.column_conditions] == ["column.tags excludes pii"]


@pytest.mark.parametrize(
    "condition",
    ["grant.scope has finance", "user.role contains admin", "column.tags excludes"],
)
def test_malformed_conditions_fail_closed(tmp_path: Path, condition: str) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        f"policies:\n  - action: read\n    conditions: ['{condition}']\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError):
        load_policies(path)


def test_duplicate_policy_ids_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "dup.yaml"
    path.write_text(
        "policies:\n  - {id: a, action: read}\n  - {id: a, action: query}\n", encoding="utf-8"
    )
    with pytest.raises(PolicyError, match="duplicate"):
        load_policies(path)
