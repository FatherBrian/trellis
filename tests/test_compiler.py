"""The YAML compiles to the Cedar we expect, and that Cedar validates against the schema."""

from __future__ import annotations

import os
from pathlib import Path

import cedarpy

from trellisd.compiler import CEDAR_SCHEMA, Compiler, render
from trellisd.config import load_config
from trellisd.db import Database
from trellisd.grants import GrantStore

from conftest import NOW, THREE_KEYS

GOLDEN = Path(__file__).parent / "golden" / "three-keys.cedar"


def test_three_keys_matches_golden() -> None:
    text = render(load_config(THREE_KEYS))
    if os.environ.get("UPDATE_GOLDEN"):
        GOLDEN.write_text(text)
    assert text == GOLDEN.read_text()


def test_generated_cedar_validates() -> None:
    assert Compiler(load_config(THREE_KEYS)).validate() == []


def test_every_policy_carries_an_id_and_obligations() -> None:
    c = Compiler(load_config(THREE_KEYS))
    subject = c.subject_policies()
    ids = [m.id for m in subject.meta]
    assert "access.finance-gl" in ids
    assert "purpose.inspection-review" in ids
    finance = next(m for m in subject.meta if m.id == "access.finance-gl")
    assert finance.mask == {"pii"}
    assert finance.row_filter == "region = {person.region}"
    assert subject.lookup("policy0") == subject.meta[0]
    assert subject.lookup("nonsense") is None
    ceiling = c.ceiling_policies()
    assert [m.effect for m in ceiling.meta if m.id == "ceiling.report-bot.never"] == ["forbid"]


def test_grant_scope_policy_validates_and_carries_the_trigger_filter() -> None:
    cfg = load_config(THREE_KEYS)
    store = GrantStore(Database(":memory:"))
    g = store.build(
        kind="purpose",
        subject="inspection-review",
        agent="inspector-bot",
        scope=frozenset({"quality"}),
        actions=("read",),
        issued_by="x",
        trigger_type="inspection",
        trigger_record="INS-1",
        now=NOW,
    )
    ps = Compiler(cfg).scope_policy(g)
    assert ps.meta[0].row_filter == "inspection_id = {trigger.record}"
    assert cedarpy.validate_policies(ps.text, CEDAR_SCHEMA).validation_passed


def test_entities_build_the_dataset_tree() -> None:
    ents = Compiler(load_config(THREE_KEYS)).entities()
    by = {(e["uid"]["type"], e["uid"]["id"]): e for e in ents}
    assert by[("Dataset", "finance.gl")]["parents"] == [{"type": "Dataset", "id": "finance"}]
    col = by[("Column", "finance.gl.journal_entries.approver_email")]
    assert col["attrs"]["tags"] == ["finance", "pii"]
    assert by[("Person", "ana@example.com")]["parents"] == [
        {"type": "Group", "id": "finance-analysts"}
    ]
