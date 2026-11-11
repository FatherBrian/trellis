"""Contracts: the format, the binding index, the ODCS adapter, and Cedar compilation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from trellisd import Trellis, load_config
from trellisd.catalog import ConfigCatalog, Resolver
from trellisd.compiler import Compiler, render
from trellisd.config import ConfigError, Contract, TrellisConfig, contract_schema
from trellisd.db import Database
from trellisd.odcs import OdcsError, to_contracts

from conftest import ANA, NOW, ROOT

LAKEHOUSE = ROOT / "examples" / "lakehouse"
FIXTURES = Path(__file__).parent / "fixtures" / "odcs"
JOURNAL = "finance.gl.journal_entries"
CASH = "finance.treasury.cash_positions"


def _odcs(name: str) -> dict:  # type: ignore[type-arg]
    return yaml.safe_load((FIXTURES / name).read_text())


# -- the format -----------------------------------------------------------------------------


def test_lakehouse_example_loads_both_kinds_of_contract() -> None:
    cfg = load_config(LAKEHOUSE)
    gl = cfg.contracts["urn:contract:finance.gl"]
    cash = cfg.contracts["urn:odcs:treasury-cash-positions"]
    assert gl.origin == "trellis"
    assert gl.tables == (JOURNAL,)
    assert gl.version_id.startswith("v3@")
    assert cash.origin == "odcs"
    assert cash.bindings == (CASH,)
    assert cash.tags == {"finance", "confidential"}
    assert cash.elements["account"] == {"pii"}
    assert cash.owner == "treasury-owner@example.com"


def test_version_id_changes_with_the_content() -> None:
    gl = load_config(LAKEHOUSE).contracts["urn:contract:finance.gl"]
    changed = gl.model_copy(
        update={"elements": {**gl.elements, "approver_email": frozenset({"pii"})}}
    )
    assert changed.version == gl.version
    assert changed.version_id != gl.version_id


def test_two_contracts_claiming_one_table_is_a_load_error(tmp_path: Path) -> None:
    for name in ("a", "b"):
        (tmp_path / f"{name}.yaml").write_text(
            yaml.safe_dump(
                {"contract": f"urn:contract:{name}", "bindings": [JOURNAL], "owner": "o@x"}
            )
        )
    with pytest.raises(ConfigError, match="claimed by two contracts"):
        load_config(tmp_path)


def test_contract_schema_is_published() -> None:
    schema = contract_schema()
    assert schema["title"] == "Trellis contract"
    assert {"contract", "bindings", "owner", "elements", "access", "rows"} <= set(
        schema["properties"]
    )
    assert "origin" not in schema["properties"]


def test_bad_contract_is_refused(tmp_path: Path) -> None:
    (tmp_path / "c.yaml").write_text("contract: urn:contract:x\nbindings: [a.b]\n")
    with pytest.raises(ConfigError, match="owner"):
        load_config(tmp_path)


def test_contract_compiles_to_a_permit_with_its_mask_and_row_rule() -> None:
    text = render(load_config(LAKEHOUSE))
    assert '@id("contract.finance.gl.analysts") @mask("pii")' in text
    assert '@row_filter("region = {person.region}")' in text
    assert 'resource in Table::"finance.gl.journal_entries"' in text
    assert Compiler(load_config(LAKEHOUSE)).validate() == []


def test_levels_widen_in_the_safe_direction() -> None:
    cfg = load_config(LAKEHOUSE)
    assert cfg.at_or_below(frozenset({"confidential"})) == {"public", "internal", "confidential"}
    assert cfg.at_or_above(frozenset({"internal"})) == {"internal", "confidential", "restricted"}
    text = render(cfg)
    # report-bot's ceiling lists confidential, so it reaches internal and public too.
    assert '["confidential", "finance", "internal", "pii", "public"].containsAll' in text


# -- the ODCS adapter -----------------------------------------------------------------------


def test_odcs_maps_owner_tags_roles_and_custom_properties() -> None:
    mapped = to_contracts(_odcs("journal.odcs.yaml"))
    (c,) = mapped.contracts
    assert c.contract == "urn:contract:finance.gl"
    assert c.bindings == (JOURNAL,)
    assert c.owner == "finance-owner@example.com"
    assert c.steward == "finance-steward@example.com"
    assert c.tags == {"finance", "internal"}
    assert set(c.elements) == {"entry_id", "amount", "region", "approver_email"}
    assert c.access["finance-analysts"].who == ("group:finance-analysts",)
    assert c.access["finance-analysts"].mask == {"pii"}
    assert c.rows == ("region = {person.region}",)
    assert c.purposes == {"financial_close"}
    assert mapped.ignored == ["slaProperties", "status"]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"apiVersion": "v2.2.2"}, "only ODCS v3"),
        ({"id": None}, "no id"),
        ({"team": []}, "owner role"),
        ({"roles": [{"role": "x", "access": "admin"}]}, "only read or write"),
        ({"servers": []}, "can't tell which table"),
        ({"customProperties": [{"property": "trellis.maks", "value": ["pii"]}]}, "unknown custom"),
        ({"schema": []}, "describes no tables"),
    ],
)
def test_odcs_refuses_what_it_cant_map_fully(change: dict, message: str) -> None:  # type: ignore[type-arg]
    doc = {**_odcs("journal.odcs.yaml"), **change}
    with pytest.raises(OdcsError, match=message):
        to_contracts(doc)


def test_odcs_refuses_nested_properties() -> None:
    with pytest.raises(OdcsError, match="nested properties"):
        to_contracts(_odcs("nested.odcs.yaml"))


def test_odcs_error_names_the_file(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text((FIXTURES / "nested.odcs.yaml").read_text())
    with pytest.raises(ConfigError, match=r"bad\.yaml: .*nested"):
        load_config(tmp_path)


def _with_contract(contract: Contract) -> TrellisConfig:
    base = load_config(LAKEHOUSE)
    return base.model_copy(update={"contracts": {contract.contract: contract}, "catalogs": {}})


DECISION_MATRIX = [
    ("query", None),
    ("read", ["entry_id", "amount"]),
    ("read", ["approver_email", "region"]),
    ("export", None),
    ("write", ["amount"]),
]


@pytest.mark.parametrize("catalog_tags", [{}, {"approver_email": {"pii"}}, {"notes": set()}])
def test_odcs_twin_decides_exactly_like_the_trellis_contract(catalog_tags: dict) -> None:  # type: ignore[type-arg]
    handwritten = load_config(LAKEHOUSE).contracts["urn:contract:finance.gl"]
    (twin,) = to_contracts(_odcs("journal.odcs.yaml")).contracts
    cols = {"entry_id": set(), "amount": set(), "region": set(), "approver_email": set()}
    cols.update(catalog_tags)
    observed = ConfigCatalog(
        {JOURNAL: (frozenset({"finance"}), {c: frozenset(t) for c, t in cols.items()})}
    )
    outcomes = []
    for contract in (handwritten, twin):
        cfg = _with_contract(contract)
        t = Trellis(cfg, Database(":memory:"), catalog=Resolver.from_config(cfg, [observed]))
        issued = t.issue_grant(
            person=ANA, agent="report-bot", task="Q3", scope={"finance"}, now=NOW
        )
        row = []
        for action, columns in DECISION_MATRIX:
            d = t.authorize(issued.token, action, JOURNAL, columns, now=NOW)
            row.append((d.allowed, d.denied_by, sorted(d.masked), d.row_filter, d.resource_tags))
        outcomes.append(row)
        t.close()
    assert outcomes[0] == outcomes[1]
    assert outcomes[0][0][0] is True  # and the matrix isn't all denies
