"""A server's own contract in reef.yaml: its tools need no contract files."""

from __future__ import annotations

from typing import Any

import pytest

from reef.config import ReefConfig, ReefConfigError
from trellisd.config import Contract, TrellisConfig


def reef(**hr: Any) -> ReefConfig:
    server = {"url": "http://hr/mcp", "credential": "none", **hr}
    return ReefConfig.model_validate({"servers": {"hr": server}})


SERVER = {
    "owner": "hr-lead@example.com",
    "tags": ["hr"],
    "elements": {"region": []},
    "access": {"partners": {"who": ["group:hr-partners"], "actions": ["read"]}},
}


def test_every_tool_gets_the_servers_contract() -> None:
    rc = reef(**SERVER, tools={"headcount": {"action": "read"}, "roster": {}})
    contracts = rc.contracts()
    assert sorted(contracts) == ["urn:contract:hr.headcount", "urn:contract:hr.roster"]
    c = contracts["urn:contract:hr.headcount"]
    assert c.kind == "mcp_tool"
    assert c.bindings == ("mcp://hr/headcount",)
    assert c.owner == "hr-lead@example.com"
    assert c.tags == {"hr"}
    assert set(c.access) == {"partners"}


def test_a_tool_adds_tags_and_overrides_by_name() -> None:
    payroll = {
        "tags": ["confidential"],
        "elements": {"region": ["internal"], "salary": ["pii"]},
        "access": {
            "partners": {"who": ["group:hr-partners"], "actions": ["read"], "mask": ["pii"]},
            "reporting": {"who": ["user:ana@example.com"], "actions": ["read"]},
        },
    }
    c = reef(**SERVER, tools={"payroll": payroll}).contracts()["urn:contract:hr.payroll"]
    assert c.tags == {"hr", "confidential"}  # joined, never replaced
    assert c.elements == {"region": {"internal"}, "salary": {"pii"}}
    assert set(c.access) == {"partners", "reporting"}
    assert c.access["partners"].mask == {"pii"}  # the tool's role replaced the server's


def test_a_tool_with_its_own_resource_binds_that_address() -> None:
    rc = reef(**SERVER, tools={"journal": {"resource": "finance.gl.journal_entries"}})
    assert rc.contracts()["urn:contract:hr.journal"].bindings == ("finance.gl.journal_entries",)


def test_a_server_without_an_owner_has_no_contract() -> None:
    assert reef(tools={"headcount": {}}).contracts() == {}


@pytest.mark.parametrize("field", ["tags", "elements", "access"])
def test_server_classification_without_an_owner_is_an_error(field: str) -> None:
    value = SERVER[field]
    with pytest.raises(ValueError, match="need an owner"):
        reef(**{field: value}, tools={"headcount": {}})


def test_tool_classification_without_an_owner_is_an_error() -> None:
    with pytest.raises(ValueError, match="tools payroll set tags"):
        reef(tools={"headcount": {}, "payroll": {"tags": ["pii"]}})


def test_apply_to_adds_the_contracts_to_trellis() -> None:
    rc = reef(**SERVER, tools={"headcount": {}})
    config = rc.apply_to(TrellisConfig())
    contract = config.contract_for("mcp://hr/headcount")
    assert contract is not None
    assert contract.contract == "urn:contract:hr.headcount"


def test_one_address_keeps_one_contract() -> None:
    existing = Contract(
        contract="urn:contract:hr.people",
        kind="mcp_tool",
        bindings=("mcp://hr/headcount",),
        owner="someone@example.com",
    )
    config = TrellisConfig(contracts={existing.contract: existing})
    with pytest.raises(ReefConfigError, match="keep one"):
        reef(**SERVER, tools={"headcount": {}}).apply_to(config)


def test_apply_to_without_server_contracts_is_unchanged() -> None:
    config = TrellisConfig()
    assert reef(tools={"headcount": {}}).apply_to(config) is config
