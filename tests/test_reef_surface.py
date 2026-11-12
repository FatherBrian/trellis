"""The trellisd names Reef (reef-mcp, github.com/FatherBrian/reef) imports.

Reef lives in its own repo and depends on released trellisd, so removing or renaming one of
these breaks a published reef-mcp. Change them only in a new minor version, and update Reef
first. The private names at the end are kept for reef-mcp 0.1.0.
"""

import importlib

import pytest

REEF_USES = {
    "trellisd.app": ["Trellis"],
    "trellisd.cli": ["event_line", "parse_duration", "print_issued", "print_table", "print_trace"],
    "trellisd.config": [
        "ACTIONS",
        "CatalogSource",
        "Contract",
        "ContractAccess",
        "TrellisConfig",
        "load_config",
    ],
    "trellisd.db": ["DEFAULT_URL", "Database"],
    "trellisd.demo_idp": ["DEMO_SECRETS", "http"],
    "trellisd.enforce": ["RowFilterError", "compile_filter"],
    "trellisd.engine": ["MASK", "Decision"],
    "trellisd.fake_iceberg": ["FakeIcebergCatalog"],
    "trellisd.fake_idp": ["FakeIdP"],
    "trellisd.grants": ["Grant", "GrantError", "IssuedGrant"],
    "trellisd.iceberg": ["IcebergRestAdmin", "IcebergRestTagSource"],
    "trellisd.identity": ["Identities", "IdentityError"],
    "trellisd.ledger": ["Ledger", "LedgerUnavailable"],
    "trellisd.server": ["TOKEN_EXCHANGE", "TrellisServer"],
    "trellisd.signing": ["Signer"],
    "trellisd.trace": ["recorded_decision", "trace"],
}

# reef-mcp 0.1.0 imports these from trellisd.cli; they stay until trellisd 0.2.
REEF_0_1_0_USES = {"trellisd.cli": ["_event_line", "_table"]}


@pytest.mark.parametrize(
    ("module", "name"),
    [(m, n) for uses in (REEF_USES, REEF_0_1_0_USES) for m, ns in uses.items() for n in ns],
)
def test_reef_can_import(module: str, name: str) -> None:
    assert hasattr(importlib.import_module(module), name), f"Reef imports {module}.{name}"
