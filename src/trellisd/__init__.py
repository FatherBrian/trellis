"""Trellis: delegated access control and a tamper-evident audit ledger for AI agents.

The package, import and CLI name is ``trellisd``.
"""

from trellisd.app import Trellis
from trellisd.catalog import Catalog, ConfigCatalog, TableInfo
from trellisd.config import ConfigError, TrellisConfig, load_config
from trellisd.db import Database
from trellisd.engine import CheckResult, Decision, Engine
from trellisd.grants import Grant, GrantError, GrantStore, IssuedGrant
from trellisd.ledger import Ledger, LedgerEvent, LedgerUnavailable, VerifyResult

__version__ = "0.1.0"

__all__ = [
    "Catalog",
    "CheckResult",
    "ConfigCatalog",
    "ConfigError",
    "Database",
    "Decision",
    "Engine",
    "Grant",
    "GrantError",
    "GrantStore",
    "IssuedGrant",
    "Ledger",
    "LedgerEvent",
    "LedgerUnavailable",
    "TableInfo",
    "Trellis",
    "TrellisConfig",
    "VerifyResult",
    "__version__",
    "load_config",
]
