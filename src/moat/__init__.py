"""Moat: delegated access control and a tamper-evident audit ledger for AI agents."""

from moat.catalog import Catalog, Column, Human, Resource, YamlCatalog
from moat.decision import Authorizer, Decision, Principal, RequestContext
from moat.grants import AgentProfile, Grant, GrantError, GrantStore, IssuedGrant
from moat.ledger import Ledger, LedgerEvent, VerifyResult
from moat.policy import Policy, PolicyBundle, PolicyError, load_policies

__version__ = "0.0.1"

__all__ = [
    "AgentProfile",
    "Authorizer",
    "Catalog",
    "Column",
    "Decision",
    "Grant",
    "GrantError",
    "GrantStore",
    "Human",
    "IssuedGrant",
    "Ledger",
    "LedgerEvent",
    "Policy",
    "PolicyBundle",
    "PolicyError",
    "Principal",
    "RequestContext",
    "Resource",
    "VerifyResult",
    "YamlCatalog",
    "__version__",
    "load_policies",
]
