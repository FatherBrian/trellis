"""Read ODCS v3 data contracts as Trellis contracts (read-only).

Teams already on the Open Data Contract Standard keep their contracts; Trellis maps what
access decisions need and refuses a contract it can't map fully, rather than guess.

What maps:

* ``id`` is the URN (``urn:odcs:<id>`` unless it is already a URN); ``version`` carries over.
* The owner and steward come from ``team`` (roles ``owner`` / ``data owner`` and
  ``steward`` / ``data steward``). No owner, no contract.
* Each object in ``schema`` becomes one Trellis contract bound to its table: a dotted
  ``physicalName``, or the one server's ``schema`` plus the name.
* ``tags`` and ``classification`` (on the contract, each object and each property) become
  tags; a classification on the ranked scale becomes that level.
* ``roles`` become access: ``group:<role>``, read or write.
* ODCS has no masks or row filters, so they come from ``customProperties``:
  ``trellis.mask``, ``trellis.rows``, ``trellis.purposes`` and ``trellis.bindings``.

What's refused: another major version, a missing id or owner, a nested property, a table
it can't place, a role with an access level other than read or write, and any unknown
``trellis.*`` custom property. Sections access doesn't use (quality, SLAs, pricing,
support) are ignored and listed as ignored.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from trellisd.config import Contract, ContractAccess

_OWNER_ROLES = {"owner", "data owner", "dataowner", "data_owner"}
_STEWARD_ROLES = {"steward", "data steward", "datasteward", "data_steward"}
_KNOWN_CUSTOM = {"trellis.mask", "trellis.rows", "trellis.purposes", "trellis.bindings"}
#: Top-level ODCS sections that say nothing about access.
_IGNORED = (
    "quality",
    "slaProperties",
    "slaDefaultElement",
    "price",
    "support",
    "authoritativeDefinitions",
    "contractCreatedTs",
    "dataProduct",
    "domain",
    "tenant",
    "status",
    "description",
)
_ACCESS = {
    "read": ("read", "query"),
    "readonly": ("read", "query"),
    "write": ("read", "query", "write"),
    "readwrite": ("read", "query", "write"),
}


class OdcsError(ValueError):
    """The contract can't be mapped fully, so Trellis won't use any of it."""


@dataclass
class Mapped:
    contracts: list[Contract]
    ignored: list[str] = field(default_factory=list)


def _tags(*values: Any) -> set[str]:
    out: set[str] = set()
    for v in values:
        if v is None:
            continue
        if isinstance(v, str):
            out.add(v.strip().lower())
        elif isinstance(v, list):
            out |= {str(x).strip().lower() for x in v}
        else:
            raise OdcsError(f"expected a tag or list of tags, got {v!r}")
    return {t for t in out if t}


def _custom(items: Any, where: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in items or []:
        prop = str(item.get("property", ""))
        if prop.startswith("trellis."):
            if prop not in _KNOWN_CUSTOM:
                raise OdcsError(f"{where}: unknown custom property {prop}")
            out[prop] = item.get("value")
    return out


def _list(value: Any, what: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return list(value)
    raise OdcsError(f"{what} must be a string or a list of strings")


def to_contracts(doc: dict[str, Any]) -> Mapped:
    api = str(doc.get("apiVersion", ""))
    if not api.startswith("v3."):
        raise OdcsError(f"only ODCS v3 is supported, this is {api or 'unversioned'}")
    if doc.get("kind") != "DataContract":
        raise OdcsError("kind must be DataContract")
    cid = doc.get("id")
    if not cid:
        raise OdcsError("the contract has no id, so it can't have a stable URN")
    urn = str(cid) if str(cid).startswith("urn:") else f"urn:odcs:{cid}"

    owner = steward = None
    for member in doc.get("team") or []:
        role = str(member.get("role", "")).strip().lower()
        name = member.get("username") or member.get("name")
        if role in _OWNER_ROLES and owner is None:
            owner = name
        elif role in _STEWARD_ROLES and steward is None:
            steward = name
    if not owner:
        raise OdcsError("no team member has the owner role, and Trellis needs a named owner")

    custom = _custom(doc.get("customProperties"), "contract")
    mask = _tags(custom.get("trellis.mask"))
    rows = _list(custom.get("trellis.rows"), "trellis.rows")
    purposes = _tags(custom.get("trellis.purposes"))
    explicit_bindings = _list(custom.get("trellis.bindings"), "trellis.bindings")

    access: dict[str, ContractAccess] = {}
    for r in doc.get("roles") or []:
        role = r.get("role")
        if not role:
            raise OdcsError("a role has no name")
        level = str(r.get("access", "read")).replace(" ", "").replace("-", "").lower()
        if level not in _ACCESS:
            raise OdcsError(f"role {role} has access {r.get('access')!r}; only read or write map")
        access[str(role)] = ContractAccess(
            who=(f"group:{role}",), actions=_ACCESS[level], mask=frozenset(mask)
        )

    servers = doc.get("servers") or []
    schemas = {s.get("schema") for s in servers if s.get("schema")}
    objects = doc.get("schema") or []
    if not objects:
        raise OdcsError("the contract describes no tables (schema is empty)")
    if explicit_bindings and len(objects) > 1:
        raise OdcsError("trellis.bindings needs a contract with one schema object")

    top_tags = _tags(doc.get("tags"), doc.get("classification"))
    out: list[Contract] = []
    for obj in objects:
        name = obj.get("name")
        if not name:
            raise OdcsError("a schema object has no name")
        _custom(obj.get("customProperties"), f"schema object {name}")
        physical = str(obj.get("physicalName") or name)
        if explicit_bindings:
            bindings = explicit_bindings
        elif "." in physical:
            bindings = [physical]
        elif len(schemas) == 1:
            bindings = [f"{next(iter(schemas))}.{physical}"]
        else:
            raise OdcsError(
                f"can't tell which table {name} is: give it a dotted physicalName, one server"
                " with a schema, or trellis.bindings"
            )
        elements: dict[str, frozenset[str]] = {}
        for prop in obj.get("properties") or []:
            pname = prop.get("physicalName") or prop.get("name")
            if not pname:
                raise OdcsError(f"a property of {name} has no name")
            if prop.get("properties") or prop.get("items"):
                raise OdcsError(f"{name}.{pname} has nested properties; v0.1 maps flat tables only")
            _custom(prop.get("customProperties"), f"{name}.{pname}")
            elements[str(pname)] = frozenset(_tags(prop.get("tags"), prop.get("classification")))
        obj_urn = urn if len(objects) == 1 else f"{urn}:{name}"
        try:
            out.append(
                Contract(
                    contract=obj_urn,
                    version=str(doc.get("version", "1")),
                    kind="table",
                    description=str(obj.get("description") or doc.get("description") or ""),
                    bindings=tuple(bindings),
                    owner=str(owner),
                    steward=steward,
                    tags=frozenset(top_tags | _tags(obj.get("tags"), obj.get("classification"))),
                    elements=elements,
                    purposes=frozenset(purposes),
                    access=access,
                    rows=tuple(rows),
                    origin="odcs",
                )
            )
        except ValidationError as exc:
            raise OdcsError(str(exc)) from exc
    ignored = [k for k in _IGNORED if k in doc]
    return Mapped(out, ignored)
