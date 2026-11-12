"""Contract and catalog disagree: the precedence table, and adding a source never widens."""

from __future__ import annotations

from collections.abc import Iterable

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from trellisd import Trellis, load_config
from trellisd.catalog import (
    ConfigCatalog,
    ObservedTags,
    Resolver,
    SourceUnavailable,
    TagSourceInfo,
    normalize,
)
from trellisd.config import Contract, ContractAccess, TrellisConfig
from trellisd.db import Database
from trellisd.engine import Decision

from conftest import ANA, NOW, ROOT

LAKEHOUSE = ROOT / "examples" / "lakehouse"
T = "finance.gl.journal_entries"
LEVELS = ("public", "internal", "confidential", "restricted")


class Source:
    """A tag source that reports fixed tags, or is down."""

    def __init__(
        self,
        name: str,
        tags: Iterable[str] = (),
        columns: dict[str, set[str]] | None = None,
        *,
        owner: str | None = None,
        down: bool = False,
    ) -> None:
        self.name = name
        self._tags = frozenset(tags)
        self._columns = {c: frozenset(t) for c, t in (columns or {}).items()}
        self.owner = owner
        self.down = down

    def tags(self, address: str) -> ObservedTags | None:
        if self.down:
            raise SourceUnavailable(self.name, f"catalog {self.name} is down")
        if address != T:
            return None
        return ObservedTags(
            T,
            self._tags,
            dict(self._columns),
            TagSourceInfo(f"catalog {self.name}", "7"),
            owner=self.owner,
        )

    def addresses(self) -> list[str]:
        return [T]


def contract(
    tags: Iterable[str] = ("finance",),
    elements: dict[str, set[str]] | None = None,
    mask: Iterable[str] = ("pii",),
    rows: tuple[str, ...] = ("region = {person.region}",),
) -> Contract:
    return Contract(
        contract="urn:contract:finance.gl",
        version="3",
        bindings=(T,),
        owner="finance-owner@example.com",
        tags=frozenset(tags),
        elements={
            c: frozenset(t)
            for c, t in (
                elements
                or {"entry_id": set(), "amount": set(), "region": set(), "approver_email": set()}
            ).items()
        },
        access={"analysts": ContractAccess(who=("group:finance-analysts",), mask=frozenset(mask))},
        rows=rows,
    )


def config_with(c: Contract | None) -> TrellisConfig:
    base = load_config(LAKEHOUSE)
    return base.model_copy(update={"contracts": {c.contract: c} if c else {}, "catalogs": {}})


def decide(
    c: Contract | None, *sources: Source, columns: list[str] | None = None, scope: str = "finance"
) -> Decision:
    cfg = config_with(c)
    resolver = Resolver(dict(cfg.contracts), list(sources), cfg.scale)
    with Trellis(cfg, Database(":memory:"), catalog=resolver) as t:
        g = t.grants.build(
            kind="personal",
            subject=ANA,
            agent="report-bot",
            task="Q3",
            scope=frozenset({scope}),
            actions=("read", "query"),
            issued_by=ANA,
            now=NOW,
        )
        return t.decide(g, "query", T, columns, now=NOW)


def resolve(c: Contract | None, *sources: Source):  # type: ignore[no-untyped-def]
    return Resolver({c.contract: c} if c else {}, list(sources), LEVELS).table(T)


# -- the precedence table -------------------------------------------------------------------


def test_contract_tags_apply_with_no_catalog() -> None:
    info = resolve(contract(tags={"finance", "internal"}))
    assert info.tags == {"finance", "internal"}
    assert info.provenance["finance"][0].source == "contract urn:contract:finance.gl"


def test_a_catalog_tag_adds_to_the_contract() -> None:
    info = resolve(contract(), Source("lake", columns={"approver_email": {"pii"}}))
    assert info.column_tags("approver_email") == {"finance", "pii"}
    assert [s.source for s in info.sources_of("approver_email", "pii")] == ["catalog lake"]


def test_a_tag_both_give_carries_both_sources() -> None:
    info = resolve(contract(), Source("lake", tags={"finance"}))
    assert [s.source for s in info.provenance["finance"]] == [
        "contract urn:contract:finance.gl",
        "catalog lake",
    ]


@pytest.mark.parametrize(
    ("contract_level", "catalog_level", "wins"),
    [
        ("internal", "confidential", "confidential"),
        ("restricted", "internal", "restricted"),
        ("confidential", "confidential", "confidential"),
        (None, "internal", "internal"),
        ("internal", None, "internal"),
    ],
)
def test_ranked_levels_take_the_higher(
    contract_level: str | None, catalog_level: str | None, wins: str
) -> None:
    c = contract(tags={"finance", *([contract_level] if contract_level else [])})
    info = resolve(c, Source("lake", tags={"finance", *([catalog_level] if catalog_level else [])}))
    assert info.tags & set(LEVELS) == {wins}


def test_a_catalog_cant_remove_a_contract_tag() -> None:
    c = contract(elements={"amount": set(), "approver_email": {"pii"}})
    info = resolve(c, Source("lake", tags=set(), columns={"approver_email": set()}))
    assert "pii" in info.column_tags("approver_email")
    assert "finance" in info.tags


def test_owner_comes_from_the_contract_only() -> None:
    info = resolve(contract(), Source("lake", owner="someone-else@example.com"))
    assert info.owner == "finance-owner@example.com"
    assert info.catalog_owners == {"catalog lake": "someone-else@example.com"}


def test_drift_a_catalog_column_the_contract_lacks_is_masked() -> None:
    d = decide(contract(), Source("lake", tags={"finance"}, columns={"notes": set()}))
    assert d.allowed
    assert d.masked["notes"].startswith("drift:")


def test_a_contract_column_the_catalog_lacks_isnt_drift() -> None:
    info = resolve(contract(), Source("lake", columns={"amount": set()}))
    assert info.drift == frozenset()


def test_no_contract_and_no_catalog_denies() -> None:
    d = decide(None)
    assert not d.allowed
    assert d.denied_by == ("catalog",)


def test_catalog_only_tags_classify_without_a_contract() -> None:
    d = decide(
        None, Source("lake", tags={"finance"}, columns={"amount": set()}), columns=["amount"]
    )
    # Classified (the catalog's tags), but no contract role gives Ana access to it.
    assert d.resource_tags == ("finance",)
    assert d.contract is None
    assert d.denied_by == ("person",)


def test_a_source_down_past_its_bound_denies() -> None:
    d = decide(contract(), Source("lake", down=True))
    assert not d.allowed
    assert d.denied_by == ("catalog",)
    assert "pip_unavailable" in d.reason


def test_a_catalog_tag_trips_the_ceiling_and_names_its_source() -> None:
    d = decide(contract(), Source("lake", tags={"restricted"}))
    assert not d.allowed
    assert d.denied_by == ("ceiling",)
    assert "restricted from catalog lake 7" in d.reason


def test_a_catalog_tag_cant_make_a_grant_match() -> None:
    # The grant covers hr; the contract says finance. A catalog adding hr doesn't help.
    hr_ceiling = decide(contract(), Source("lake", tags={"hr"}), scope="hr")
    assert not hr_ceiling.allowed
    assert "task" in hr_ceiling.denied_by


def test_normalize_keeps_the_highest_level() -> None:
    assert normalize({"finance", "public", "confidential"}, LEVELS) == {"finance", "confidential"}


# -- adding a source never widens access ----------------------------------------------------

TAGS = st.sets(st.sampled_from(["finance", "hr", "pii", "export_controlled", *LEVELS]), max_size=3)
COLS = st.dictionaries(st.sampled_from(["amount", "approver_email", "notes"]), TAGS, max_size=3)


def _outcome(d: Decision) -> tuple[bool, set[str]]:
    return d.allowed, set(d.masked)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    with_contract=st.booleans(),
    contract_tags=TAGS,
    first=st.tuples(TAGS, COLS),
    extra=st.tuples(TAGS, COLS),
    scope=st.sampled_from(["finance", "hr", "pii"]),
)
def test_adding_a_source_never_widens_access(
    with_contract: bool,
    contract_tags: set[str],
    first: tuple[set[str], dict[str, set[str]]],
    extra: tuple[set[str], dict[str, set[str]]],
    scope: str,
) -> None:
    c = contract(tags=contract_tags | {"finance"}) if with_contract else None
    cols = ["amount", "approver_email", "notes"]
    base = [Source("lake", first[0], first[1])]
    before = decide(c, *base, columns=cols, scope=scope)
    after = decide(c, *base, Source("other", extra[0], extra[1]), columns=cols, scope=scope)
    if after.allowed:
        assert before.allowed, (before.reason, after.reason)
        assert set(before.masked) <= set(after.masked)
        assert before.row_filter == after.row_filter


def test_config_catalog_alone_still_works_as_a_catalog() -> None:
    cfg = load_config(ROOT / "examples" / "three-keys")
    info = ConfigCatalog.from_config(cfg).table("hr.payroll")
    assert info is not None
    assert info.tags == {"hr", "pii"}
    assert info.declared_tags == {"hr", "pii"}
