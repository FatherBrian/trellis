"""The Iceberg REST tag source, against responses recorded from two real catalogs, the
in-process fake, and (when one is running) a live catalog."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from trellisd.catalog import SourceUnavailable
from trellisd.config import CatalogSource
from trellisd.fake_iceberg import FakeIcebergCatalog
from trellisd.iceberg import IcebergRestAdmin, IcebergRestTagSource

RECORDED = Path(__file__).parent / "fixtures" / "iceberg"
CATALOGS = ["iceberg-rest-fixture", "polaris"]
T = "finance.gl.journal_entries"


class Recorded:
    """Replays recorded responses: /v1/config, then loadTable as of one step."""

    def __init__(self, catalog: str, step: str) -> None:
        self.dir = RECORDED / catalog
        self.step = step
        self.calls: list[str] = []
        self.down = False

    def load(self, name: str) -> dict:  # type: ignore[type-arg]
        return json.loads((self.dir / f"{name}.json").read_text())  # type: ignore[no-any-return]

    def __call__(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, bytes]:
        if self.down:
            raise OSError("connection refused")
        path = url.split("//", 1)[1].split("/", 1)[1]
        self.calls.append(path)
        config = self.load("config")
        if "v1/config" in path:
            return config["status"], json.dumps(config["body"]).encode()
        rec = self.load("05-missing" if path.endswith("/missing") else self.step)
        assert "/" + path.split("/", 1)[1] == rec["path"] or path.endswith(rec["path"])
        return rec["status"], json.dumps(rec["body"]).encode()


def source(
    transport: object, clock: list[float] | None = None, **kw: object
) -> IcebergRestTagSource:
    now = clock if clock is not None else [0.0]
    warehouse = "lakehouse"
    settings = CatalogSource(uri="http://catalog.test/api", warehouse=warehouse, **kw)  # type: ignore[arg-type]
    return IcebergRestTagSource(
        "lakehouse",
        settings,
        transport=transport,
        clock=lambda: now[0],  # type: ignore[arg-type]
    )


@pytest.mark.parametrize("catalog", CATALOGS)
def test_reads_table_tags_and_every_column(catalog: str) -> None:
    obs = source(Recorded(catalog, "01-created")).tags(T)
    assert obs is not None
    assert obs.tags == {"finance"}
    assert set(obs.columns) == {"entry_id", "amount", "region", "approver_email"}
    assert all(not t for t in obs.columns.values())
    assert obs.source.source == "catalog lakehouse"
    assert obs.source.version.startswith("00000-")


@pytest.mark.parametrize("catalog", CATALOGS)
def test_reads_a_column_tag(catalog: str) -> None:
    obs = source(Recorded(catalog, "02-column-tagged")).tags(T)
    assert obs is not None
    assert obs.columns["approver_email"] == {"pii"}
    assert obs.source.version.startswith("00001-")


@pytest.mark.parametrize("catalog", CATALOGS)
def test_sees_a_new_column_in_the_current_schema(catalog: str) -> None:
    obs = source(Recorded(catalog, "03-column-added")).tags(T)
    assert obs is not None
    assert "notes" in obs.columns


@pytest.mark.parametrize("catalog", CATALOGS)
def test_reads_a_table_level(catalog: str) -> None:
    obs = source(Recorded(catalog, "04-table-level")).tags(T)
    assert obs is not None
    assert obs.tags == {"finance", "confidential"}


@pytest.mark.parametrize("catalog", CATALOGS)
def test_a_missing_table_is_none(catalog: str) -> None:
    assert source(Recorded(catalog, "01-created")).tags("finance.gl.missing") is None


def test_uses_the_prefix_the_catalog_returns() -> None:
    rec = Recorded("polaris", "01-created")
    source(rec).tags(T)
    assert rec.calls[1].endswith("/v1/lakehouse/namespaces/finance%1Fgl/tables/journal_entries")


def test_caches_for_the_ttl_then_rereads() -> None:
    rec, now = Recorded("iceberg-rest-fixture", "01-created"), [0.0]
    src = source(rec, now)
    src.tags(T)
    src.tags(T)
    assert len(rec.calls) == 2  # config + one load
    rec.step = "02-column-tagged"
    now[0] = 301
    obs = src.tags(T)
    assert obs is not None and obs.columns["approver_email"] == {"pii"}


def test_evict_makes_a_new_tag_apply_at_once() -> None:
    rec = Recorded("iceberg-rest-fixture", "01-created")
    src = source(rec)
    src.tags(T)
    rec.step = "02-column-tagged"
    src.evict(T)
    obs = src.tags(T)
    assert obs is not None and obs.columns["approver_email"] == {"pii"}


def test_not_found_is_cached_briefly() -> None:
    rec, now = Recorded("iceberg-rest-fixture", "01-created"), [0.0]
    src = source(rec, now)
    src.tags("finance.gl.missing")
    src.tags("finance.gl.missing")
    assert len(rec.calls) == 2
    now[0] = 31
    src.tags("finance.gl.missing")
    assert len(rec.calls) == 3


def test_down_inside_the_bound_serves_stale_then_fails_closed() -> None:
    rec, now = Recorded("iceberg-rest-fixture", "02-column-tagged"), [0.0]
    src = source(rec, now)
    src.tags(T)
    rec.down = True
    now[0] = 600
    stale = src.tags(T)
    assert stale is not None and stale.stale and stale.columns["approver_email"] == {"pii"}
    now[0] = 901
    with pytest.raises(SourceUnavailable, match="staleness bound"):
        src.tags(T)


def test_down_with_nothing_cached_fails_closed() -> None:
    rec = Recorded("iceberg-rest-fixture", "01-created")
    rec.down = True
    with pytest.raises(SourceUnavailable, match="nothing is cached"):
        source(rec).tags(T)


def test_only_answers_for_its_namespaces() -> None:
    rec = Recorded("iceberg-rest-fixture", "01-created")
    src = source(rec, namespaces=("hr",))
    assert src.tags(T) is None
    assert rec.calls == []


def test_custom_property_names() -> None:
    with FakeIcebergCatalog() as cat:
        admin = IcebergRestAdmin(cat.uri)
        admin.create_namespace("finance.gl")
        admin.create_table(T, {"a": "string"}, {"classification": "finance"})
        admin.set_properties(T, {"a.tags": "pii"})
        settings = CatalogSource(
            uri=cat.uri, tag_property="classification", column_property="{column}.tags"
        )
        obs = IcebergRestTagSource("x", settings).tags(T)
        assert obs is not None and obs.tags == {"finance"} and obs.columns["a"] == {"pii"}


def test_fake_catalog_matches_the_recorded_shape() -> None:
    real = json.loads((RECORDED / "iceberg-rest-fixture" / "02-column-tagged.json").read_text())
    with FakeIcebergCatalog() as cat:
        admin = IcebergRestAdmin(cat.uri)
        admin.create_namespace("finance.gl")
        admin.create_table(
            T,
            {
                "entry_id": "string",
                "amount": "decimal(18,2)",
                "region": "string",
                "approver_email": "string",
            },
            {"trellis.tags": "finance"},
        )
        fake = admin.tag_column(T, "approver_email", "pii")
    assert set(fake) == set(real["body"])
    assert set(fake["metadata"]) == set(real["body"]["metadata"]) - {"created-at"}
    assert fake["metadata"]["properties"] == real["body"]["metadata"]["properties"]


LIVE = os.environ.get("TRELLISD_TEST_ICEBERG")


@pytest.mark.skipif(not LIVE, reason="set TRELLISD_TEST_ICEBERG to a running Iceberg REST catalog")
def test_live_catalog_round_trip() -> None:
    assert LIVE
    admin = IcebergRestAdmin(LIVE)
    live_table = "trellis_test.live.tags"
    admin.drop_table(live_table)
    admin.create_namespace("trellis_test.live")
    admin.create_table(live_table, {"a": "string", "b": "string"}, {"trellis.tags": "finance"})
    admin.tag_column(live_table, "b", "pii")
    obs = IcebergRestTagSource("live", CatalogSource(uri=LIVE)).tags(live_table)
    assert obs is not None and obs.tags == {"finance"} and obs.columns["b"] == {"pii"}
    admin.drop_table(live_table)
