"""M3's demo, end to end against the in-process Iceberg REST catalog, and its CLI commands."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from trellisd.cli import _ledger, main, run_catalog_says_pii
from trellisd.engine import Decision
from trellisd.fake_iceberg import FakeIcebergCatalog
from trellisd.trace import replay, trace

from conftest import ROOT

LAKEHOUSE = ROOT / "examples" / "lakehouse"
FIXTURES = Path(__file__).parent / "fixtures" / "odcs"


def run(*args: str) -> tuple[int, str]:
    result = CliRunner().invoke(main, list(args), catch_exceptions=False)
    return result.exit_code, result.output


@pytest.fixture(scope="module")
def demo(tmp_path_factory: pytest.TempPathFactory) -> tuple[list[Decision], str]:
    db = f"sqlite:///{tmp_path_factory.mktemp('demo')}/demo.db"
    with FakeIcebergCatalog() as cat:
        decisions = run_catalog_says_pii(cat.uri, db, go_down=cat.down)
    return decisions, db


def test_the_demo_tells_its_story(demo: tuple[list[Decision], str]) -> None:
    d, _ = demo
    assert len(d) == 7
    first, masked, drift, restricted, back, stale, down = d
    assert first.allowed and first.masked == {} and first.row_filter == "region = 'emea'"
    assert masked.allowed and set(masked.masked) == {"approver_email"}
    assert "catalog lakehouse" in masked.masked["approver_email"]
    assert drift.allowed and drift.masked["notes"].startswith("drift:")
    assert not restricted.allowed and restricted.denied_by == ("ceiling",)
    assert "restricted from catalog lakehouse" in restricted.reason
    assert back.allowed
    assert stale.allowed and stale.stale and "approver_email" in stale.masked
    assert not down.allowed and down.denied_by == ("catalog",)
    assert "pip_unavailable" in down.reason
    assert all(x.contract == "urn:contract:finance.gl" for x in d[:-1])
    assert all(x.contract_version and x.contract_version.startswith("v3@") for x in d[:-1])


def test_the_row_rule_and_mask_apply_to_rows(demo: tuple[list[Decision], str]) -> None:
    masked = demo[0][1]
    rows = [
        {"entry_id": "a", "region": "emea", "approver_email": "x@y"},
        {"entry_id": "b", "region": "amer", "approver_email": "z@y"},
    ]
    assert masked.enforce(rows) == [{"entry_id": "a", "region": "emea", "approver_email": "***"}]


def test_drift_is_logged_once_for_the_owner(demo: tuple[list[Decision], str]) -> None:
    led = _ledger(demo[1])
    try:
        drift = led.query(kind="catalog.drift")
        assert len(drift) == 1
        assert drift[0].body["owner"] == "finance-owner@example.com"
        assert drift[0].body["column"] == "notes"
        assert led.verify().ok
    finally:
        led.db.close()


def test_trace_names_the_tag_sources_and_replay_reproduces(
    demo: tuple[list[Decision], str],
) -> None:
    from trellisd import load_config
    from trellisd.catalog import Resolver
    from trellisd.engine import Engine

    decisions, db = demo
    led = _ledger(db)
    try:
        for d in decisions[:-1]:
            assert d.event_id
            t = trace(led, d.event_id)
            assert t.table is not None
            assert t.table.contract == "urn:contract:finance.gl"
            # Replayed against the config and the catalog answer it recorded, it decides the same.
            today = Engine(load_config(LAKEHOUSE), Resolver.from_config(load_config(LAKEHOUSE)))
            r = replay(led, today, d.event_id)
            assert r.reproduces, (d.reason, r.at_recorded_version)
        masked = trace(led, decisions[1].event_id or "")
        assert masked.table is not None
        srcs = masked.table.sources_of("approver_email", "pii")
        assert [s.source for s in srcs] == ["catalog lakehouse"]
    finally:
        led.db.close()


def test_demo_command_runs_with_its_own_catalog() -> None:
    code, out = run("demo", "catalog-says-pii")
    assert code == 0, out
    assert "masked approver_email" in out
    assert "Where its tags came from" in out
    assert "drift" in out
    assert "pip_unavailable" in out
    assert "chain verified" in out


def test_contracts_list() -> None:
    code, out = run("contracts", "list", "--config", str(LAKEHOUSE))
    assert code == 0, out
    assert "urn:contract:finance.gl" in out
    assert "urn:odcs:treasury-cash-positions" in out
    assert "finance.gl.journal_entries" in out


def test_contracts_import_odcs_prints_the_trellis_form() -> None:
    import yaml

    code, out = run("contracts", "import-odcs", str(FIXTURES / "journal.odcs.yaml"))
    assert code == 0, out
    first = next(d for d in yaml.safe_load_all(out) if isinstance(d, dict))
    assert first["contract"] == "urn:contract:finance.gl"
    assert first["owner"] == "finance-owner@example.com"
    assert first["tags"] == ["finance", "internal"]
    assert "ignored (not about access): slaProperties, status" in out


def test_contracts_import_odcs_refuses_nested() -> None:
    result = CliRunner().invoke(
        main, ["contracts", "import-odcs", str(FIXTURES / "nested.odcs.yaml")]
    )
    assert result.exit_code != 0
    assert "nested" in result.output


def test_catalog_tags_reads_a_live_catalog(tmp_path: Path) -> None:
    import shutil

    from trellisd.iceberg import IcebergRestAdmin

    with FakeIcebergCatalog() as cat:
        conf = tmp_path / "lakehouse"
        shutil.copytree(LAKEHOUSE, conf)
        text = (conf / "catalogs.yaml").read_text()
        (conf / "catalogs.yaml").write_text(text.replace("http://localhost:8181", cat.uri))
        admin = IcebergRestAdmin(cat.uri)
        admin.create_namespace("finance.gl")
        admin.create_table(
            "finance.gl.journal_entries",
            {"entry_id": "string", "approver_email": "string"},
            {"trellis.tags": "finance"},
        )
        admin.tag_column("finance.gl.journal_entries", "approver_email", "pii")
        code, out = run("catalog", "tags", "finance.gl.journal_entries", "--config", str(conf))
    assert code == 0, out
    assert "approver_email: pii (catalog lakehouse" in out
    assert "contract urn:contract:finance.gl" in out


def test_catalog_tags_fails_closed_when_the_catalog_is_down(tmp_path: Path) -> None:
    import shutil

    conf = tmp_path / "lakehouse"
    shutil.copytree(LAKEHOUSE, conf)
    text = (conf / "catalogs.yaml").read_text()
    (conf / "catalogs.yaml").write_text(text.replace("http://localhost:8181", "http://127.0.0.1:9"))
    result = CliRunner().invoke(
        main, ["catalog", "tags", "finance.gl.journal_entries", "--config", str(conf)]
    )
    assert result.exit_code != 0
    assert "lakehouse" in result.output
