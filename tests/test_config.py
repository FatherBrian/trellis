from __future__ import annotations

from pathlib import Path

import pytest

from trellisd.config import ConfigError, json_schema, load_config

from conftest import THREE_KEYS


def test_example_loads() -> None:
    cfg = load_config(THREE_KEYS)
    assert set(cfg.agents) == {"report-bot", "inspector-bot"}
    assert cfg.agents["report-bot"].ceiling.never == {"export_controlled"}
    assert cfg.groups_of("ana@example.com") == ("finance-analysts",)
    assert cfg.catalog["hr.payroll"].tags == {"hr", "pii"}


def test_unknown_keys_are_refused(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text("agents:\n  bot:\n    owner: a\n    cieling: {}\n")
    with pytest.raises(ConfigError, match="cieling"):
        load_config(tmp_path)


def test_duplicate_rule_ids_are_refused(tmp_path: Path) -> None:
    rule = "access:\n  - id: r1\n    who: [group:g]\n"
    (tmp_path / "a.yaml").write_text(rule)
    (tmp_path / "b.yaml").write_text(rule)
    with pytest.raises(ConfigError, match="r1"):
        load_config(tmp_path)


def test_purpose_must_name_known_agents(tmp_path: Path) -> None:
    (tmp_path / "p.yaml").write_text(
        "purposes:\n  p:\n    owner: o\n    agents: [ghost]\n    trigger: {type: t, tags: [x]}\n"
    )
    with pytest.raises(ConfigError, match="ghost"):
        load_config(tmp_path)


def test_who_must_be_group_or_user(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text("access:\n  - id: r\n    who: [ana]\n")
    with pytest.raises(ConfigError, match="group: or user:"):
        load_config(tmp_path)


def test_bad_yaml_and_missing_paths(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text("people: [unclosed\n")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(tmp_path)
    with pytest.raises(ConfigError, match="no such file"):
        load_config(tmp_path / "nope")


def test_json_schema_names_the_sections() -> None:
    schema = json_schema()
    assert set(schema["properties"]) == {
        "people",
        "agents",
        "access",
        "purposes",
        "catalog",
        "catalogs",
        "levels",
        "sensitive",
        "idps",
    }
