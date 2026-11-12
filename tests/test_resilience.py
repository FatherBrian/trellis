"""Trellis with its database gone: every answer is a deny, never an exception."""

from __future__ import annotations

from trellisd import Trellis, load_config
from trellisd.db import Database

from conftest import JOURNAL, THREE_KEYS


def test_a_closed_database_denies_instead_of_raising() -> None:
    t = Trellis(load_config(THREE_KEYS), Database(":memory:"))
    issued = t.issue_grant(
        person="ana@example.com", agent="report-bot", task="Q3 close", scope={"finance"}
    )
    assert t.authorize(issued.token, "read", JOURNAL).allowed
    t.db.close()
    d = t.authorize(issued.token, "read", JOURNAL)
    assert not d.allowed
    assert "ledger" in d.denied_by
    assert "won't act unrecorded" in d.reason
    assert d.event_id is None


def test_reload_takes_effect_on_the_next_decision() -> None:
    cfg = load_config(THREE_KEYS)
    t = Trellis(cfg, Database(":memory:"))
    issued = t.issue_grant(
        person="ana@example.com", agent="report-bot", task="Q3 close", scope={"finance"}
    )
    before = t.config_version
    bot = cfg.agents["report-bot"]
    lowered = bot.model_copy(
        update={"ceiling": bot.ceiling.model_copy(update={"tags": frozenset({"hr"})})}
    )
    t.reload(cfg.model_copy(update={"agents": {**cfg.agents, "report-bot": lowered}}))
    d = t.authorize(issued.token, "read", JOURNAL)
    assert d.denied_by == ("ceiling",)
    assert t.config_version != before
    assert t.ledger.get(d.event_id or "").body["config_version"] == t.config_version  # type: ignore[union-attr]
