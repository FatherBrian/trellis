"""M5: Reef, Trellis enforced at the door of MCP servers."""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

import anyio
import jwt
import pytest
from click.testing import CliRunner
from mcp import types
from mcp.shared.exceptions import MCPError

from reef.agent import AgentClient
from reef.cli import main
from reef.config import ReefConfig, ReefConfigError, ServerSpec, ToolSpec, load_reef_config
from reef.demo import run_the_door
from reef.gateway import Reef, enforce
from reef.relay import relayed
from reef.stack import Stack, examples, open_stack
from trellisd.config import Contract, ContractAccess, load_config
from trellisd.db import Database
from trellisd.engine import MASK, Decision
from trellisd.ledger import LedgerUnavailable
from trellisd.trace import trace

ALL = ["hr_headcount", "hr_payroll", "ledger_journal_entries", "ledger_post_adjustment"]


@pytest.fixture
def stack() -> Iterator[Stack]:
    with open_stack() as s:
        yield s


def names(tools: list[types.Tool]) -> list[str]:
    return sorted(t.name for t in tools)


# -- the tool list ---------------------------------------------------------------------------


def test_two_grants_see_different_tools_from_the_same_servers(stack: Stack) -> None:
    report = AgentClient(stack.url, stack.report_bot.token).list_tools()
    people = AgentClient(stack.url, stack.people_bot.token).list_tools()
    assert names(report) == ["ledger_journal_entries"]
    assert names(people) == ["hr_headcount", "hr_payroll"]
    journal = report[0]
    assert "region = 'emea'" in (journal.description or "")
    assert "approver_email comes back as ***" in (journal.description or "")
    assert journal.input_schema == {"type": "object", "properties": {}}


def test_each_list_is_one_ledger_event_naming_what_was_hidden(stack: Stack) -> None:
    AgentClient(stack.url, stack.report_bot.token).list_tools()
    (ev,) = stack.trellis.ledger.query(kind="tools.listed")
    assert ev.agent == "report-bot"
    assert ev.subject == "ana@example.com"
    assert ev.grant_id == stack.report_bot.grant.id
    assert ev.body["shown"] == ["ledger_journal_entries"]
    hidden = {h["tool"]: h["denied_by"] for h in ev.body["hidden"]}
    assert hidden["hr_payroll"] == ["task"]
    assert "person" in hidden["ledger_post_adjustment"]  # a write: no role of Ana's allows it
    assert ev.body["receipt"] == stack.report_bot.grant.receipt


def test_a_tool_dropped_from_its_contract_leaves_the_next_list(stack: Stack) -> None:
    people = AgentClient(stack.url, stack.people_bot.token)
    assert "hr_payroll" in names(people.list_tools())
    cfg = stack.trellis.config
    payroll = cfg.contracts["urn:contract:hr.payroll"]
    dropped = payroll.model_copy(update={"bindings": ("mcp://hr/payroll-archive",)})
    stack.trellis.reload(
        cfg.model_copy(update={"contracts": {**cfg.contracts, payroll.contract: dropped}})
    )
    assert names(people.list_tools()) == ["hr_headcount"]
    r = people.call("hr_payroll")
    assert r.is_error
    assert r.structured_content["denied_by"] == ["catalog"]  # type: ignore[index]
    assert stack.hr.calls == []


def test_a_tool_the_config_doesnt_map_is_never_shown(stack: Stack) -> None:
    rc = stack.reef.config
    hr = rc.servers["hr"].model_copy(update={"tools": {"headcount": ToolSpec(action="read")}})
    stack.reef.config = rc.model_copy(update={"servers": {**rc.servers, "hr": hr}})
    stack.reef.routes.pop("hr_payroll")
    assert names(AgentClient(stack.url, stack.people_bot.token).list_tools()) == ["hr_headcount"]


def test_listing_needs_a_live_grant(stack: Stack) -> None:
    with pytest.raises(MCPError, match="grant token"):
        AgentClient(stack.url, "").list_tools()
    with pytest.raises(MCPError, match="unknown token"):
        AgentClient(stack.url, "not-a-grant").list_tools()
    stack.trellis.revoke(stack.report_bot.grant.id, by="ana@example.com")
    with pytest.raises(MCPError, match="revoked"):
        AgentClient(stack.url, stack.report_bot.token).list_tools()


# -- a call ----------------------------------------------------------------------------------


def test_an_allowed_call_is_decided_recorded_forwarded_and_enforced(stack: Stack) -> None:
    r = AgentClient(stack.url, stack.report_bot.token).call("ledger_journal_entries")
    assert not r.is_error
    rows = r.structured_content["rows"]  # type: ignore[index]
    assert [row["entry_id"] for row in rows] == ["JE-1001", "JE-1003"]
    assert {row["approver_email"] for row in rows} == {MASK}
    (call,) = stack.ledger.calls
    assert call.caller == "ana@example.com"
    assert call.meta["trellis"]["obligations"]["row_filter"] == "region = 'emea'"
    # (The MCP client may list tools before it calls; that's a tools.listed event.)
    kinds = [
        (e.kind, e.body.get("stage"))
        for e in stack.trellis.ledger.query()
        if e.kind not in ("grant.issued", "tools.listed")
    ]
    assert kinds == [
        ("decision", None),
        ("credential.exchanged", None),
        ("enforcement", "forward"),
        ("enforcement", "result"),
    ]
    result = stack.trellis.ledger.query(kind="enforcement")[-1].body
    assert (result["rows_in"], result["rows_out"], result["masked"]) == (4, 2, ["approver_email"])


def test_a_denied_call_reaches_nothing_downstream(stack: Stack) -> None:
    r = AgentClient(stack.url, stack.report_bot.token).call("hr_payroll")
    assert r.is_error
    out: dict[str, Any] = r.structured_content  # type: ignore[assignment]
    assert out["denied_by"] == ["task"]
    assert out["request_access"]["ask"] == "ana@example.com"
    assert out["request_access"]["contract_owner"] == "hr-lead@example.com"
    assert stack.hr.calls == [] and stack.ledger.calls == []
    decision = stack.trellis.ledger.get(out["event_id"])
    assert decision is not None and decision.body["allowed"] is False
    (blocked,) = stack.trellis.ledger.query(kind="enforcement")
    assert blocked.body["stage"] == "blocked" and blocked.body["decision"] == out["event_id"]
    assert blocked.seq > decision.seq


@pytest.mark.parametrize(
    ("tool", "first", "ask"),
    [
        ("ledger_post_adjustment", "person", "finance-owner@example.com"),
        ("hr_payroll", "task", "ana@example.com"),
        ("no_such_tool", "catalog", None),
    ],
)
def test_a_deny_names_the_check_and_who_to_ask(
    stack: Stack, tool: str, first: str, ask: str | None
) -> None:
    r = AgentClient(stack.url, stack.report_bot.token).call(tool)
    out: dict[str, Any] = r.structured_content  # type: ignore[assignment]
    assert out["denied_by"][0] == first
    assert out["request_access"]["ask"] == ask
    assert r.content[0].text.startswith("Denied at the door")  # type: ignore[union-attr]


def test_a_lowered_ceiling_closes_the_door_at_once(stack: Stack) -> None:
    report = AgentClient(stack.url, stack.report_bot.token)
    assert not report.call("ledger_journal_entries").is_error
    cfg = stack.trellis.config
    bot = cfg.agents["report-bot"]
    lowered = bot.model_copy(
        update={"ceiling": bot.ceiling.model_copy(update={"tags": frozenset({"hr", "pii"})})}
    )
    stack.trellis.reload(cfg.model_copy(update={"agents": {**cfg.agents, "report-bot": lowered}}))
    assert report.list_tools() == []
    r = report.call("ledger_journal_entries")
    out: dict[str, Any] = r.structured_content  # type: ignore[assignment]
    assert out["denied_by"] == ["ceiling"]
    assert out["request_access"]["ask"] == "dana@example.com"  # who sets report-bot's ceiling
    assert len(stack.ledger.calls) == 1


def test_a_call_without_a_grant_is_denied_and_recorded(stack: Stack) -> None:
    r = AgentClient(stack.url, "").call("ledger_journal_entries")
    assert r.is_error
    assert "no grant token" in r.content[0].text  # type: ignore[union-attr]
    assert stack.ledger.calls == []
    assert stack.trellis.ledger.query(kind="decision")[-1].body["allowed"] is False


def test_no_forward_unless_the_enforcement_event_is_written(
    stack: Stack, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = stack.trellis.ledger.append

    def append(kind: str, **kw: Any) -> Any:
        if kind == "enforcement":
            raise LedgerUnavailable("ledger write failed: disk full")
        return real(kind, **kw)

    monkeypatch.setattr(stack.trellis.ledger, "append", append)
    r = AgentClient(stack.url, stack.report_bot.token).call("ledger_journal_entries")
    assert r.is_error
    assert "forwarded nothing" in r.content[0].text  # type: ignore[union-attr]
    assert stack.ledger.calls == []


def test_a_result_that_cant_be_recorded_is_held_back(
    stack: Stack, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = stack.trellis.ledger.append

    def append(kind: str, **kw: Any) -> Any:
        if kind == "enforcement" and (kw.get("body") or {}).get("stage") == "result":
            raise LedgerUnavailable("ledger write failed: disk full")
        return real(kind, **kw)

    monkeypatch.setattr(stack.trellis.ledger, "append", append)
    r = AgentClient(stack.url, stack.report_bot.token).call("ledger_journal_entries")
    assert r.is_error
    assert "holds it back" in r.content[0].text  # type: ignore[union-attr]
    assert "JE-1001" not in str(r.model_dump())


def test_trace_shows_what_the_door_did(stack: Stack) -> None:
    AgentClient(stack.url, stack.report_bot.token).call("ledger_journal_entries")
    decision = stack.trellis.ledger.query(kind="decision")[-1]
    t = trace(stack.trellis.ledger, decision.event_id)
    assert [e.body["stage"] for e in t.enforcement] == ["forward", "result"]


# -- the ledger going away -------------------------------------------------------------------


def test_a_stopped_ledger_denies_every_call(stack: Stack) -> None:
    report = AgentClient(stack.url, stack.report_bot.token)
    people = AgentClient(stack.url, stack.people_bot.token)
    stack.trellis.db.close()
    for client in (report, people):
        with pytest.raises(MCPError, match="shows no tools"):
            client.list_tools()
    for client, tool in ((report, "ledger_journal_entries"), (people, "hr_payroll")):
        r = client.call(tool)
        assert r.is_error
        assert "won't act unrecorded" in r.content[0].text  # type: ignore[union-attr]
    assert stack.ledger.calls == [] and stack.hr.calls == []


@pytest.mark.postgres
@pytest.mark.skipif(
    not os.environ.get("TRELLISD_TEST_POSTGRES"),
    reason="set TRELLISD_TEST_POSTGRES to run the Postgres tests",
)
def test_postgres_going_away_denies_and_coming_back_recovers() -> None:
    relay, url = relayed(os.environ["TRELLISD_TEST_POSTGRES"])
    try:
        with open_stack(Database(url)) as s:
            report = AgentClient(s.url, s.report_bot.token)
            assert not report.call("ledger_journal_entries").is_error
            relay.cut()
            for _ in range(2):  # the dropped connection, then a refused reconnect
                r = report.call("ledger_journal_entries")
                assert r.is_error and "won't act unrecorded" in r.content[0].text  # type: ignore[union-attr]
            assert len(s.ledger.calls) == 1
            relay.resume()
            assert not report.call("ledger_journal_entries").is_error
            assert len(s.ledger.calls) == 2
            assert s.trellis.ledger.verify().ok
    finally:
        relay.close()


# -- credential modes ------------------------------------------------------------------------


class Recorder:
    def __init__(self) -> None:
        self.credentials: list[str | None] = []

    async def list_tools(self, credential: str | None) -> list[types.Tool]:
        return [types.Tool(name="open", input_schema={"type": "object"})]

    async def call_tool(
        self, name: str, arguments: dict[str, Any], credential: str | None, meta: dict[str, Any]
    ) -> types.CallToolResult:
        self.credentials.append(credential)
        return types.CallToolResult(content=[], structured_content={"ok": True})


def test_each_credential_mode_sends_the_right_token(stack: Stack) -> None:
    cfg = stack.trellis.config
    contracts = dict(cfg.contracts)
    for server in ("obo", "agent", "brokered", "none"):
        urn = f"urn:contract:support.{server}"
        contracts[urn] = Contract(
            contract=urn,
            kind="mcp_tool",
            bindings=(f"mcp://{server}/open",),
            owner="support@example.com",
            tags=frozenset({"finance", "internal"}),
            access={"analysts": ContractAccess(who=("group:finance-analysts",))},
        )
    stack.trellis.reload(cfg.model_copy(update={"contracts": contracts}))
    spec = {"open": ToolSpec(action="read")}
    rc = ReefConfig(
        servers={
            "obo": ServerSpec(url="x", credential="obo", audience="tickets-mcp", tools=spec),
            "agent": ServerSpec(url="x", credential="agent", audience="tickets-mcp", tools=spec),
            "brokered": ServerSpec(
                url="x", credential="brokered", credential_env="SVC", tools=spec
            ),
            "none": ServerSpec(url="x", credential="none", tools=spec),
        }
    )
    rec = {name: Recorder() for name in rc.servers}
    reef = Reef(
        stack.trellis, rc, downstream=lambda name, _url: rec[name], environ={"SVC": "svc-secret"}
    )
    token = stack.report_bot.token

    async def calls() -> None:
        for server in rc.servers:
            r = await reef.call_tool(token, f"{server}_open")
            assert not r.is_error, (server, r.content)

    anyio.run(calls)

    def claims(t: str | None) -> dict[str, Any]:
        assert t is not None
        out: dict[str, Any] = jwt.decode(
            t, stack.idp.key.public_key(), algorithms=["RS256"], audience="tickets-mcp"
        )
        return out

    obo = claims(rec["obo"].credentials[0])
    assert obo["email"] == "ana@example.com"  # the person, not the agent
    agent = claims(rec["agent"].credentials[0])
    assert agent["sub"] == "sa-report-bot" and "email" not in agent  # the agent itself
    assert rec["brokered"].credentials == ["svc-secret"]
    assert rec["none"].credentials == [None]
    modes = [e.body["mode"] for e in stack.trellis.ledger.query(kind="credential.exchanged")]
    assert modes == ["obo", "agent"]
    assert "svc-secret" not in str([e.body for e in stack.trellis.ledger.query()])


def test_a_missing_brokered_credential_forwards_nothing(stack: Stack) -> None:
    stack.reef.environ = {}
    r = AgentClient(stack.url, stack.people_bot.token).call("hr_headcount")
    assert r.is_error and "REEF_HR_TOKEN isn't set" in r.content[0].text  # type: ignore[union-attr]
    assert stack.hr.calls == []
    assert stack.trellis.ledger.query(kind="enforcement")[-1].body["stage"] == "refused"


# -- obligations on results ------------------------------------------------------------------


def decision(**kw: Any) -> Decision:
    return Decision(allowed=True, reason="ok", action="read", resource="r", **kw)


ROWS = [{"id": 1, "region": "emea", "email": "a@x"}, {"id": 2, "region": "amer", "email": "b@x"}]


def result(structured: Any = None, text: str | None = None) -> types.CallToolResult:
    content = [types.TextContent(type="text", text=text)] if text is not None else []
    return types.CallToolResult(content=content, structured_content=structured)


@pytest.mark.parametrize(
    "given",
    [
        result({"rows": ROWS}),
        result(
            None,
            text='[{"id": 1, "region": "emea", "email": "a@x"},'
            ' {"id": 2, "region": "amer", "email": "b@x"}]',
        ),
    ],
)
def test_enforce_masks_then_filters(given: types.CallToolResult) -> None:
    d = decision(masked={"email": "pii"}, row_filter="region = 'emea'")
    out, summary = enforce(d, given)
    rows = out.structured_content["rows"]  # type: ignore[index]
    assert rows == [{"id": 1, "region": "emea", "email": MASK}]
    assert (summary["rows_in"], summary["rows_out"]) == (4 // 2, 1)


def test_enforce_fails_closed_on_a_shape_it_cant_read() -> None:
    d = decision(row_filter="region = 'emea'")
    for given in (result(None, text="some prose"), result({"count": 3}), result(["a", "b"])):
        out, summary = enforce(d, given)
        assert out.is_error and summary["outcome"] == "withheld"


def test_enforce_fails_closed_on_a_filter_outside_the_dialect() -> None:
    out, summary = enforce(decision(row_filter="region LIKE 'e%'"), result({"rows": ROWS}))
    assert out.is_error and summary["outcome"] == "withheld"


def test_enforce_masks_a_single_record() -> None:
    out, _ = enforce(decision(masked={"email": "pii"}), result({"id": 1, "email": "a@x"}))
    assert out.structured_content == {"id": 1, "email": MASK}


def test_enforce_passes_through_without_obligations() -> None:
    given = result(None, text="anything")
    assert enforce(decision(), given)[0] is given


# -- config, CLI and the demo ----------------------------------------------------------------


def test_the_example_config_loads() -> None:
    rc = load_reef_config(examples() / "reef.yaml")
    assert rc.servers["ledger"].credential == "obo"
    assert rc.resource("ledger", "journal_entries") == "mcp://ledger/journal_entries"
    load_config(examples() / "trellis")


@pytest.mark.parametrize(
    ("server", "why"),
    [
        ({"url": "x", "credential": "obo"}, "needs an audience"),
        ({"url": "x", "credential": "brokered"}, "needs credential_env"),
        ({"url": "x", "credential": "none", "tools": {"t": {"action": "delete"}}}, "isn't one of"),
        ({"url": "x", "credential": "magic"}, "credential"),
    ],
)
def test_config_errors(tmp_path: Any, server: dict[str, Any], why: str) -> None:
    import yaml

    path = tmp_path / "reef.yaml"
    path.write_text(yaml.safe_dump({"reef": {"servers": {"s": server}}}))
    with pytest.raises(ReefConfigError, match=why):
        load_reef_config(path)


def test_two_tools_cant_share_a_name() -> None:
    with pytest.raises(ValueError, match="both become"):
        ReefConfig(
            servers={
                "a": ServerSpec(url="x", credential="none", tools={"b_c": ToolSpec()}),
                "a_b": ServerSpec(url="x", credential="none", tools={"c": ToolSpec()}),
            }
        )


def test_the_demo_runs() -> None:
    out = run_the_door()
    assert out.tools == {
        "report-bot": ["ledger_journal_entries"],
        "people-bot": ["hr_headcount", "hr_payroll"],
    }
    assert out.first.allowed and out.first.row_filter
    assert not out.denied.allowed and out.denied.denied_by == ("task",)
    assert out.hr_calls_after == out.hr_calls_before == 0
    assert all("shows no tools" in why for why in out.down_lists)
    assert all(r.is_error for r in out.down_calls)
    assert out.recovered is None


def test_demo_command() -> None:
    res = CliRunner().invoke(main, ["demo", "the-door"], catch_exceptions=False)
    assert res.exit_code == 0, res.output
    assert "Denied at the door." in res.output
    assert "reef blocked it: nothing was forwarded to hr" in res.output
    assert "reef kept 2 of 4 rows, approver_email masked" in res.output
    assert "chain verified" in res.output
    assert "reached a server while the ledger was down: 0" in res.output


assert ALL  # the four tools the demo servers offer
