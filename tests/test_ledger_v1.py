"""M2: signed grant entries, checkpoints, the outbox, trace and replay."""

from __future__ import annotations

from datetime import timedelta

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from trellisd import Trellis, load_config
from trellisd.engine import Engine
from trellisd.export import MemorySink, OpenTelemetrySink, backlog, drain
from trellisd.ledger import chain_hash
from trellisd.mcp_middleware import TrellisDenied, TrellisGuard
from trellisd.trace import TraceError, grant_as_of, replay, trace

from conftest import ANA, EXPORT, INSPECTIONS, JOURNAL, NOW, PAYROLL, THREE_KEYS, TREASURY


def scenario(t: Trellis) -> dict[str, str]:
    """M1's calls plus a purpose run and a call after revocation. Returns event ids."""
    q3 = t.issue_grant(person=ANA, agent="report-bot", task="Q3 close", scope={"finance"}, now=NOW)
    ids = {}
    for name, res in (
        ("journal", JOURNAL),
        ("export", EXPORT),
        ("hr", PAYROLL),
        ("treasury", TREASURY),
    ):
        ids[name] = t.authorize(q3.token, "read", res, now=NOW).event_id or ""
    run = t.start_run(
        purpose="inspection-review",
        agent="inspector-bot",
        record="INS-1",
        started_by="qms",
        now=NOW,
    )
    ids["inspection"] = t.authorize(run.token, "read", INSPECTIONS, now=NOW).event_id or ""
    t.revoke(q3.grant.id, by=ANA, now=NOW + timedelta(minutes=5))
    ids["after_revoke"] = (
        t.authorize(q3.token, "read", JOURNAL, now=NOW + timedelta(minutes=6)).event_id or ""
    )
    ids["unknown"] = t.authorize("trellis_nope", "read", JOURNAL, now=NOW).event_id or ""
    return ids


# -- signatures and checkpoints ------------------------------------------------------------


def test_grant_entries_are_signed_and_decisions_are_not(trellis: Trellis) -> None:
    scenario(trellis)
    for ev in trellis.ledger.query():
        if ev.kind.startswith("grant."):
            assert ev.sig
            assert ev.key_id == trellis.signer.key_id
        else:
            assert not ev.sig
    assert trellis.ledger.verify().ok


def test_forged_signature_is_detected(trellis: Trellis) -> None:
    scenario(trellis)
    trellis.db.execute("UPDATE trellis_ledger SET sig = 'AAAA' WHERE seq = 1")
    v = trellis.ledger.verify()
    assert not v.ok
    assert "signature" in (v.problem or "")


def test_cut_tail_needs_a_checkpoint(trellis: Trellis) -> None:
    scenario(trellis)
    cp = trellis.ledger.checkpoint()
    assert cp.signature_ok()
    assert trellis.ledger.checkpoints() == [cp]
    trellis.db.execute("DELETE FROM trellis_ledger WHERE seq > ?", (cp.seq - 3,))
    assert trellis.ledger.verify().ok  # a shorter chain is still a valid chain...
    v = trellis.ledger.verify(cp)  # ...but not against the signed checkpoint
    assert not v.ok
    assert f"events {cp.seq - 2} to {cp.seq} are missing from the end" in (v.problem or "")


def test_edit_and_cut_tail_are_both_named(trellis: Trellis) -> None:
    ids = scenario(trellis)
    cp = trellis.ledger.checkpoint()
    hr = trellis.ledger.get(ids["hr"])
    assert hr is not None
    trellis.db.execute(
        "UPDATE trellis_ledger SET payload = replace(payload, '\"allowed\":false',"
        " '\"allowed\":true') WHERE seq = ?",
        (hr.seq,),
    )
    trellis.db.execute("DELETE FROM trellis_ledger WHERE seq > ?", (cp.seq - 2,))
    v = trellis.ledger.verify(cp)
    assert v.broken_at == hr.seq
    assert v.problems[0] == f"event {hr.seq} was changed after it was written"
    assert "missing from the end" in v.problems[1]


def test_rewritten_history_with_fresh_hashes_fails_the_checkpoint(trellis: Trellis) -> None:
    scenario(trellis)
    cp = trellis.ledger.checkpoint()
    # An attacker edits event 2 and recomputes every hash after it (chain looks valid).
    rows = trellis.db.query("SELECT seq, payload FROM trellis_ledger ORDER BY seq")
    import json

    prev = None
    for seq, payload in rows:
        data = json.loads(payload)
        if prev is not None:
            data["prev_hash"] = prev
        if int(seq) == 2:
            data["body"]["allowed"] = not data["body"]["allowed"]
        h = chain_hash(data["prev_hash"], data)
        trellis.db.execute(
            "UPDATE trellis_ledger SET payload = ?, prev_hash = ?, hash = ?, sig = '' "
            "WHERE seq = ?",
            (json.dumps(data, sort_keys=True, separators=(",", ":")), data["prev_hash"], h, seq),
        )
        prev = h
    assert trellis.ledger.verify().ok
    v = trellis.ledger.verify(cp)
    assert "history was rewritten" in (v.problem or "")


def test_a_forged_checkpoint_is_refused(trellis: Trellis) -> None:
    scenario(trellis)
    cp = trellis.ledger.checkpoint()
    forged = cp.model_copy(update={"seq": cp.seq - 1})
    assert not forged.signature_ok()
    assert "checkpoint's signature" in (trellis.ledger.verify(forged).problem or "")


# -- the outbox ----------------------------------------------------------------------------


def test_outbox_drains_in_order_at_least_once(trellis: Trellis) -> None:
    scenario(trellis)
    total = len(trellis.ledger)
    assert backlog(trellis.ledger) == total
    sink = MemorySink()
    r = drain(trellis.ledger, sink, limit=3)
    assert r.sent == 3
    assert backlog(trellis.ledger) == total - 3
    drain(trellis.ledger, sink)
    assert backlog(trellis.ledger) == 0
    assert len(sink.events) == total


def test_a_sink_outage_never_blocks_a_decision(trellis: Trellis) -> None:
    class Down:
        name = "down"

        def send(self, event: object) -> None:
            raise ConnectionError("collector unreachable")

    q3 = trellis.issue_grant(person=ANA, agent="report-bot", task="t", scope={"finance"}, now=NOW)
    r = drain(trellis.ledger, Down())
    assert r.failed == 1
    assert "unreachable" in (r.error or "")
    d = trellis.authorize(q3.token, "read", JOURNAL, now=NOW)
    assert d.allowed
    assert backlog(trellis.ledger) == 2
    rows = trellis.db.query("SELECT attempts, last_error FROM trellis_outbox ORDER BY seq")
    assert rows[0][0] == 1
    assert "unreachable" in rows[0][1]


def test_opentelemetry_sink_is_idempotent(trellis: Trellis) -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    ids = scenario(trellis)
    sink = OpenTelemetrySink(provider)
    drain(trellis.ledger, sink)
    # At least once: re-sending an event (say, after a crash before it was marked) is a no-op.
    ev = trellis.ledger.get(ids["hr"])
    assert ev is not None
    sink.send(ev)
    spans = exporter.get_finished_spans()
    assert len(spans) == len(trellis.ledger)
    hr = next(s for s in spans if s.attributes and s.attributes["trellis.event_id"] == ids["hr"])
    assert hr.name == "trellis.decision"
    assert hr.attributes is not None
    assert hr.attributes["trellis.allowed"] is False
    assert hr.attributes["trellis.check.task"] is False
    assert hr.attributes["trellis.check.person"] is True
    assert list(hr.attributes["trellis.denied_by"]) == ["task"]  # type: ignore[arg-type]


def test_a_failed_write_means_the_tool_never_runs(
    trellis: Trellis, monkeypatch: pytest.MonkeyPatch
) -> None:
    from trellisd.ledger import LedgerUnavailable

    q3 = trellis.issue_grant(person=ANA, agent="report-bot", task="t", scope={"finance"})
    guard = TrellisGuard(trellis, token_provider=lambda: q3.token)
    ran = False

    @guard.tool(action="read", resource=JOURNAL)
    def tool() -> list[dict[str, str]]:
        nonlocal ran
        ran = True
        return []

    def broken(*_a: object, **_k: object) -> None:
        raise LedgerUnavailable("ledger write failed: database is down")

    monkeypatch.setattr(trellis.ledger, "append", broken)
    with pytest.raises(TrellisDenied, match="won't act unrecorded"):
        tool()
    assert not ran


# -- trace and replay ----------------------------------------------------------------------


def test_every_decision_links_to_an_existing_grant_entry(trellis: Trellis) -> None:
    scenario(trellis)
    for ev in trellis.ledger.query(kind="decision"):
        if not ev.grant_id:
            assert ev.body["denied_by"] == ["grant"]
            continue
        issued = trellis.ledger.by_hash(ev.body["receipt"])
        assert issued is not None
        assert issued.kind == "grant.issued"
        assert issued.grant_id == ev.grant_id
        assert issued.seq < ev.seq


def test_trace_walks_a_deny_to_who_allowed_it(trellis: Trellis) -> None:
    ids = scenario(trellis)
    t = trace(trellis.ledger, ids["hr"])
    assert t.grant is not None
    assert t.grant.grant.issued_by == ANA
    assert t.grant.signature_ok
    assert t.grant.revoked is None  # revoked later, not before this call
    task = t.decision.check("task")
    assert task is not None
    assert not task.allowed
    assert task.considered == (f"grant.{t.grant.grant.id}",)
    assert t.warnings == []

    later = trace(trellis.ledger, ids["after_revoke"])
    assert later.grant is not None
    assert later.grant.revoked is not None


def test_trace_flags_a_receipt_that_matches_nothing(trellis: Trellis) -> None:
    ids = scenario(trellis)
    ev = trellis.ledger.get(ids["journal"])
    assert ev is not None
    trellis.db.execute(
        "UPDATE trellis_ledger SET payload = replace(payload, ?, ?) WHERE seq = ?",
        (ev.body["receipt"], "0" * 64, ev.seq),
    )
    assert "doesn't match the grant entry" in trace(trellis.ledger, ids["journal"]).warnings[0]


def test_trace_errors(trellis: Trellis) -> None:
    scenario(trellis)
    first = trellis.ledger.query()[0]
    with pytest.raises(TraceError, match="not a decision"):
        trace(trellis.ledger, first.event_id)
    with pytest.raises(TraceError, match="no event"):
        trace(trellis.ledger, "ev_missing")
    with pytest.raises(TraceError, match=r"no grant\.issued"):
        grant_as_of(trellis.ledger, "g-missing")


@pytest.mark.parametrize(
    "name", ["journal", "export", "hr", "treasury", "inspection", "after_revoke"]
)
def test_replay_reproduces_the_original_decision(trellis: Trellis, name: str) -> None:
    ids = scenario(trellis)
    r = replay(trellis.ledger, trellis.engine, ids[name])
    assert r.reproduces, r.at_recorded_version
    assert r.changed_today == []


def test_replay_shows_what_todays_policy_would_change(trellis: Trellis) -> None:
    ids = scenario(trellis)
    cfg = load_config(THREE_KEYS)
    stricter = cfg.model_copy(update={"access": tuple(r for r in cfg.access if r.id != "ana-hr")})
    r = replay(trellis.ledger, Engine(stricter), ids["hr"])
    assert r.reproduces  # the recorded version still gives the recorded answer
    assert "ana@example.com's access: yes then, no now" in r.changed_today


def test_replay_needs_a_grant(trellis: Trellis) -> None:
    ids = scenario(trellis)
    with pytest.raises(TraceError, match="no grant"):
        replay(trellis.ledger, trellis.engine, ids["unknown"])
