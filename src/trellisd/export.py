"""The outbox: every ledger event is queued in the same transaction that writes it, and a
drainer sends queued events to a sink outside the decision path.

Delivery is at least once, so sinks are idempotent on the event id. A sink outage leaves
events queued (with the error and an attempt count) and never blocks a decision.

The one sink in v0.1 is OpenTelemetry: one span per event, named ``trellis.<kind>``, with
the decision's answers as attributes, so the ledger shows up in whatever tracing backend
you already run.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from trellisd.grants import utcnow
from trellisd.ledger import Ledger, LedgerEvent


class Sink(Protocol):
    name: str

    def send(self, event: LedgerEvent) -> None: ...


def event_attributes(event: LedgerEvent) -> dict[str, Any]:
    """OpenTelemetry attributes for one event (strings, bools and lists of strings only)."""
    b = event.body
    attrs: dict[str, Any] = {
        "trellis.event_id": event.event_id,
        "trellis.seq": event.seq,
        "trellis.kind": event.kind,
        "trellis.hash": event.hash,
        "trellis.agent": event.agent,
        "trellis.subject": event.subject,
        "trellis.grant_id": event.grant_id,
    }
    if event.kind == "decision":
        attrs.update(
            {
                "trellis.allowed": bool(b.get("allowed")),
                "trellis.action": str(b.get("action", "")),
                "trellis.resource": str(b.get("resource", "")),
                "trellis.denied_by": [str(x) for x in b.get("denied_by", [])],
                "trellis.policy_ids": [str(x) for x in b.get("policy_ids", [])],
                "trellis.masked": sorted(str(k) for k in (b.get("masked") or {})),
                "trellis.receipt": str(b.get("receipt") or ""),
            }
        )
        for check in b.get("checks", []):
            attrs[f"trellis.check.{check['name']}"] = bool(check["allowed"])
    return attrs


class OpenTelemetrySink:
    """One span per ledger event. Skips events it has already sent (idempotent)."""

    name = "opentelemetry"

    def __init__(self, tracer_provider: Any = None) -> None:
        from opentelemetry import trace

        self._tracer = trace.get_tracer("trellisd", tracer_provider=tracer_provider)
        self._sent: set[str] = set()

    def send(self, event: LedgerEvent) -> None:
        if event.event_id in self._sent:
            return
        start = int(event.ts.timestamp() * 1e9)
        span = self._tracer.start_span(
            f"trellis.{event.kind}", start_time=start, attributes=event_attributes(event)
        )
        span.end(end_time=start)
        self._sent.add(event.event_id)


class MemorySink:
    """For tests and demos."""

    name = "memory"

    def __init__(self) -> None:
        self.events: dict[str, LedgerEvent] = {}

    def send(self, event: LedgerEvent) -> None:
        self.events.setdefault(event.event_id, event)


class DrainResult:
    def __init__(self) -> None:
        self.sent = 0
        self.failed = 0
        self.error: str | None = None

    def __repr__(self) -> str:
        return f"DrainResult(sent={self.sent}, failed={self.failed}, error={self.error!r})"


def pending(ledger: Ledger, limit: int = 500) -> list[tuple[str, int]]:
    rows = ledger.db.query(
        "SELECT event_id, attempts FROM trellis_outbox WHERE delivered_at IS NULL"
        " ORDER BY seq LIMIT ?",
        (limit,),
    )
    return [(str(r[0]), int(r[1])) for r in rows]


def drain(ledger: Ledger, sink: Sink, limit: int = 500, now: datetime | None = None) -> DrainResult:
    """Send queued events in ledger order. Stops at the first failure and keeps the rest."""
    result = DrainResult()
    for event_id, _attempts in pending(ledger, limit):
        event = ledger.get(event_id)
        if event is None:  # deleted after it was queued: leave it queued and say so
            ledger.db.execute(
                "UPDATE trellis_outbox SET last_error = ? WHERE event_id = ?",
                ("the event is no longer in the ledger", event_id),
            )
            continue
        try:
            sink.send(event)
        except Exception as exc:
            ledger.db.execute(
                "UPDATE trellis_outbox SET attempts = attempts + 1, last_error = ?"
                " WHERE event_id = ?",
                (f"{sink.name}: {exc}"[:500], event_id),
            )
            result.failed += 1
            result.error = str(exc)
            break
        ledger.db.execute(
            "UPDATE trellis_outbox SET attempts = attempts + 1, delivered_at = ?,"
            " last_error = NULL WHERE event_id = ?",
            ((now or utcnow()).isoformat(), event_id),
        )
        result.sent += 1
    return result


def backlog(ledger: Ledger) -> int:
    return int(
        ledger.db.query("SELECT COUNT(*) FROM trellis_outbox WHERE delivered_at IS NULL")[0][0]
    )


__all__ = [
    "DrainResult",
    "MemorySink",
    "OpenTelemetrySink",
    "Sink",
    "backlog",
    "drain",
    "event_attributes",
    "pending",
]
