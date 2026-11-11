"""Answering "who allowed this?": walk a decision back to its grant, and replay it.

``trace(ledger, event_id)`` follows a decision to the grant it ran under (by the receipt
the decision recorded), to who issued that grant and when, and to any revocation, and
returns the three answers with the policy behind each.

``replay(trellis, event_id)`` re-runs a past decision twice: against the config and catalog
snapshot it recorded (which should reproduce it exactly) and against the current policy
(which shows what would change today).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from trellisd.catalog import SnapshotCatalog, table_from_snapshot
from trellisd.config import TrellisConfig
from trellisd.engine import CheckResult, Decision, Engine
from trellisd.grants import Grant
from trellisd.ledger import Ledger, LedgerEvent
from trellisd.signing import verify_signature

_EXTRA = ("receipt", "config_version", "catalog_snapshot")


class TraceError(LookupError):
    pass


@dataclass
class GrantHistory:
    grant: Grant
    issued: LedgerEvent
    revoked: LedgerEvent | None = None
    signature_ok: bool = False


@dataclass
class Trace:
    event: LedgerEvent
    decision: Decision
    grant: GrantHistory | None
    #: Problems found while walking: a receipt that matches nothing, a bad signature.
    warnings: list[str] = field(default_factory=list)


def recorded_decision(event: LedgerEvent) -> Decision:
    if event.kind != "decision":
        raise TraceError(f"{event.event_id} is a {event.kind} event, not a decision")
    body = {k: v for k, v in event.body.items() if k not in _EXTRA}
    return Decision.model_validate({**body, "event_id": event.event_id})


def grant_as_of(ledger: Ledger, grant_id: str, before_seq: int | None = None) -> GrantHistory:
    """The grant as the ledger recorded it, with any revocation before ``before_seq``."""
    issued = ledger.query(kind="grant.issued", grant_id=grant_id)
    if not issued:
        raise TraceError(f"no grant.issued entry for {grant_id}")
    ev = issued[0]
    grant = Grant.model_validate({**ev.body, "receipt": ev.hash})
    revoked = ledger.query(kind="grant.revoked", grant_id=grant_id, before_seq=before_seq)
    rev = revoked[0] if revoked else None
    if rev is not None:
        grant = grant.model_copy(update={"revoked_at": rev.ts, "revoked_by": rev.body.get("by")})
    pub = ledger.public_keys().get(ev.key_id)
    sig_ok = bool(pub) and verify_signature(pub or "", ev.hash, ev.sig)
    return GrantHistory(grant=grant, issued=ev, revoked=rev, signature_ok=sig_ok)


def trace(ledger: Ledger, event_id: str) -> Trace:
    event = ledger.get(event_id)
    if event is None:
        raise TraceError(f"no event {event_id}")
    decision = recorded_decision(event)
    warnings: list[str] = []
    history = None
    if event.grant_id:
        history = grant_as_of(ledger, event.grant_id, before_seq=event.seq)
        receipt = event.body.get("receipt")
        if receipt != history.issued.hash:
            warnings.append(
                f"the decision's receipt {str(receipt)[:12]}… doesn't match the grant entry "
                f"{history.issued.hash[:12]}…"
            )
        if not history.signature_ok:
            warnings.append(f"the grant entry for {event.grant_id} isn't validly signed")
    return Trace(event=event, decision=decision, grant=history, warnings=warnings)


# -- replay ----------------------------------------------------------------------------------


@dataclass
class Replay:
    recorded: Decision
    at_recorded_version: Decision | None
    at_current_policy: Decision
    #: Why the recorded version couldn't be replayed, if it couldn't.
    unavailable: str | None = None

    @property
    def reproduces(self) -> bool:
        return self.at_recorded_version is not None and not differences(
            self.recorded, self.at_recorded_version
        )

    @property
    def changed_today(self) -> list[str]:
        return differences(self.recorded, self.at_current_policy)


def _check_key(c: CheckResult) -> tuple[str, bool, tuple[str, ...]]:
    return (c.name, c.allowed, c.policies)


def differences(a: Decision, b: Decision) -> list[str]:
    out = []
    if a.allowed != b.allowed:
        out.append(
            f"{'allowed' if a.allowed else 'denied'} then, "
            f"{'allowed' if b.allowed else 'denied'} now"
        )
    for ca, cb in zip(a.checks, b.checks, strict=False):
        if _check_key(ca) != _check_key(cb):
            then = "yes" if ca.allowed else "no"
            now = "yes" if cb.allowed else "no"
            if then != now:
                out.append(f"{ca.label}: {then} then, {now} now")
            else:
                out.append(
                    f"{ca.label}: decided by {', '.join(ca.policies) or 'nothing'} then,"
                    f" {', '.join(cb.policies) or 'nothing'} now"
                )
    if len(a.checks) != len(b.checks):
        out.append("a different set of checks ran")
    if set(a.masked) != set(b.masked):
        out.append(
            f"masked {sorted(a.masked) or 'nothing'} then, {sorted(b.masked) or 'nothing'} now"
        )
    if a.row_filter != b.row_filter:
        out.append(f"row filter {a.row_filter!r} then, {b.row_filter!r} now")
    return out


def replay(ledger: Ledger, current: Engine, event_id: str) -> Replay:
    event = ledger.get(event_id)
    if event is None:
        raise TraceError(f"no event {event_id}")
    recorded = recorded_decision(event)
    if not event.grant_id:
        raise TraceError("this call had no grant (an unknown token), so there's nothing to replay")
    grant = grant_as_of(ledger, event.grant_id, before_seq=event.seq).grant
    cols = recorded.columns or None
    args: dict[str, Any] = {"now": event.ts}
    at_current = current.decide(grant, recorded.action, recorded.resource, cols, **args)
    cfg_body = ledger.snapshot(str(event.body.get("config_version", "")))
    tbl_body = ledger.snapshot(str(event.body.get("catalog_snapshot", "")))
    if cfg_body is None:
        return Replay(recorded, None, at_current, "the recorded config version isn't stored")
    tables = [table_from_snapshot(tbl_body)] if tbl_body else []
    then = Engine(TrellisConfig.model_validate(cfg_body), SnapshotCatalog(tables))
    at_recorded = then.decide(grant, recorded.action, recorded.resource, cols, **args)
    return Replay(recorded, at_recorded, at_current)
