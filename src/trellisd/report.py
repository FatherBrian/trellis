"""The access report: who let which agent do what, for whom, over a period.

It's built for an access review. An identity-governance tool knows what an agent is
*entitled* to; this says what it actually *did*, per grant: who it acted for, on which task,
who allowed it, and which resources it reached, with allowed and denied counts. Everything
comes from the ledger, so the report can be checked against it.

    trellisd report --since 90d               # CSV, one row per grant and resource
    trellisd report --since 90d --format json
"""

from __future__ import annotations

import csv
import io
import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from trellisd.ledger import Ledger

COLUMNS = (
    "agent",
    "acting_for",
    "kind",
    "task",
    "granted_by",
    "granted_at",
    "expires_at",
    "revoked_at",
    "scope",
    "resource",
    "action",
    "allowed_calls",
    "denied_calls",
    "masked_fields",
    "first_call",
    "last_call",
    "grant_id",
)


@dataclass
class Usage:
    resource: str
    action: str
    allowed: int = 0
    denied: int = 0
    masked: set[str] = field(default_factory=set)
    first: str = ""
    last: str = ""


@dataclass
class GrantReport:
    grant_id: str
    agent: str
    acting_for: str
    kind: str
    task: str
    granted_by: str
    granted_at: str
    expires_at: str
    revoked_at: str
    scope: list[str]
    usage: list[Usage]


def build(ledger: Ledger, since: datetime | None = None) -> list[GrantReport]:
    """One entry per grant that was issued, or used, since ``since``."""
    grants: dict[str, dict[str, Any]] = {}
    for ev in ledger.query(kind="grant.issued"):
        grants[ev.grant_id] = {**ev.body, "_ts": ev.ts.isoformat()}
    revoked = {ev.grant_id: ev.ts.isoformat() for ev in ledger.query(kind="grant.revoked")}

    usage: dict[str, dict[tuple[str, str], Usage]] = defaultdict(dict)
    for ev in ledger.query(kind="decision", since=since):
        if not ev.grant_id:
            continue
        b = ev.body
        key = (str(b.get("resource", "")), str(b.get("action", "")))
        u = usage[ev.grant_id].setdefault(key, Usage(*key))
        if b.get("allowed"):
            u.allowed += 1
            u.masked |= set(b.get("masked") or {})
        else:
            u.denied += 1
        ts = ev.ts.isoformat()
        u.first = u.first or ts
        u.last = ts

    wanted = set(usage)
    for gid, g in grants.items():
        if since is None or g["_ts"] >= since.isoformat():
            wanted.add(gid)

    out: list[GrantReport] = []
    for gid in sorted(wanted, key=lambda g: grants.get(g, {}).get("_ts", "")):
        g = grants.get(gid, {})
        out.append(
            GrantReport(
                grant_id=gid,
                agent=str(g.get("agent", "")),
                acting_for=str(g.get("subject", "")),
                kind=str(g.get("kind", "")),
                task=str(g.get("task", "")),
                granted_by=str(g.get("issued_by", "")),
                granted_at=str(g.get("issued_at", g.get("_ts", ""))),
                expires_at=str(g.get("expires_at", "")),
                revoked_at=revoked.get(gid, ""),
                scope=list(g.get("scope", [])),
                usage=sorted(usage.get(gid, {}).values(), key=lambda u: (u.resource, u.action)),
            )
        )
    return out


def to_csv(reports: list[GrantReport]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS, lineterminator="\n")
    w.writeheader()
    for r in reports:
        base = {
            "agent": r.agent,
            "acting_for": r.acting_for,
            "kind": r.kind,
            "task": r.task,
            "granted_by": r.granted_by,
            "granted_at": r.granted_at,
            "expires_at": r.expires_at,
            "revoked_at": r.revoked_at,
            "scope": " ".join(r.scope),
            "grant_id": r.grant_id,
        }
        if not r.usage:  # a grant nobody used is worth seeing in a review too
            w.writerow({**base, "allowed_calls": 0, "denied_calls": 0})
        for u in r.usage:
            w.writerow(
                {
                    **base,
                    "resource": u.resource,
                    "action": u.action,
                    "allowed_calls": u.allowed,
                    "denied_calls": u.denied,
                    "masked_fields": " ".join(sorted(u.masked)),
                    "first_call": u.first,
                    "last_call": u.last,
                }
            )
    return buf.getvalue()


def to_json(reports: list[GrantReport], verified: dict[str, Any]) -> str:
    def usage(u: Usage) -> dict[str, Any]:
        d = asdict(u)
        d["masked"] = sorted(u.masked)
        return d

    return json.dumps(
        {
            "ledger": verified,
            "grants": [{**asdict(r), "usage": [usage(u) for u in r.usage]} for r in reports],
        },
        indent=2,
    )
