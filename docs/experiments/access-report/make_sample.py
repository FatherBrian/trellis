"""Make a sample access report to show people who run access reviews.

    python docs/experiments/access-report/make_sample.py   # writes sample.csv next to this

It plays a few days of agent work against the three-keys example (two people, two agents,
a revoked grant, some denied calls) and writes the report `trellisd report` would produce.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from trellisd import Trellis
from trellisd.report import build, to_csv

ROOT = Path(__file__).resolve().parents[3]
CONFIG = ROOT / "examples" / "three-keys"
START = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)


def main() -> None:
    with TemporaryDirectory() as tmp:
        db = f"sqlite:///{Path(tmp) / 'sample.db'}"
        with Trellis.open(CONFIG, db_url=db) as t:
            day = START
            close = t.issue_grant(
                person="ana@example.com",
                agent="report-bot",
                task="Q3 close",
                scope={"finance"},
                ttl=timedelta(hours=8),
                now=day,
            )
            for h in range(1, 7):
                t.authorize(
                    close.token, "read", "finance.gl.journal_entries", now=day + timedelta(hours=h)
                )
            t.authorize(
                close.token, "read", "finance.gl.export_ledger", now=day + timedelta(hours=2)
            )
            t.authorize(close.token, "read", "hr.payroll", now=day + timedelta(hours=3))

            day = START + timedelta(days=2)
            recon = t.issue_grant(
                person="ana@example.com",
                agent="report-bot",
                task="Bank reconciliation",
                scope={"finance"},
                ttl=timedelta(hours=4),
                now=day,
            )
            t.authorize(
                recon.token, "read", "finance.gl.journal_entries", now=day + timedelta(hours=1)
            )
            t.revoke(recon.grant.id, by="ana@example.com", now=day + timedelta(hours=1, minutes=30))
            t.authorize(
                recon.token, "read", "finance.gl.journal_entries", now=day + timedelta(hours=2)
            )

            day = START + timedelta(days=3)
            t.issue_grant(
                person="tom@example.com",
                agent="report-bot",
                task="Board pack draft",
                scope={"finance"},
                ttl=timedelta(hours=2),
                now=day,
            )

            text = to_csv(build(t.ledger))
    out = Path(__file__).with_name("sample.csv")
    out.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
