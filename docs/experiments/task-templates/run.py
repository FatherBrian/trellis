"""Can a task template be narrow and still let the work through?

Three tasks an agent might be handed, each with the calls the work actually needs and calls
it shouldn't make. Each task is run twice through Trellis's real engine: once with a naive
template (its domain's tag, read only) and once with a template tuned to the work. For each,
it counts legitimate calls allowed, allowed but with fields masked, and wrongly denied, plus
out-of-task calls denied or let through.

    python docs/experiments/task-templates/run.py   # writes RESULTS.md next to this file

The workloads are written by hand, so this measures the template design, not real traffic.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trellisd import Trellis
from trellisd.config import TrellisConfig

ANA = "ana@example.com"

# -- the tools, as contracts: tags on the tool, tags on the fields it returns ----------------

TOOLS: dict[str, dict[str, Any]] = {
    # finance
    "mcp://ledger/journal_entries": {"tags": ["finance", "internal"]},
    "mcp://ledger/gl_balances": {"tags": ["finance", "internal"]},
    "mcp://ledger/post_adjustment": {"tags": ["finance", "internal"]},
    "mcp://ledger/export_ledger": {"tags": ["finance", "export_controlled"]},
    "mcp://market/fx_rates": {"tags": ["market-data", "public"]},
    # hr
    "mcp://hr/headcount": {"tags": ["hr", "internal"]},
    "mcp://hr/org_chart": {"tags": ["hr", "internal"], "fields": {"name": [], "email": ["pii"]}},
    "mcp://hr/payroll": {
        "tags": ["hr", "confidential"],
        "fields": {"employee": [], "cost_center": [], "salary": ["pii"]},
    },
    "mcp://hr/performance_reviews": {"tags": ["hr", "confidential", "pii"]},
    # support and customers
    "mcp://support/tickets": {
        "tags": ["support", "internal"],
        "fields": {"subject": [], "customer_email": ["pii"]},
    },
    "mcp://support/reply_to_ticket": {"tags": ["support", "internal"]},
    "mcp://crm/accounts": {
        "tags": ["customer", "confidential"],
        "fields": {"company": [], "email": ["pii"], "phone": ["pii"]},
    },
    "mcp://orders/order_history": {"tags": ["finance", "customer", "internal"]},
}

ACTIONS = ["read", "query", "write"]


def config() -> TrellisConfig:
    contracts = {}
    for address, t in TOOLS.items():
        name = address.removeprefix("mcp://").replace("/", ".")
        urn = f"urn:contract:{name}"
        contracts[urn] = {
            "contract": urn,
            "kind": "mcp_tool",
            "bindings": [address],
            "owner": "data-owner@example.com",
            "tags": t["tags"],
            "elements": t.get("fields", {}),
            # Ana may use every tool herself, so the person check never decides here: the
            # experiment is about the task check.
            "access": {"ana": {"who": [f"user:{ANA}"], "actions": ACTIONS}},
        }
    return TrellisConfig.model_validate(
        {
            "agents": {
                "work-bot": {
                    "owner": "platform@example.com",
                    "ceiling": {
                        "actions": ACTIONS,
                        "tags": [
                            *("finance", "hr", "support", "customer", "market-data"),
                            *("pii", "confidential"),
                        ],
                        "never": ["export_controlled"],
                    },
                }
            },
            "contracts": contracts,
        }
    )


# -- the tasks: what the work needs, and what it shouldn't touch ------------------------------


@dataclass
class Call:
    action: str
    tool: str
    why: str
    needs: tuple[str, ...] = ()  # fields the work actually needs to see


@dataclass
class Task:
    name: str
    legit: list[Call]
    out_of_task: list[Call]
    naive: tuple[list[str], list[str]]  # (scope tags, actions)
    tuned: tuple[list[str], list[str]]


TASKS = [
    Task(
        "Q3 close",
        legit=[
            Call("read", "mcp://ledger/journal_entries", "review the quarter's entries"),
            Call("read", "mcp://ledger/gl_balances", "check balances"),
            Call("read", "mcp://market/fx_rates", "convert foreign-currency entries"),
            Call("write", "mcp://ledger/post_adjustment", "post an accrual adjustment"),
        ],
        out_of_task=[
            Call("read", "mcp://hr/payroll", "not part of the close"),
            Call("read", "mcp://crm/accounts", "not part of the close"),
            Call("read", "mcp://ledger/export_ledger", "export-controlled"),
        ],
        naive=(["finance"], ["read", "query"]),
        tuned=(["finance", "market-data"], ["read", "query", "write"]),
    ),
    Task(
        "Headcount review",
        legit=[
            Call("read", "mcp://hr/headcount", "count by region"),
            Call("read", "mcp://hr/org_chart", "who reports to whom"),
            Call("read", "mcp://hr/payroll", "cost per team", needs=("cost_center",)),
        ],
        out_of_task=[
            Call("read", "mcp://hr/performance_reviews", "individual reviews aren't needed"),
            Call("read", "mcp://ledger/journal_entries", "not part of the review"),
            Call("read", "mcp://crm/accounts", "not part of the review"),
        ],
        naive=(["hr"], ["read", "query"]),
        tuned=(["hr"], ["read", "query"]),
    ),
    Task(
        "Customer escalation",
        legit=[
            Call("read", "mcp://support/tickets", "read the ticket", needs=("customer_email",)),
            Call("read", "mcp://crm/accounts", "find the account owner", needs=("email",)),
            Call("read", "mcp://orders/order_history", "check the disputed order"),
            Call("write", "mcp://support/reply_to_ticket", "reply to the customer"),
        ],
        out_of_task=[
            Call("read", "mcp://hr/payroll", "not part of the escalation"),
            Call("read", "mcp://ledger/journal_entries", "not part of the escalation"),
            Call("read", "mcp://ledger/export_ledger", "export-controlled"),
        ],
        naive=(["support"], ["read", "query"]),
        tuned=(["support", "customer", "pii"], ["read", "query", "write"]),
    ),
]


# -- run ----------------------------------------------------------------------------------------


def run(trellis: Trellis, task: Task, scope: list[str], actions: list[str]) -> dict[str, Any]:
    issued = trellis.issue_grant(
        person=ANA, agent="work-bot", task=task.name, scope=scope, actions=tuple(actions)
    )
    rows = []
    counts = {"clean": 0, "masked": 0, "blocked_need": 0, "false_deny": 0, "denied": 0, "leak": 0}
    for kind, calls in (("legit", task.legit), ("out", task.out_of_task)):
        for c in calls:
            d = trellis.authorize(issued.token, c.action, c.tool)
            masked = sorted(d.masked)
            if kind == "legit":
                if not d.allowed:
                    outcome = "wrongly denied"
                    counts["false_deny"] += 1
                elif hidden := sorted(set(c.needs) & set(masked)):
                    outcome = f"allowed, but needed {', '.join(hidden)} masked"
                    counts["blocked_need"] += 1
                elif masked:
                    outcome = f"allowed, {', '.join(masked)} masked"
                    counts["masked"] += 1
                else:
                    outcome = "allowed"
                    counts["clean"] += 1
            elif d.allowed:
                outcome = "LET THROUGH"
                counts["leak"] += 1
            else:
                outcome = "denied"
                counts["denied"] += 1
            reason = "" if d.allowed else d.reason.split(":", 1)[-1].strip()
            rows.append((kind, c, outcome, reason))
    reach = sum(1 for t in TOOLS if trellis.authorize(issued.token, "read", t).allowed)
    return {"rows": rows, "counts": counts, "reach": reach}


def main() -> None:
    lines = [
        "# Task templates: results",
        "",
        "Generated by `run.py` with Trellis's real engine. Ana may use every tool, and the",
        "agent's ceiling allows everything except export-controlled data, so these numbers are",
        "about the task template alone.",
        "",
        f"There are {len(TOOLS)} tools. **Reach** is how many the template lets the agent read.",
        "",
        "| Task | Template | Scope · actions | Legit allowed | …with a needed field masked"
        " | Wrongly denied | Out-of-task denied | Let through | Reach |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    details: list[str] = []
    with Trellis(config(), "sqlite:///:memory:") as trellis:
        for task in TASKS:
            for label, (scope, actions) in (("naive", task.naive), ("tuned", task.tuned)):
                r = run(trellis, task, scope, actions)
                c = r["counts"]
                ok = c["clean"] + c["masked"] + c["blocked_need"]
                lines.append(
                    f"| {task.name} | {label} | {', '.join(scope)} · {', '.join(actions)} |"
                    f" {ok}/{len(task.legit)} | {c['blocked_need']} | {c['false_deny']} |"
                    f" {c['denied']}/{len(task.out_of_task)} | {c['leak']} |"
                    f" {r['reach']}/{len(TOOLS)} |"
                )
                details += [
                    "",
                    f"## {task.name}, {label}",
                    "",
                    "| Call | Kind | Outcome | Why denied |",
                    "|---|---|---|---|",
                ]
                for kind, call, outcome, reason in r["rows"]:
                    who = "needed" if kind == "legit" else "shouldn't happen"
                    details.append(
                        f"| `{call.action} {call.tool.removeprefix('mcp://')}` ({call.why})"
                        f" | {who} | {outcome} | {reason} |"
                    )
    out = Path(__file__).with_name("RESULTS.md")
    out.write_text("\n".join(lines + details) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
