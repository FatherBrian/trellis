# Experiment: can task templates be narrow and still let the work through?

**Question.** If a person hands an agent a task by picking a template ("Q3 close"), does the
template let the legitimate work through without also letting through things the task
shouldn't touch?

**Setup.** 13 tools across finance, HR, support and CRM, each with a contract (tags on the tool,
tags on the fields it returns). Three tasks, each with the calls the work needs and calls it
shouldn't make. Each task ran twice through Trellis's real engine: a **naive** template (its
domain's tag, read only) and a **tuned** template designed from the workload. Ana may use every
tool and the agent's ceiling allows everything but export-controlled data, so only the task
check decides. Run it with `python docs/experiments/task-templates/run.py`; full results are in
[RESULTS.md](RESULTS.md).

**Caveat.** The workloads are written by hand. This tests template design against plausible work,
not a measured rate from real traffic.

## Results

| Task | Template | Legit calls allowed | Out-of-task calls denied | Tools reachable |
|---|---|---|---|---|
| Q3 close | naive: `finance`, read | 2 of 4 | 3 of 3 | 4 of 13 |
| Q3 close | tuned: `finance, market-data`, read and write | 4 of 4 | 3 of 3 | 5 of 13 |
| Headcount review | `hr`, read | 3 of 3 | **2 of 3** | 4 of 13 |
| Customer escalation | naive: `support`, read | 1 of 4 | 3 of 3 | 2 of 13 |
| Customer escalation | tuned: `support, customer, pii`, read and write | 4 of 4 | 3 of 3 | 5 of 13 |

## Findings

1. **Naive domain templates block real work.** Real tasks cross domains: the close needs FX
   rates (market data), and an escalation needs the CRM and order history. A one-tag template
   let through 2 of 4 and 1 of 4 of the needed calls. Writes were denied too, because the
   template said read only.

2. **Tuned templates work, and stay fairly narrow.** Designed from the actual work, every
   template allowed all the legitimate calls and denied every out-of-task call, while reaching
   only 5 of 13 tools. So narrow-but-workable templates are possible, **if someone designs them
   from the work**. That's the real cost: a template is a small piece of design, not a
   checkbox.

3. **The task check matches any one tag, which is too loose.** The headcount template (`hr`) let
   through `performance_reviews`, a tool tagged `hr, confidential, pii` that the task never
   needs. A resource passes the task check if it carries *any* tag in the template's scope, so a
   sensitive tool in the same domain gets in.

4. **The task check never restricts sensitive fields.** Fields inherit their tool's tags, so in
   the headcount review `salary` (tagged pii) wasn't masked by the task check: every field also
   carries `hr`. In practice, masking came from the agent's **ceiling** or a contract role's
   `mask`, not from the task. (That also corrects Reef's guide, which said the grant masked
   `salary`; it was the ceiling.)

## After the fix: sensitive tags must be named

Trellis now treats some tags as **sensitive** (`pii` by default; set `sensitive:` in the config
to add `phi`, `pci` or others, or `[]` to turn it off). The task check passes a resource only
when the scope covers one of its other tags **and** every sensitive tag it carries, and the same
rule applies to each field. A scope made only of sensitive tags is refused when the grant is
issued, because a task has to name a domain. Re-running the experiment:

| Task | Template | Legit calls allowed | Out-of-task calls denied | Tools reachable |
|---|---|---|---|---|
| Q3 close | tuned: `finance, market-data`, read and write | 4 of 4 | 3 of 3 | 5 of 13 |
| Headcount review | `hr`, read | 3 of 3 (`salary` masked) | **3 of 3** | 3 of 13 |
| Customer escalation | naive: `support`, read | 1 of 4 (and the needed email masked) | 3 of 3 | 2 of 13 |
| Customer escalation | tuned: `support, customer, pii`, read and write | 4 of 4 | 3 of 3 | 4 of 13 |

`performance_reviews` is now denied ("is pii, and the grant covers hr without pii"), and
payroll's `salary` is masked ("the grant's scope doesn't include pii") unless the template names
pii. `tests/test_sensitive_scope.py` covers these cases, plus a property test: across random
tags, fields and scopes, no grant reaches a sensitive tag, on a tool or a field, that its scope
doesn't name.

## Still to do for 0.2

- ~~Sensitive tags must be covered, not just one domain tag.~~ Done (above).
- **Templates can name tools as well as tags.** A template with a `tools:` list (the task's
  toolbox) is the most precise option for agents whose tools are known, and it's what the
  agent config's toolbox already does at the ceiling level.
- **Templates carry actions explicitly.** "Read only" is the wrong default for tasks that post
  or reply. Writes stay off unless the template says `write`.
- **Report each template's reach** ("5 of 13 tools, 2 with pii") when it's created, so a
  reviewer can see how broad it is before approving it.
- **Next step for real numbers:** run templates in log-only mode against real agent traffic and
  count would-be denials before enforcing. That's the false-denial rate this experiment can't
  give.
