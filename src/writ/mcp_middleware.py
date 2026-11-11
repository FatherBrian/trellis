"""MCP middleware: wrap a tool call in an authorize check and a ledger write.

The guard is SDK-agnostic so it can be tested without an MCP server. It reads the
agent's grant token from a ``token_provider`` you supply; with the Python MCP SDK that
provider reads the bearer token from the current request context.

Usage::

    guard = WritGuard(authorizer, ledger, token_provider=current_request_token)

    @mcp.tool()
    @guard.tool(action="read", resource="finance.gl.journal_entries")
    def journal_entries(limit: int = 100) -> list[dict]:
        ...

The ledger write happens before the tool runs, so a denied or crashed call is still on
record. On an allow, masked columns are redacted from dict or list-of-dict results.

TODO(week 3): ship a ready-made ``token_provider`` for ``mcp.server.fastmcp`` and wire the
guard into FastMCP tool registration so ``@guard.tool`` is the only decorator needed.
TODO(week 3): apply the decision's row filter when the tool runs SQL.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any, ParamSpec, TypeVar, cast

from writ.decision import Authorizer, Decision, Principal, RequestContext
from writ.grants import GrantError
from writ.ledger import Ledger

P = ParamSpec("P")
R = TypeVar("R")

MASK = "***"

ResourceSpec = str | Callable[..., str]


class WritDenied(PermissionError):
    """Raised instead of running the tool when Writ denies the call."""

    def __init__(self, decision: Decision, event_id: str | None = None) -> None:
        super().__init__(decision.reason)
        self.decision = decision
        self.event_id = event_id


def redact(result: Any, masks: tuple[str, ...]) -> Any:
    """Replace masked columns in a row or list of rows. Other shapes pass through untouched."""
    if not masks:
        return result
    if isinstance(result, dict):
        return {k: (MASK if k in masks else v) for k, v in result.items()}
    if isinstance(result, list):
        return [redact(row, masks) for row in result]
    return result


class WritGuard:
    def __init__(
        self,
        authorizer: Authorizer,
        ledger: Ledger,
        token_provider: Callable[[], str],
    ) -> None:
        self.authorizer = authorizer
        self.ledger = ledger
        self.token_provider = token_provider

    def check(self, action: str, resource: str, columns: tuple[str, ...] | None = None) -> Decision:
        """Authorize and record one call. Raises ``WritDenied`` on a deny."""
        try:
            grant = self.authorizer.grants.resolve(self.token_provider())
        except GrantError as exc:
            # TODO(week 2): record rejected tokens too, under an "unknown" principal.
            raise WritDenied(Decision(allowed=False, reason=str(exc))) from exc
        principal = Principal.from_grant(grant)
        ctx = RequestContext(columns=columns)
        decision = self.authorizer.authorize(principal, action, resource, ctx)
        event = self.ledger.record(principal, action, resource, decision, ctx)
        if not decision.allowed:
            raise WritDenied(decision, event.event_id)
        return decision

    def tool(
        self,
        *,
        action: str,
        resource: ResourceSpec,
        columns_arg: str | None = None,
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        """Decorate a sync or async tool function.

        ``resource`` is a fixed name or a callable that derives it from the tool's
        arguments. ``columns_arg`` names a tool parameter holding requested columns.
        """

        def resolve(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[str, Any]:
            name = resource if isinstance(resource, str) else resource(*args, **kwargs)
            cols = kwargs.get(columns_arg) if columns_arg else None
            return name, tuple(cols) if cols is not None else None

        def decorate(fn: Callable[P, R]) -> Callable[P, R]:
            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                    name, cols = resolve(args, kwargs)
                    decision = self.check(action, name, cols)
                    return redact(await fn(*args, **kwargs), decision.masks)

                return cast(Callable[P, R], async_wrapper)

            @functools.wraps(fn)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                name, cols = resolve(args, kwargs)
                decision = self.check(action, name, cols)
                return cast(R, redact(fn(*args, **kwargs), decision.masks))

            return wrapper

        return decorate
