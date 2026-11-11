"""A small HTTP server in front of ``Authorizer.authorize``.

TODO(week 1): serve ``POST /v1/authorize`` (principal, action, resource, context) and
``POST /v1/grants`` / ``DELETE /v1/grants/{id}``, recording every decision in the ledger.
Keep the dependency footprint small: the standard library or one light ASGI framework.
"""

from __future__ import annotations


def serve(host: str = "127.0.0.1", port: int = 8181) -> None:
    raise NotImplementedError("the HTTP decision server lands in week 1")
