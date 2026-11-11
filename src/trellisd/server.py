"""The decision server: one AuthZEN endpoint in front of ``Trellis.authorize`` (M4).

M4 serves ``POST /access/v1/evaluation`` and ``/.well-known/authzen-configuration``,
recording every decision in the ledger before it answers.
Keep the dependency footprint small: the standard library or one light ASGI framework.
"""

from __future__ import annotations


def serve(host: str = "127.0.0.1", port: int = 8181) -> None:
    raise NotImplementedError("the AuthZEN endpoint lands in M4")
