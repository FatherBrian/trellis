"""A small in-process OIDC IdP, for demos and tests that run without Docker.

It publishes discovery and JWKS documents and signs RS256 tokens, and its token endpoint
speaks four grants: ``password`` (a person signs in), ``client_credentials`` (an agent
signs in as itself), RFC 8693 token exchange, and Entra-style on-behalf-of
(``jwt-bearer`` with ``requested_token_use=on_behalf_of``). Tokens look like a typical
IdP's: ``iss``, ``sub``, ``aud``, ``exp``, ``iat``, ``jti``, plus ``email`` and
``groups`` for a person and ``azp`` for the client.

It is a test double, not an IdP: passwords are plain and every client may exchange.

    with FakeIdP(users={"ana": {"email": "ana@example.com", "password": "pw"}},
                 clients={"report-bot": "secret"}) as idp:
        token = idp.sign_in("ana", audience="trellis")
"""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105 (a grant type)
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class FakeIdP:
    def __init__(
        self,
        users: dict[str, dict[str, Any]] | None = None,
        clients: dict[str, str] | None = None,
        ttl: int = 3600,
    ) -> None:
        self.users = users or {}
        self.clients = clients or {}
        self.ttl = ttl
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = uuid.uuid4().hex[:8]
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self._thread.start()

    @property
    def issuer(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host!s}:{port}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> FakeIdP:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- tokens ----------------------------------------------------------------------------

    def mint(
        self,
        claims: dict[str, Any],
        *,
        key: Any = None,
        kid: str | None = None,
        alg: str = "RS256",
    ) -> str:
        """Sign any claims (tests use it for expired, wrong-audience or forged tokens)."""
        now = int(time.time())
        body = {"iss": self.issuer, "iat": now, "exp": now + self.ttl, "jti": uuid.uuid4().hex}
        body.update(claims)
        return jwt.encode(
            body,
            key if key is not None else self.key,
            algorithm=alg,
            headers={"kid": kid or self.kid},
        )

    def sign_in(self, username: str, audience: str, client: str = "trellis-cli") -> str:
        user = self.users[username]
        return self.mint(
            {
                "sub": user.get("sub", f"u-{username}"),
                "aud": audience,
                "azp": client,
                "email": user["email"],
                "name": user.get("name", username),
                "groups": list(user.get("groups", [])),
            }
        )

    def client_token(self, client_id: str, audience: str) -> str:
        return self.mint({"sub": f"sa-{client_id}", "aud": audience, "azp": client_id})

    def jwks(self) -> dict[str, Any]:
        pub = self.key.public_key().public_numbers()

        def b64(n: int) -> str:
            raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self.kid,
                    "n": b64(pub.n),
                    "e": b64(pub.e),
                }
            ]
        }

    def discovery(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "jwks_uri": f"{self.issuer}/jwks",
            "token_endpoint": f"{self.issuer}/token",
            "grant_types_supported": [
                "password",
                "client_credentials",
                TOKEN_EXCHANGE,
                JWT_BEARER,
            ],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    # -- the token endpoint ----------------------------------------------------------------

    def _client_ok(self, form: dict[str, str]) -> bool:
        cid = form.get("client_id", "")
        return cid in self.clients and self.clients[cid] == form.get("client_secret")

    def _verify_own(self, token: str) -> dict[str, Any]:
        return jwt.decode(
            token, self.key.public_key(), algorithms=["RS256"], options={"verify_aud": False}
        )

    def token(self, form: dict[str, str]) -> tuple[int, dict[str, Any]]:
        def error(code: str, why: str, status: int = 400) -> tuple[int, dict[str, Any]]:
            return status, {"error": code, "error_description": why}

        grant = form.get("grant_type")
        if grant == "password":
            user = self.users.get(form.get("username", ""))
            if user is None or user.get("password") != form.get("password"):
                return error("invalid_grant", "wrong username or password")
            token = self.sign_in(
                form["username"], form.get("audience", "trellis"), form.get("client_id", "")
            )
        elif grant == "client_credentials":
            if not self._client_ok(form):
                return error("invalid_client", "unknown client or wrong secret", 401)
            token = self.client_token(form["client_id"], form.get("audience", "trellis"))
        elif grant in (TOKEN_EXCHANGE, JWT_BEARER):
            if not self._client_ok(form):
                return error("invalid_client", "unknown client or wrong secret", 401)
            subject = form.get("subject_token") or form.get("assertion") or ""
            try:
                claims = self._verify_own(subject)
            except jwt.PyJWTError as exc:
                return error("invalid_grant", f"subject token refused: {exc}")
            if grant == JWT_BEARER:
                if form.get("requested_token_use") != "on_behalf_of":
                    return error("invalid_request", "requested_token_use must be on_behalf_of")
                scope = form.get("scope", "")
                audience = scope.split(" ")[0].rsplit("/", 1)[0] if scope else ""
            else:
                audience = form.get("audience", "")
                scope = form.get("scope", "")
            if not audience:
                return error("invalid_request", "no audience")
            keep: dict[str, Any] = {
                k: claims[k] for k in ("sub", "email", "name", "groups") if k in claims
            }
            token = self.mint({**keep, "aud": audience, "azp": form["client_id"], "scope": scope})
        else:
            return error("unsupported_grant_type", f"{grant} isn't supported")
        return 200, {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": self.ttl,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        }

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        idp = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send(self, status: int, body: Any) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                path = urllib.parse.urlsplit(self.path).path
                if path == "/.well-known/openid-configuration":
                    self._send(200, idp.discovery())
                elif path == "/jwks":
                    self._send(200, idp.jwks())
                else:
                    self._send(404, {"error": "not_found"})

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n).decode() if n else ""
                form = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
                if urllib.parse.urlsplit(self.path).path != "/token":
                    self._send(404, {"error": "not_found"})
                    return
                self._send(*idp.token(form))

        return Handler
