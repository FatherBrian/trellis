"""Sign-in from any OIDC IdP: verify inbound tokens, and exchange them for downstream ones.

Trellis brokers sign-in; it isn't an IdP. It never creates users or holds passwords. It
accepts a token from any configured OIDC IdP, checks the signature against the IdP's
published keys, the issuer, the audience and the expiry, and turns the token into a
``Principal``: a person (named by ``subject_claim``, usually ``email``) or a workload (a
client, for a token with no person in it).

For servers that take the person's own token, ``exchange()`` asks the IdP for one through
RFC 8693 token exchange (Keycloak, Ping, Okta) or Entra's on-behalf-of flow.

    sources = Identities.from_config(config)
    person = sources.verify(id_token)            # Principal(kind="human", id="ana@...")
    downstream = sources.exchange(person, id_token, "ledger-mcp", ["read"])
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

import jwt

from trellisd.config import IdentityProvider, TrellisConfig
from trellisd.iceberg import Transport, urllib_transport

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105 (a grant type)
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105 (a token type)
# Never accept a symmetric or unsigned token: anyone holding a shared secret could forge one.
_ASYMMETRIC = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}


class IdentityError(Exception):
    """A token Trellis won't accept, or an exchange the IdP refused. ``check`` says which."""

    def __init__(self, message: str, check: str = "token") -> None:
        super().__init__(message)
        self.check = check


@dataclass(frozen=True)
class Principal:
    """Who a verified token names, and who vouched for it."""

    id: str
    kind: Literal["human", "workload"]
    idp: str
    issuer: str
    subject: str
    groups: tuple[str, ...] = ()
    expires_at: datetime | None = None
    claims: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)

    def vouch(self) -> dict[str, str]:
        """What the ledger keeps about the sign-in: never the token itself."""
        return {
            "id": self.id,
            "kind": self.kind,
            "idp": self.idp,
            "issuer": self.issuer,
            "subject": self.subject,
        }


class IdentitySource(Protocol):
    """One per IdP (Entra, Ping, Okta, Keycloak, any OIDC)."""

    name: str
    settings: IdentityProvider

    def verify(self, token: str) -> Principal: ...

    def exchange(self, subject_token: str, audience: str, scopes: Sequence[str]) -> str: ...


def unverified_issuer(token: str) -> str | None:
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None
    iss = claims.get("iss")
    return iss if isinstance(iss, str) else None


class OidcSource:
    """A generic OIDC IdP: discovery, JWKS, and the issuer, audience and expiry checks."""

    def __init__(
        self,
        name: str,
        settings: IdentityProvider,
        *,
        transport: Transport | None = None,
        clock: Callable[[], float] = time.time,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.name = name
        self.settings = settings
        self.transport = transport or urllib_transport()
        self.clock = clock
        self.environ = environ if environ is not None else os.environ
        self._discovery: dict[str, Any] | None = None
        self._keys: dict[str, jwt.PyJWK] = {}
        self._keys_read_at = -1e9
        self._lock = threading.Lock()

    # -- discovery and keys ----------------------------------------------------------------

    def _get_json(self, url: str) -> dict[str, Any]:
        try:
            status, body = self.transport("GET", url, {"Accept": "application/json"}, None)
        except OSError as exc:
            raise IdentityError(f"IdP {self.name} can't be reached ({exc})", "idp") from exc
        if status != 200:
            raise IdentityError(f"IdP {self.name} answered {status} for {url}", "idp")
        data = json.loads(body)
        if not isinstance(data, dict):
            raise IdentityError(f"IdP {self.name} sent something that isn't JSON", "idp")
        return data

    def discovery(self) -> dict[str, Any]:
        if self._discovery is None:
            url = self.settings.discovery_url or (
                self.settings.issuer.rstrip("/") + "/.well-known/openid-configuration"
            )
            doc = self._get_json(url)
            if doc.get("issuer") != self.settings.issuer:
                raise IdentityError(
                    f"IdP {self.name}'s discovery document names issuer {doc.get('issuer')},"
                    f" not {self.settings.issuer}",
                    "idp",
                )
            self._discovery = doc
        return self._discovery

    def _key(self, kid: str | None) -> jwt.PyJWK:
        with self._lock:
            if kid in self._keys:
                return self._keys[kid]
            # An unknown key id means the IdP may have rotated: reread, at most once a minute.
            if self.clock() - self._keys_read_at >= 60 or not self._keys:
                jwks = self._get_json(str(self.discovery()["jwks_uri"]))
                self._keys = {}
                for k in jwks.get("keys", []):
                    if k.get("use", "sig") != "sig":
                        continue
                    try:
                        self._keys[k.get("kid")] = jwt.PyJWK(k)
                    except jwt.PyJWTError:
                        continue
                self._keys_read_at = self.clock()
            if kid in self._keys:
                return self._keys[kid]
            if kid is None and len(self._keys) == 1:
                return next(iter(self._keys.values()))
        raise IdentityError(
            f"the token was signed with key {kid}, which IdP {self.name} doesn't publish",
            "signature",
        )

    # -- verify ----------------------------------------------------------------------------

    def verify(self, token: str) -> Principal:
        s = self.settings
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise IdentityError("that isn't a signed JWT", "token") from exc
        alg = header.get("alg")
        allowed = set(s.algorithms) & _ASYMMETRIC
        if alg not in allowed:
            raise IdentityError(
                f"the token is signed with {alg}; Trellis accepts {', '.join(sorted(allowed))}",
                "signature",
            )
        key = self._key(header.get("kid"))
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=[alg],
                audience=list(s.audience),
                issuer=s.issuer,
                leeway=s.leeway_seconds,
                options={"require": ["exp", "iss", "sub"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise IdentityError(f"the token from {self.name} has expired", "expired") from exc
        except jwt.InvalidAudienceError as exc:
            aud = jwt.decode(token, options={"verify_signature": False}).get("aud")
            raise IdentityError(
                f"the token is for {aud}, not for {' or '.join(s.audience)}", "audience"
            ) from exc
        except jwt.InvalidIssuerError as exc:
            raise IdentityError(
                f"the token wasn't issued by {self.name} ({s.issuer})", "issuer"
            ) from exc
        except jwt.ImmatureSignatureError as exc:
            raise IdentityError("the token isn't valid yet", "token") from exc
        except jwt.InvalidSignatureError as exc:
            raise IdentityError(
                f"the token's signature doesn't match {self.name}'s keys", "signature"
            ) from exc
        except jwt.PyJWTError as exc:
            raise IdentityError(f"the token was refused: {exc}", "token") from exc
        exp = datetime.fromtimestamp(claims["exp"], tz=UTC)
        groups = claims.get("groups")
        groups_t = tuple(str(g) for g in groups) if isinstance(groups, list) else ()
        person = claims.get(s.subject_claim)
        is_app = claims.get("idtyp") == "app"  # Entra marks app-only tokens this way
        if isinstance(person, str) and person and not is_app:
            return Principal(
                id=person.lower(),
                kind="human",
                idp=self.name,
                issuer=s.issuer,
                subject=str(claims["sub"]),
                groups=groups_t,
                expires_at=exp,
                claims=claims,
            )
        client = next((claims[c] for c in s.client_claims if isinstance(claims.get(c), str)), None)
        return Principal(
            id=str(client or claims["sub"]),
            kind="workload",
            idp=self.name,
            issuer=s.issuer,
            subject=str(claims["sub"]),
            groups=groups_t,
            expires_at=exp,
            claims=claims,
        )

    # -- exchange --------------------------------------------------------------------------

    def exchange(self, subject_token: str, audience: str, scopes: Sequence[str]) -> str:
        """A token for ``audience`` that still names the person, from the IdP."""
        s = self.settings
        if s.exchange == "none":
            raise IdentityError(f"IdP {self.name} isn't set up to exchange tokens", "exchange")
        if not s.client_id:
            raise IdentityError(f"IdP {self.name} needs client_id to exchange tokens", "exchange")
        secret = self.environ.get(s.client_secret_env or "") if s.client_secret_env else None
        form: dict[str, str] = {"client_id": s.client_id}
        if secret:
            form["client_secret"] = secret
        if s.exchange == "rfc8693":
            form |= {
                "grant_type": TOKEN_EXCHANGE,
                "subject_token": subject_token,
                "subject_token_type": ACCESS_TOKEN,
                "requested_token_type": ACCESS_TOKEN,
                "audience": audience,
            }
            if scopes:
                form["scope"] = " ".join(scopes)
        else:  # Entra on-behalf-of: the audience is named by the scope.
            form |= {
                "grant_type": JWT_BEARER,
                "assertion": subject_token,
                "requested_token_use": "on_behalf_of",
                "scope": " ".join(scopes) if scopes else f"{audience}/.default",
            }
        url = str(self.discovery()["token_endpoint"])
        try:
            status, body = self.transport(
                "POST",
                url,
                {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
                urllib.parse.urlencode(form).encode(),
            )
        except OSError as exc:
            raise IdentityError(f"IdP {self.name} can't be reached ({exc})", "idp") from exc
        try:
            data = json.loads(body)
        except ValueError:
            data = {}
        if status != 200 or "access_token" not in data:
            why = data.get("error_description") or data.get("error") or f"status {status}"
            raise IdentityError(f"IdP {self.name} refused the exchange: {why}", "exchange")
        return str(data["access_token"])


class Identities:
    """Every configured IdP; a token goes to the one whose issuer it names."""

    def __init__(self, sources: Sequence[IdentitySource]) -> None:
        self.sources = {s.name: s for s in sources}
        self._by_issuer = {s.settings.issuer: s for s in sources}

    @classmethod
    def from_config(cls, config: TrellisConfig, **kw: Any) -> Identities:
        return cls([OidcSource(name, p, **kw) for name, p in sorted(config.idps.items())])

    def __bool__(self) -> bool:
        return bool(self.sources)

    def verify(self, token: str) -> Principal:
        iss = unverified_issuer(token)
        if iss is None:
            raise IdentityError("that isn't a signed JWT", "token")
        source = self._by_issuer.get(iss)
        if source is None:
            raise IdentityError(f"no IdP Trellis trusts issues tokens as {iss}", "issuer")
        return source.verify(token)

    def exchange(
        self, principal: Principal, subject_token: str, audience: str, scopes: Sequence[str]
    ) -> str:
        source = self.sources.get(principal.idp)
        if source is None:
            raise IdentityError(f"no IdP called {principal.idp}", "idp")
        return source.exchange(subject_token, audience, scopes)
