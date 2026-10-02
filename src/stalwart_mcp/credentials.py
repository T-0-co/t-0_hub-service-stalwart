"""Per-request credentials and the quarantine for rejected ones.

The server never stores credentials. Each MCP request carries one in its
`Authorization` header:

- `Bearer user@example.com:app-password` — what an MCP hub sends for a per-user
  credential stored as "username:app-password". Forwarded as HTTP Basic.
- `Bearer <token>` (no colon) — a Stalwart API key or OAuth access token.
  Forwarded unchanged as Bearer.
- `Basic <base64>` — forwarded unchanged.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from .errors import AuthRejected, CredentialMissing


@dataclass(frozen=True)
class Credential:
    scheme: Literal["basic", "bearer"]
    secret: str
    """For basic: "username:password". For bearer: the token."""

    @property
    def fingerprint(self) -> str:
        """Stable, non-reversible key for caches and the quarantine. Never log `secret`."""
        return hashlib.sha256(f"{self.scheme}\0{self.secret}".encode()).hexdigest()[:20]

    @property
    def username(self) -> str | None:
        return self.secret.split(":", 1)[0] if self.scheme == "basic" else None

    def authorization(self) -> str:
        if self.scheme == "basic":
            return "Basic " + base64.b64encode(self.secret.encode()).decode()
        return "Bearer " + self.secret


def credential_from_headers(headers: Mapping[str, str] | None) -> Credential:
    value = (headers or {}).get("authorization") or (headers or {}).get("Authorization")
    if not value:
        raise CredentialMissing(
            "No credential in this request.",
            hint="Behind a hub: store your Stalwart login as 'user@domain:app-password' in the hub's "
            "connections page. Standalone: connect through OAuth.",
        )
    scheme, _, rest = value.strip().partition(" ")
    rest = rest.strip()
    if not rest:
        raise CredentialMissing("Malformed Authorization header.")
    if scheme.lower() == "basic":
        try:
            decoded = base64.b64decode(rest, validate=True).decode()
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise CredentialMissing("Malformed Basic credential.") from exc
        if ":" not in decoded:
            raise CredentialMissing("Basic credential lacks 'user:password'.")
        return Credential("basic", decoded)
    if scheme.lower() == "bearer":
        # @gotcha The hub can only send "Authorization: Bearer <stored value>". A stored
        #         "user:app-password" therefore arrives as a Bearer token with a colon.
        #         Stalwart API keys and OAuth tokens never contain a colon.
        if ":" in rest:
            user, _, password = rest.partition(":")
            if not user or not password:
                raise CredentialMissing("Credential must be 'user@domain:app-password'.")
            return Credential("basic", rest)
        return Credential("bearer", rest)
    raise CredentialMissing(f"Unsupported Authorization scheme '{scheme}'.")


class AuthQuarantine:
    """Remembers credentials that Stalwart rejected, so they are never retried.

    @warn This is the brute-force protection of last resort once this server's IP is on
          Stalwart's allowed-IP list (which exempts it from Stalwart's own bans). A hub
          retries tool calls; without this, one wrong app password turns into a stream
          of failed logins. A changed credential has a new fingerprint and passes again.
    """

    def __init__(self, hold_seconds: float = 3600.0):
        self._hold = hold_seconds
        self._bad: dict[str, float] = {}
        self._lock = threading.Lock()

    def check(self, cred: Credential) -> None:
        with self._lock:
            until = self._bad.get(cred.fingerprint)
            if until is None:
                return
            if until < time.time():
                del self._bad[cred.fingerprint]
                return
        raise AuthRejected(
            "Stalwart rejected this credential earlier; it is not retried.",
            hint="Update the credential (new app password or token). Retries with the same "
            f"credential resume after {time.strftime('%H:%M UTC', time.gmtime(until))}.",
        )

    def mark(self, cred: Credential) -> None:
        with self._lock:
            self._bad[cred.fingerprint] = time.time() + self._hold

    def clear(self) -> None:
        with self._lock:
            self._bad.clear()
