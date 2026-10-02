"""Async JMAP client for Stalwart (RFC 8620/8621 plus Stalwart's management objects).

Operating rules, all learned against a production Stalwart (0.16):

@warn   Authentication failures are never retried (see errors.AuthRejected). Stalwart
        bans the source IP for every account behind it, and a banned IP looks like a
        broken server: TCP connects, TLS is reset.
@gotcha HTTP 429 is ambiguous: throttling (harmless, retry once after a pause) or a
        brute-force ban (stop). The body tells them apart; when in doubt, assume a ban.
@gotcha A bad `sinceState` on Email/changes answers HTTP 400 for the WHOLE request, not
        as a method error, and takes down every other call batched with it. Changes
        calls therefore always go alone (`isolated=True`), and both the 400 and the
        method error `cannotCalculateChanges` mean "full resync needed".
@gotcha The request beyond `maxConcurrentRequests` is rejected immediately
        (urn:ietf:params:jmap:error:limit), not queued. Hence the semaphore in Throttle
        and a short backoff on that error.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import httpx

from .config import Config
from .credentials import AuthQuarantine, Credential
from .errors import (
    AuthRejected,
    IpBlocked,
    MethodError,
    RateLimited,
    ResyncRequired,
    StalwartError,
    Unreachable,
)
from .throttle import Throttle

CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"
SUBMISSION = "urn:ietf:params:jmap:submission"
VACATION = "urn:ietf:params:jmap:vacationresponse"
SIEVE = "urn:ietf:params:jmap:sieve"
QUOTA = "urn:ietf:params:jmap:quota"
BLOB = "urn:ietf:params:jmap:blob"
MANAGEMENT = "urn:stalwart:jmap"

SESSION_TTL = 300.0
RATE_BACKOFF_SECONDS = 5.0
BAN_PAUSE_SECONDS = 600.0

Call = tuple[str, dict[str, Any], str]


def _looks_like_ban(body: str) -> bool:
    """Does a 429 body look like a ban rather than throttling?

    @gotcha When in doubt answer True. Reading a ban as throttling causes one more
            attempt, and extra attempts are exactly what extends a ban.
    """
    b = body.lower()
    if any(word in b for word in ("blocked", "banned", "too many auth", "brute")):
        return True
    return not any(word in b for word in ("ratelimit", "rate limit", "error:limit", "too many requests"))


@dataclass
class Session:
    raw: dict[str, Any]
    fetched_at: float = field(default_factory=time.monotonic)

    @property
    def api_url(self) -> str:
        return self.raw["apiUrl"]

    @property
    def username(self) -> str:
        return self.raw.get("username", "")

    @property
    def accounts(self) -> dict[str, dict[str, Any]]:
        return self.raw.get("accounts", {})

    @property
    def capabilities(self) -> dict[str, Any]:
        return self.raw.get("capabilities", {})

    def has(self, capability: str) -> bool:
        return capability in self.capabilities

    def primary(self, capability: str) -> str | None:
        return self.raw.get("primaryAccounts", {}).get(capability)

    def core_limit(self, name: str, default: int) -> int:
        value = self.capabilities.get(CORE, {}).get(name)
        return int(value) if isinstance(value, int) and value > 0 else default

    def account_has(self, account_id: str, capability: str) -> bool:
        return capability in self.accounts.get(account_id, {}).get("accountCapabilities", {})

    def download_url(self, account_id: str, blob_id: str, name: str, mime: str) -> str:
        return (
            self.raw["downloadUrl"]
            .replace("{accountId}", quote(account_id, safe=""))
            .replace("{blobId}", quote(blob_id, safe=""))
            .replace("{name}", quote(name or "file", safe=""))
            .replace("{type}", quote(mime or "application/octet-stream", safe=""))
        )

    def upload_url(self, account_id: str) -> str:
        return self.raw["uploadUrl"].replace("{accountId}", quote(account_id, safe=""))


class Responses:
    """Method responses of one JMAP request, addressable by call id."""

    def __init__(self, raw: list[list[Any]]):
        self.raw = raw

    def all(self, call_id: str) -> list[tuple[str, dict[str, Any]]]:
        return [(name, args) for name, args, cid in self.raw if cid == call_id]

    def get(self, call_id: str, method: str | None = None) -> dict[str, Any]:
        """Arguments of the response for `call_id`. Raises MethodError on an error response."""
        for name, args in self.all(call_id):
            if name == "error":
                raise MethodError(method or call_id, args.get("type", "unknown"), args.get("description"))
            if method is None or name == method:
                return args
        raise StalwartError(f"No response for call '{call_id}'" + (f" ({method})" if method else ""))

    def error(self, call_id: str) -> dict[str, Any] | None:
        for name, args in self.all(call_id):
            if name == "error":
                return args
        return None


class Runtime:
    """Process-wide shared state: HTTP pool, pacing, quarantine and caches."""

    def __init__(self, config: Config, http: httpx.AsyncClient | None = None):
        self.config = config
        self.http = http or httpx.AsyncClient(
            timeout=httpx.Timeout(config.http_timeout),
            follow_redirects=True,
            headers={"User-Agent": "stalwart-mcp"},
        )
        self.throttle = Throttle(config.max_rps, config.max_concurrent)
        self.quarantine = AuthQuarantine()
        self.sessions: dict[str, Session] = {}
        self.cache: dict[tuple[str, str, str], tuple[float, Any]] = {}

    def cache_get(self, key: tuple[str, str, str], ttl: float) -> Any | None:
        hit = self.cache.get(key)
        if hit and time.monotonic() - hit[0] < ttl:
            return hit[1]
        return None

    def cache_put(self, key: tuple[str, str, str], value: Any) -> None:
        self.cache[key] = (time.monotonic(), value)

    def cache_drop(self, fingerprint: str, kind: str | None = None) -> None:
        for key in list(self.cache):
            if key[0] == fingerprint and (kind is None or key[2] == kind):
                del self.cache[key]

    async def aclose(self) -> None:
        await self.http.aclose()


class Jmap:
    """One credential's view of the server. Cheap to create per tool call."""

    def __init__(self, runtime: Runtime, credential: Credential):
        self.rt = runtime
        self.cred = credential
        self.base_url = runtime.config.stalwart_url

    # ------------------------------------------------------------------ transport

    async def _send(
        self,
        method: str,
        url: str,
        *,
        json: Any = None,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
        isolated: bool = False,
    ) -> httpx.Response:
        self.rt.throttle.check_open()
        self.rt.quarantine.check(self.cred)
        hdrs = {"Authorization": self.cred.authorization(), **(headers or {})}
        attempt = 0
        while True:
            attempt += 1
            async with self.rt.throttle.slot():
                try:
                    resp = await self.rt.http.request(method, url, json=json, content=content, headers=hdrs)
                except httpx.TimeoutException as exc:
                    raise Unreachable(f"Timeout talking to Stalwart ({type(exc).__name__}).") from exc
                except httpx.TransportError as exc:
                    raise Unreachable(
                        f"Cannot reach Stalwart: {type(exc).__name__}.",
                        hint="If TLS is reset right after connecting, Stalwart is probably blocking this "
                        "server's IP (check its blocked IPs).",
                    ) from exc
            status = resp.status_code
            if status < 400:
                return resp
            body = resp.text[:2000]
            if status in (401, 403):
                self.rt.quarantine.mark(self.cred)
                self.rt.sessions.pop(self.cred.fingerprint, None)
                raise AuthRejected(
                    f"Stalwart rejected the credential (HTTP {status}).",
                    hint="Check user name and app password / token. It will not be retried.",
                )
            if status == 429:
                if _looks_like_ban(body):
                    self.rt.throttle.trip(BAN_PAUSE_SECONDS)
                    raise IpBlocked(
                        "Stalwart answered 429 like an IP or account ban.",
                        hint="Put this server's IP on Stalwart's allowed-IP list, or wait for the ban to expire.",
                        details={"body": body[:200]},
                    )
                if attempt == 1:
                    await asyncio.sleep(RATE_BACKOFF_SECONDS)
                    continue
                raise RateLimited("Stalwart is throttling requests (HTTP 429).", details={"body": body[:200]})
            if status == 503 or "error:limit" in body:
                if attempt <= 3:
                    await asyncio.sleep(0.4 * 2 ** (attempt - 1))
                    continue
                raise RateLimited(f"Stalwart is at its concurrency limit (HTTP {status}).")
            if status == 400 and isolated:
                raise ResyncRequired("Stalwart rejected the state token (HTTP 400).")
            raise StalwartError(f"Stalwart answered HTTP {status}.", details={"body": body[:400]})

    async def session(self, refresh: bool = False) -> Session:
        cached = self.rt.sessions.get(self.cred.fingerprint)
        if cached and not refresh and time.monotonic() - cached.fetched_at < SESSION_TTL:
            return cached
        # @gotcha /.well-known/jmap answers 307; the client follows redirects.
        resp = await self._send("GET", f"{self.base_url}/.well-known/jmap")
        session = Session(resp.json())
        self.rt.sessions[self.cred.fingerprint] = session
        return session

    async def call(self, calls: Sequence[Call], using: Iterable[str], *, isolated: bool = False) -> Responses:
        session = await self.session()
        max_calls = session.core_limit("maxCallsInRequest", 16)
        if len(calls) > max_calls:
            raise StalwartError(f"Internal: {len(calls)} calls exceed maxCallsInRequest={max_calls}.")
        payload = {
            "using": sorted({CORE, *using}),
            "methodCalls": [[name, args, cid] for name, args, cid in calls],
        }
        resp = await self._send("POST", session.api_url, json=payload, isolated=isolated)
        data = resp.json()
        if "methodResponses" not in data:
            raise StalwartError("Malformed JMAP response.", details={"type": data.get("type")})
        return Responses(data["methodResponses"])

    async def one(self, method: str, args: dict[str, Any], using: Iterable[str], **kw: Any) -> dict[str, Any]:
        return (await self.call([(method, args, "c0")], using, **kw)).get("c0", method)

    async def download(
        self,
        account_id: str,
        blob_id: str,
        *,
        name: str = "file",
        mime: str = "application/octet-stream",
        max_bytes: int | None = None,
    ) -> bytes:
        """Fetch a blob through the session's downloadUrl (not JSON, but paced like any request)."""
        session = await self.session()
        resp = await self._send("GET", session.download_url(account_id, blob_id, name, mime))
        data = resp.content
        if max_bytes is not None and len(data) > max_bytes:
            raise StalwartError(f"Blob is larger than the limit of {max_bytes} bytes.")
        return data

    async def upload(self, account_id: str, data: bytes, mime: str) -> dict[str, Any]:
        session = await self.session()
        resp = await self._send("POST", session.upload_url(account_id), content=data, headers={"Content-Type": mime})
        return resp.json()

    # ------------------------------------------------------------------ helpers

    async def account_id(self, account: str | None, capability: str = MAIL) -> str:
        """Resolve an account id from an id, a name, or the primary account for `capability`."""
        session = await self.session()
        if not account:
            primary = session.primary(capability)
            if primary:
                return primary
            raise StalwartError(f"This credential has no primary account for {capability}.")
        if account in session.accounts:
            return account
        wanted = account.strip().lower()
        matches = [aid for aid, acc in session.accounts.items() if acc.get("name", "").lower() == wanted]
        if len(matches) == 1:
            return matches[0]
        names = sorted(acc.get("name", aid) for aid, acc in session.accounts.items())
        raise StalwartError(f"Unknown account '{account}'.", hint=f"Accessible accounts: {', '.join(names)}")


def ref(call_id: str, method: str, path: str) -> dict[str, str]:
    """A JMAP result reference (RFC 8620 §3.7)."""
    return {"resultOf": call_id, "name": method, "path": path}
