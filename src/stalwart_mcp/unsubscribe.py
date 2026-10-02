"""List-Unsubscribe handling (RFC 2369, one-click per RFC 8058).

@warn The one-click POST goes from this server to a URL chosen by the sender of the
      mail. Without checks that is a server-side request forgery primitive: a crafted
      header could point at the hub, the Docker network or cloud metadata endpoints.
      Only https URLs whose host resolves exclusively to public addresses are called,
      redirects are not followed, and the response body is ignored.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import httpx

from .errors import Refused

ONE_CLICK_BODY = "List-Unsubscribe=One-Click"


def parse_header(urls: list[str] | None, post_header: str | None) -> dict[str, Any]:
    """Split List-Unsubscribe URLs into https/mailto and detect one-click support."""
    https = [u for u in urls or [] if u.lower().startswith("https://")]
    http = [u for u in urls or [] if u.lower().startswith("http://")]
    mailto = [u for u in urls or [] if u.lower().startswith("mailto:")]
    one_click = bool(post_header and "list-unsubscribe=one-click" in post_header.replace(" ", "").lower())
    return {"https": https, "http": http, "mailto": mailto, "one_click": one_click and bool(https)}


def parse_mailto(url: str) -> dict[str, str]:
    parts = urlsplit(url)
    to = unquote(parts.path)
    query = {k.lower(): v[0] for k, v in parse_qs(parts.query).items() if v}
    return {"to": to, "subject": query.get("subject", "unsubscribe"), "body": query.get("body", "unsubscribe")}


async def _assert_public_host(host: str) -> None:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        candidates = [ip]
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise Refused(f"Cannot resolve unsubscribe host '{host}'.") from exc
        candidates = [ipaddress.ip_address(info[4][0]) for info in infos]
    if not candidates or any(not c.is_global for c in candidates):
        raise Refused(
            f"Unsubscribe host '{host}' resolves to a non-public address; refusing to call it.",
            hint="This protects the internal network. Unsubscribe manually if the mail is genuine.",
        )


async def one_click(url: str, *, timeout: float = 10.0, client: httpx.AsyncClient | None = None) -> dict[str, Any]:
    """POST the RFC 8058 one-click body. Returns status information, never the response body.

    @gotcha DNS is checked before the request and resolved again by the HTTP client, so a
            hostile DNS server could still answer differently the second time (rebinding).
            Acceptable for this use; the request carries no credentials and the body is
            discarded.
    """
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise Refused("Only https one-click unsubscribe URLs are called automatically.")
    if parts.username or parts.password:
        raise Refused("Unsubscribe URL contains credentials; refusing.")
    await _assert_public_host(parts.hostname)
    own = client is None
    http = client or httpx.AsyncClient(timeout=timeout, follow_redirects=False, headers={"User-Agent": "stalwart-mcp"})
    try:
        resp = await http.post(
            url,
            content=ONE_CLICK_BODY.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        return {"ok": False, "status": None, "error": type(exc).__name__}
    finally:
        if own:
            await http.aclose()
    status = resp.status_code
    return {
        "ok": 200 <= status < 300,
        "status": status,
        "redirect": resp.headers.get("location") if 300 <= status < 400 else None,
    }
