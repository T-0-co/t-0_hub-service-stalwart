"""Runtime configuration, read once from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _csv(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


@dataclass(frozen=True)
class Config:
    stalwart_url: str
    """Base URL of the Stalwart server, e.g. https://mail.example.com (no trailing slash)."""

    max_rps: float = 4.0
    """Request starts per second towards Stalwart, shared by every user of this process.

    @warn Stalwart counts its rate limit per source IP, not per account. Behind a hub,
          all users share one IP and therefore one budget. Keep this below the server
          limit unless the hub IP is on Stalwart's allowed-IP list.
    """

    max_concurrent: int = 4
    """Parallel requests towards Stalwart. Stalwart rejects the request beyond
    `maxConcurrentRequests` immediately (urn:ietf:params:jmap:error:limit), it does not queue."""

    http_timeout: float = 25.0
    max_attachment_bytes: int = 25 * 1024 * 1024
    internal_domains: list[str] = field(default_factory=list)
    """Extra domains that count as "own" for the Sieve redirect guard, in addition to
    the domains of the account's sending identities."""

    allowed_hosts: list[str] = field(default_factory=list)
    """Host header values accepted by the MCP endpoint (DNS rebinding protection).
    Empty means no Host check, which is fine on a private container network."""

    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> Config:
        url = os.environ.get("STALWART_URL", "").strip().rstrip("/")
        if not url:
            raise RuntimeError("STALWART_URL is not set (e.g. https://mail.example.com)")
        return cls(
            stalwart_url=url,
            max_rps=float(os.environ.get("STALWART_MAX_RPS", "4")),
            max_concurrent=int(os.environ.get("STALWART_MAX_CONCURRENT", "4")),
            http_timeout=float(os.environ.get("STALWART_HTTP_TIMEOUT", "25")),
            max_attachment_bytes=int(os.environ.get("STALWART_MAX_ATTACHMENT_BYTES", str(25 * 1024 * 1024))),
            internal_domains=[d.lower() for d in _csv(os.environ.get("STALWART_INTERNAL_DOMAINS"))],
            allowed_hosts=_csv(os.environ.get("MCP_ALLOWED_HOSTS")),
            host=os.environ.get("MCP_HOST", "0.0.0.0"),
            port=int(os.environ.get("PORT", os.environ.get("MCP_PORT", "8000"))),
            log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        )
