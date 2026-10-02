"""Process-wide request pacing towards Stalwart."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from .errors import IpBlocked


class Throttle:
    """Fixed minimum spacing between request starts, plus a concurrency cap.

    Deliberately not a token bucket: a bucket allows bursts, and a burst is what an
    IP ban reacts to. Every request gets its own start slot instead.

    @gotcha The slot is reserved under the lock and slept on outside of it. The other
            way round serialises the waiting time as well, and 4/s turns into
            1 / (0.25 s + request duration).
    """

    def __init__(self, rps: float, concurrent: int):
        self._interval = 1.0 / rps if rps > 0 else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()
        self._sem = asyncio.Semaphore(max(1, concurrent))
        self._blocked_until = 0.0

    def trip(self, seconds: float) -> None:
        """Stop all traffic for a while, e.g. after a response that looks like an IP ban."""
        self._blocked_until = max(self._blocked_until, time.monotonic() + seconds)

    def check_open(self) -> None:
        remaining = self._blocked_until - time.monotonic()
        if remaining > 0:
            raise IpBlocked(
                "Paused: Stalwart recently answered like it blocks this server's IP.",
                hint=f"No requests for another {int(remaining)} s. Check Stalwart's blocked IPs and put "
                "this server's IP on the allowed list.",
            )

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        async with self._sem:
            if self._interval > 0:
                async with self._lock:
                    now = time.monotonic()
                    start = max(now, self._next)
                    self._next = start + self._interval
                delay = start - now
                if delay > 0:
                    await asyncio.sleep(delay)
            yield
