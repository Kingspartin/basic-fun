"""Daily quota tracking.

Rate limiting caps *throughput*; quota caps *total daily volume* (the number a
provider bills or cuts off at). ``reserve`` atomically counts one unit against
today's budget and returns whether it was granted. When it is not, the dispatcher
disables that module for the rest of the scan and logs it — the scan continues
with the remaining sources.

The counter resets by calendar day in UTC (key includes the date). This is a
best-effort mirror of the provider's own accounting; the provider remains the
source of truth, and a module that sees a real quota response should raise
:class:`~enrichment.errors.QuotaExceeded`.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d")


@runtime_checkable
class QuotaTracker(Protocol):
    async def reserve(self, module: str, limit: int | None, n: int = 1) -> bool: ...
    async def used(self, module: str) -> int: ...


class InMemoryQuotaTracker:
    def __init__(self) -> None:
        self._counts: dict[tuple[str, str], int] = {}
        self._lock = asyncio.Lock()

    async def reserve(self, module: str, limit: int | None, n: int = 1) -> bool:
        if limit is None:  # no quota configured => unlimited
            return True
        key = (module, _today())
        async with self._lock:
            cur = self._counts.get(key, 0)
            if cur + n > limit:
                return False
            self._counts[key] = cur + n
            return True

    async def used(self, module: str) -> int:
        return self._counts.get((module, _today()), 0)


class RedisQuotaTracker:
    """Daily quota across workers. ``redis`` is an async redis client."""

    def __init__(self, redis, prefix: str = "enrich:quota:") -> None:
        self._redis = redis
        self._prefix = prefix

    def _key(self, module: str) -> str:
        return f"{self._prefix}{module}:{_today()}"

    async def reserve(self, module: str, limit: int | None, n: int = 1) -> bool:
        if limit is None:
            return True
        key = self._key(module)
        # INCR then compare; roll back on overshoot so we never exceed the cap.
        cur = await self._redis.incrby(key, n)
        if cur == n:
            await self._redis.expire(key, 172800)  # keep 2 days for observability
        if cur > limit:
            await self._redis.decrby(key, n)
            return False
        return True

    async def used(self, module: str) -> int:
        v = await self._redis.get(self._key(module))
        return int(v) if v else 0
