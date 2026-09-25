"""Per-module token-bucket rate limiting.

Each module gets its own bucket sized to the provider's documented limits, so one
chatty provider cannot starve the others and we never exceed what a provider
allows. The in-memory bucket is correct within one process; the Redis bucket is
correct across many workers/processes via an atomic Lua refill-and-take.
"""
from __future__ import annotations

import asyncio
import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class RateLimiter(Protocol):
    async def acquire(self, module: str, tokens: int = 1) -> None: ...


class _Bucket:
    __slots__ = ("rate", "capacity", "tokens", "updated", "lock")

    def __init__(self, rate: float, capacity: float):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()


class InMemoryRateLimiter:
    """Token bucket per module. ``rate`` = tokens/sec, ``capacity`` = burst."""

    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = {}

    def configure(self, module: str, rate: float, capacity: float | None = None) -> None:
        cap = capacity if capacity is not None else max(1.0, rate)
        self._buckets[module] = _Bucket(rate, cap)

    async def acquire(self, module: str, tokens: int = 1) -> None:
        b = self._buckets.get(module)
        if b is None:  # unconfigured module: default to 1 rps, burst 1
            b = self._buckets[module] = _Bucket(1.0, 1.0)
        while True:
            async with b.lock:
                now = time.monotonic()
                elapsed = now - b.updated
                b.updated = now
                b.tokens = min(b.capacity, b.tokens + elapsed * b.rate)
                if b.tokens >= tokens:
                    b.tokens -= tokens
                    return
                deficit = tokens - b.tokens
                wait = deficit / b.rate if b.rate > 0 else 0.05
            await asyncio.sleep(wait)


# Refill-then-take, atomically. Returns wait-seconds (0 = took the tokens).
_REDIS_LUA = """
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local cap = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local want = tonumber(ARGV[4])
local st = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(st[1])
local ts = tonumber(st[2])
if tokens == nil then tokens = cap; ts = now end
local delta = math.max(0, now - ts)
tokens = math.min(cap, tokens + delta * rate)
if tokens >= want then
  tokens = tokens - want
  redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
  redis.call('PEXPIRE', key, math.ceil((cap / rate) * 1000) + 1000)
  return 0
else
  redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
  redis.call('PEXPIRE', key, math.ceil((cap / rate) * 1000) + 1000)
  return tostring((want - tokens) / rate)
end
"""


class RedisRateLimiter:
    """Distributed token bucket. ``redis`` is an async redis client (redis.asyncio)."""

    def __init__(self, redis, prefix: str = "enrich:rl:") -> None:
        self._redis = redis
        self._prefix = prefix
        self._cfg: dict[str, tuple[float, float]] = {}
        self._sha: str | None = None

    def configure(self, module: str, rate: float, capacity: float | None = None) -> None:
        self._cfg[module] = (rate, capacity if capacity is not None else max(1.0, rate))

    async def _script(self):
        if self._sha is None:
            self._sha = await self._redis.script_load(_REDIS_LUA)
        return self._sha

    async def acquire(self, module: str, tokens: int = 1) -> None:
        rate, cap = self._cfg.get(module, (1.0, 1.0))
        sha = await self._script()
        while True:
            wait = await self._redis.evalsha(
                sha, 1, f"{self._prefix}{module}", rate, cap, time.time(), tokens
            )
            wait = float(wait)
            if wait <= 0:
                return
            await asyncio.sleep(min(wait, 5.0))
