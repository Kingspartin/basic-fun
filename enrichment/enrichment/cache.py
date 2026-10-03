"""Response cache keyed by (module, entity), with a per-module TTL.

Caching cuts cost and load and makes a re-scan of the same subject cheap. A hit
does not count against the scan's request budget or the module's quota, because
no provider call is made. Cached payloads are the module's already-parsed
``list[Finding]`` serialized to plain dicts.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Protocol, runtime_checkable

from .entities import Entity


def cache_key(module: str, entity: Entity) -> str:
    return f"{module}|{entity.cache_token()}"


@runtime_checkable
class Cache(Protocol):
    async def get(self, key: str) -> Any | None: ...
    async def set(self, key: str, value: Any, ttl_seconds: int) -> None: ...


class InMemoryCache:
    def __init__(self) -> None:
        self._store: dict[str, tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Any | None:
        async with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            expires, value = item
            if expires < time.time():
                self._store.pop(key, None)
                return None
            return value

    async def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        async with self._lock:
            self._store[key] = (time.time() + ttl_seconds, value)


class RedisCache:
    def __init__(self, redis, prefix: str = "enrich:cache:") -> None:
        self._redis = redis
        self._prefix = prefix

    async def get(self, key: str) -> Any | None:
        raw = await self._redis.get(self._prefix + key)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return None

    async def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        await self._redis.set(self._prefix + key, json.dumps(value), ex=ttl_seconds)


class PostgresCache:
    """Cache table with ``expires_at`` (see schema.sql). ``pool`` is asyncpg."""

    def __init__(self, pool) -> None:
        self._pool = pool

    async def get(self, key: str) -> Any | None:
        row = await self._pool.fetchval(
            "SELECT payload FROM enrichment_cache WHERE cache_key = $1 AND expires_at > now()",
            key,
        )
        if row is None:
            return None
        return json.loads(row) if isinstance(row, str) else row

    async def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        await self._pool.execute(
            """INSERT INTO enrichment_cache (cache_key, payload, expires_at)
               VALUES ($1, $2, now() + ($3 || ' seconds')::interval)
               ON CONFLICT (cache_key) DO UPDATE
                 SET payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at""",
            key, json.dumps(value), str(ttl_seconds),
        )
