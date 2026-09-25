"""Rate limiter, cache, quota and HTTP-backoff tests."""
import time

import httpx
import pytest

from enrichment.cache import InMemoryCache
from enrichment.dispatcher import Dispatcher
from enrichment.entities import Entity, EntityType, Finding
from enrichment.errors import RateLimited
from enrichment.quota import InMemoryQuotaTracker
from enrichment.ratelimit import InMemoryRateLimiter

from conftest import http_for, make_module

EMAIL, USERNAME = EntityType.EMAIL, EntityType.USERNAME


async def test_token_bucket_paces_acquires():
    rl = InMemoryRateLimiter()
    rl.configure("m", rate=20.0, capacity=1.0)  # 1 burst, then 1 per 50ms
    start = time.monotonic()
    for _ in range(3):
        await rl.acquire("m")
    elapsed = time.monotonic() - start
    # first is free (burst), next two wait ~50ms each => >= ~0.09s
    assert elapsed >= 0.08


async def test_cache_hit_avoids_second_call():
    calls = {"n": 0}

    async def h(e):
        calls["n"] += 1
        return [Finding(entity=Entity(USERNAME, "u"), confidence=0.9)]

    m = make_module("m", [EMAIL], [USERNAME], h, cache_ttl_seconds=60)
    cache = InMemoryCache()
    d = Dispatcher([m], cache=cache)
    seed = Entity(EMAIL, "a@b.com")
    r1 = await d.scan(seed, requester_id="r", purpose="t")
    r2 = await d.scan(seed, requester_id="r", purpose="t")
    assert calls["n"] == 1  # second scan served from cache
    assert r2.stats["cache_hits"] >= 1
    assert any(f.entity.value == "u" for f in r2.findings)


async def test_quota_reserve_counts_per_day():
    q = InMemoryQuotaTracker()
    assert await q.reserve("m", limit=2)
    assert await q.reserve("m", limit=2)
    assert not await q.reserve("m", limit=2)
    assert await q.used("m") == 2
    assert await q.reserve("no_limit", limit=None)  # unlimited


async def test_http_retries_429_then_succeeds_honoring_retry_after():
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        if hits["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "0"}, json={"e": 1})
        return httpx.Response(200, json={"ok": True})

    http = http_for(handler)
    status, body = await http.get_json("https://x/test")
    assert status == 200 and body == {"ok": True}
    assert hits["n"] == 2
    await http.aclose()


async def test_http_raises_ratelimited_after_exhausting_retries():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "0"})

    http = http_for(handler)
    with pytest.raises(RateLimited):
        await http.get_json("https://x/test")
    await http.aclose()


async def test_http_retries_5xx():
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        hits["n"] += 1
        return httpx.Response(503 if hits["n"] < 3 else 200, json={"n": hits["n"]})

    http = http_for(handler)
    status, _ = await http.get_json("https://x/test")
    assert status == 200 and hits["n"] == 3
    await http.aclose()
