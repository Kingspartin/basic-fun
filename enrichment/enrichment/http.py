"""Shared async HTTP client with resilient retries.

All modules go through one client so retry policy, timeouts and the User-Agent are
consistent. Behavior:

* Per-request timeout (so one slow provider never blocks the scan; the dispatcher
  also wraps each module call in its own timeout as a backstop).
* Retry on 429 and 5xx with exponential backoff **plus full jitter**; a 429 (or
  503) ``Retry-After`` header is honored when present.
* 429 that survives all retries surfaces as :class:`RateLimited`; other 4xx as
  :class:`UpstreamError` (not retried). Modules decide what a given status *means*
  for their provider (e.g. 404 = "no data", not an error).

Only official provider APIs are called. There is deliberately no proxy pool and no
key rotation: working around a provider's rate limits or ToS is out of scope.
"""
from __future__ import annotations

import asyncio
import random
from typing import Any, Mapping

import httpx

from .errors import RateLimited, UpstreamError

DEFAULT_UA = "PeopleScope-Enrichment/1.0 (+compliance: official-APIs-only)"


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))  # delta-seconds form
    except ValueError:
        try:
            from email.utils import parsedate_to_datetime
            from datetime import datetime, timezone
            when = parsedate_to_datetime(value)
            return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError):
            return None


class HttpClient:
    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        *,
        max_retries: int = 3,
        base_backoff: float = 0.5,
        max_backoff: float = 20.0,
        user_agent: str = DEFAULT_UA,
    ) -> None:
        self._client = client or httpx.AsyncClient(
            headers={"User-Agent": user_agent}, follow_redirects=True
        )
        self._owned = client is None
        self.max_retries = max_retries
        self.base_backoff = base_backoff
        self.max_backoff = max_backoff

    async def aclose(self) -> None:
        if self._owned:
            await self._client.aclose()

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        timeout: float = 15.0,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        auth: tuple[str, str] | None = None,
    ) -> httpx.Response:
        attempt = 0
        while True:
            try:
                resp = await self._client.request(
                    method, url, headers=headers, params=params, json=json,
                    auth=auth, timeout=timeout,
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if attempt >= self.max_retries:
                    raise UpstreamError(f"network error: {exc}") from exc
                await self._sleep_backoff(attempt)
                attempt += 1
                continue

            if resp.status_code == 429 or resp.status_code >= 500:
                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                if attempt >= self.max_retries:
                    if resp.status_code == 429:
                        raise RateLimited("429 after retries", retry_after=retry_after)
                    raise UpstreamError(f"{resp.status_code} after retries", status=resp.status_code)
                await self._sleep_backoff(attempt, retry_after)
                attempt += 1
                continue

            return resp

    async def get_json(self, url: str, **kw) -> tuple[int, Any]:
        resp = await self.request("GET", url, **kw)
        return resp.status_code, self._json_or_none(resp)

    @staticmethod
    def _json_or_none(resp: httpx.Response) -> Any:
        try:
            return resp.json()
        except (ValueError, UnicodeDecodeError):
            return None

    async def _sleep_backoff(self, attempt: int, retry_after: float | None = None) -> None:
        if retry_after is not None:
            await asyncio.sleep(min(retry_after, self.max_backoff))
            return
        # Exponential backoff with full jitter: sleep in [0, min(cap, base*2^n)].
        ceiling = min(self.max_backoff, self.base_backoff * (2 ** attempt))
        await asyncio.sleep(random.uniform(0, ceiling))
