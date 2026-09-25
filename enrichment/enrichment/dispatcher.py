"""The scan dispatcher: an event-driven, breadth-first enrichment engine.

Flow for one scan:

1. Gate the **seed** against the suppression list; if suppressed, abort before any
   query and log it. Write the scan's audit record (requester, purpose, time).
2. Route the seed only to modules whose ``watched_types`` include its type.
3. For each (module, entity): serve from cache if possible (free); otherwise spend
   one unit of the scan's **request budget**, reserve **daily quota**, wait for the
   module's **rate-limit** token, then call ``handle`` under a **timeout**.
4. Each returned Finding's produced entity is gated against suppression (so nothing
   suppressed is stored or expanded), stored with full provenance, then — if new
   and within ``max_depth`` — fed back into the queue.
5. Failures are contained: a timeout or error skips one lookup; ``QuotaExceeded``
   disables that module for the rest of the scan; nothing aborts the scan except a
   suppressed seed.

Concurrency is a pool of workers over an ``asyncio.Queue``; a slow module ties up
only its own task, never the others.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .cache import Cache, InMemoryCache, cache_key
from .compliance import AuditLog, InMemoryAuditLog, InMemorySuppressionList, ScanAudit, SuppressionList
from .entities import Entity, EntityType, Finding
from .errors import QuotaExceeded, RateLimited, UpstreamError
from .modules.base import EnrichmentModule
from .quota import InMemoryQuotaTracker, QuotaTracker
from .ratelimit import InMemoryRateLimiter, RateLimiter
from .storage import InMemoryStorage, Storage, merge_findings_into_person

log = logging.getLogger("enrichment.dispatcher")


@dataclass
class ScanSettings:
    max_depth: int = 2          # hops from the seed
    max_requests: int = 200     # provider calls per scan (cache hits are free)
    workers: int = 8
    default_timeout: float = 15.0


@dataclass
class ScanResult:
    scan_id: str
    seed: Entity
    findings: list[Finding]
    profile: dict[str, Any]
    stats: dict[str, Any] = field(default_factory=dict)
    aborted: bool = False
    abort_reason: str | None = None


def _serialize(findings: list[Finding]) -> list[dict]:
    return [{"type": f.entity.type.value, "value": f.entity.value,
             "confidence": f.confidence, "label": f.label, "raw": f.raw}
            for f in findings]


def _deserialize(rows: list[dict]) -> list[Finding]:
    out = []
    for r in rows:
        try:
            out.append(Finding(entity=Entity(EntityType(r["type"]), r["value"]),
                               confidence=r.get("confidence", 0.5),
                               label=r.get("label"), raw=r.get("raw") or {}))
        except (KeyError, ValueError):
            continue
    return out


class Dispatcher:
    def __init__(
        self,
        modules: list[EnrichmentModule],
        *,
        cache: Cache | None = None,
        rate_limiter: RateLimiter | None = None,
        quota: QuotaTracker | None = None,
        suppression: SuppressionList | None = None,
        audit: AuditLog | None = None,
        storage: Storage | None = None,
        settings: ScanSettings | None = None,
    ) -> None:
        self.modules = [m for m in modules if m.config.enabled]
        self.cache = cache or InMemoryCache()
        self.rate = rate_limiter or InMemoryRateLimiter()
        self.quota = quota or InMemoryQuotaTracker()
        self.suppression = suppression or InMemorySuppressionList()
        self.audit = audit or InMemoryAuditLog()
        self.storage = storage or InMemoryStorage()
        self.settings = settings or ScanSettings()
        # index modules by watched type for O(1) routing
        self._by_type: dict[EntityType, list[EnrichmentModule]] = {}
        for m in self.modules:
            for t in m.watched_types:
                self._by_type.setdefault(t, []).append(m)
        # auto-configure the in-memory rate limiter from module configs
        if isinstance(self.rate, InMemoryRateLimiter):
            for m in self.modules:
                self.rate.configure(m.name, m.config.requests_per_second, m.config.burst)

    async def scan(
        self,
        seed: Entity,
        *,
        requester_id: str,
        purpose: str,
        max_depth: int | None = None,
        max_requests: int | None = None,
    ) -> ScanResult:
        scan_id = uuid.uuid4().hex
        s = self.settings
        max_depth = s.max_depth if max_depth is None else max_depth
        max_requests = s.max_requests if max_requests is None else max_requests
        started = time.monotonic()

        await self.audit.record_scan_start(ScanAudit(
            scan_id=scan_id, requester_id=requester_id, purpose=purpose,
            seed_type=seed.type.value, seed_value=seed.normalized,
        ))

        # --- per-scan state ---
        self._scan_id = scan_id
        self._seen: set[tuple[str, str]] = set()
        self._findings: list[Finding] = []
        self._disabled: set[str] = set()
        self._requests_made = 0
        self._max_requests = max_requests
        self._max_depth = max_depth
        self._suppressed_count = 0
        self._module_calls: dict[str, int] = {}
        self._cache_hits = 0
        self._queue: asyncio.Queue = asyncio.Queue()

        # Compliance gate on the seed itself: never query a suppressed subject.
        if await self.suppression.is_suppressed(seed):
            await self.audit.record_suppressed(scan_id, seed, "seed")
            summary = {"aborted": "seed_suppressed"}
            await self.audit.record_scan_end(scan_id, summary)
            return ScanResult(scan_id, seed, [], {}, stats=summary,
                              aborted=True, abort_reason="seed_suppressed")

        await self._enqueue(seed, depth=0, parent=None)

        workers = [asyncio.create_task(self._worker()) for _ in range(max(1, s.workers))]
        try:
            await self._queue.join()
        finally:
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

        profile = merge_findings_into_person(seed, self._findings).to_dict()
        stats = {
            "requests_made": self._requests_made,
            "cache_hits": self._cache_hits,
            "entities_seen": len(self._seen),
            "findings": len(self._findings),
            "modules_disabled": sorted(self._disabled),
            "suppressed_entities": self._suppressed_count,
            "module_calls": self._module_calls,
            "duration_seconds": round(time.monotonic() - started, 3),
            "max_depth": max_depth,
            "max_requests": max_requests,
        }
        await self.audit.record_scan_end(scan_id, stats)
        return ScanResult(scan_id, seed, list(self._findings), profile, stats=stats)

    # ------------------------------------------------------------------ helpers

    async def _enqueue(self, entity: Entity, depth: int, parent: Entity | None) -> bool:
        """Dedup + persist a node, then queue it for expansion (within depth)."""
        if entity.key in self._seen:
            return False
        self._seen.add(entity.key)
        await self.storage.persist_entity(self._scan_id, entity, depth, parent)
        if depth <= self._max_depth:
            self._queue.put_nowait((entity, depth, parent))
        return True

    def _reserve_request(self) -> bool:
        # Atomic within the single-threaded event loop (no await between check/incr).
        if self._requests_made >= self._max_requests:
            return False
        self._requests_made += 1
        return True

    async def _worker(self) -> None:
        while True:
            entity, depth, _parent = await self._queue.get()
            try:
                await self._process(entity, depth)
            except asyncio.CancelledError:  # pragma: no cover
                raise
            except Exception:  # a module bug must not kill the worker
                log.exception("unexpected error processing %s", entity)
            finally:
                self._queue.task_done()

    async def _process(self, entity: Entity, depth: int) -> None:
        for module in self._by_type.get(entity.type, ()):
            if module.name in self._disabled:
                continue

            key = cache_key(module.name, entity)
            cached = await self.cache.get(key)
            if cached is not None:
                self._cache_hits += 1
                await self._record(module.name, entity, _deserialize(cached), depth)
                continue

            # Budget gate (a real provider call is about to happen).
            if not self._reserve_request():
                log.info("scan %s request budget reached; skipping %s for %s",
                         self._scan_id, module.name, entity)
                continue

            # Quota gate; refund the budget slot if the module is out of quota.
            if not await self.quota.reserve(module.name, module.config.daily_quota):
                self._requests_made -= 1
                self._disable(module.name, "quota")
                continue

            await self.rate.acquire(module.name)

            timeout = module.config.timeout_seconds or self.settings.default_timeout
            try:
                findings = await asyncio.wait_for(module.handle(entity), timeout)
            except asyncio.TimeoutError:
                log.warning("scan %s module %s timed out on %s", self._scan_id, module.name, entity)
                continue
            except QuotaExceeded:
                self._disable(module.name, "quota_upstream")
                continue
            except RateLimited as exc:
                log.warning("scan %s module %s rate-limited on %s (retry_after=%s); skipping",
                            self._scan_id, module.name, entity, exc.retry_after)
                continue
            except UpstreamError as exc:
                log.warning("scan %s module %s upstream error on %s: %s",
                            self._scan_id, module.name, entity, exc)
                continue
            except Exception:
                log.exception("scan %s module %s crashed on %s", self._scan_id, module.name, entity)
                continue

            self._module_calls[module.name] = self._module_calls.get(module.name, 0) + 1
            await self.cache.set(key, _serialize(findings), module.config.cache_ttl_seconds)
            await self._record(module.name, entity, findings, depth)

    async def _record(self, module_name: str, parent: Entity, findings: list[Finding], depth: int) -> None:
        for f in findings:
            produced = f.entity
            # Compliance gate: never store or expand a suppressed entity.
            if await self.suppression.is_suppressed(produced):
                self._suppressed_count += 1
                await self.audit.record_suppressed(self._scan_id, produced, "produced")
                continue
            stamped = f.stamped(module=module_name, parent=parent)
            await self.storage.persist_finding(self._scan_id, stamped)
            self._findings.append(stamped)
            await self._enqueue(produced, depth + 1, parent)

    def _disable(self, module_name: str, reason: str) -> None:
        if module_name not in self._disabled:
            self._disabled.add(module_name)
            log.info("scan %s disabling module %s for rest of scan (%s)",
                     self._scan_id, module_name, reason)
