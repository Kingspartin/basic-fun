# Enrichment layer

A modular, event-driven, multi-source enrichment engine in the SpiderFoot mould:
give it one seed identifier and it fans out across data-source **modules**, feeds
what it discovers back into the queue, and returns a merged person profile where
every fact is traceable to the module and parent identifier that produced it.

It is a **separate backend package** (`enrichment/`). It does not touch the
single-file `peoplesearch.html` launcher; it is meant to sit behind your existing
search API.

## Why this shape

Everything cross-cutting — routing, dedup, rate limiting, quota, caching, retries,
compliance — lives in the dispatcher. A module only translates one provider's
response into findings. Adding a source is: write one class, register it.

```
seed ─▶ dispatcher ─▶ module(s) watching the seed's type
             ▲                    │
             └──── new entities ──┘   (deduped, depth- and budget-limited)
```

## Layout

| File | Responsibility |
|---|---|
| `entities.py` | `Entity` (typed, normalized identifier) and `Finding` (produced entity + confidence + provenance) |
| `modules/base.py` | `EnrichmentModule` interface + `ModuleConfig` (key, rps, burst, daily quota, timeout, TTL) |
| `modules/*.py` | Source adapters: `hibp`, `hunter`, `dns_rdap`, `gravatar_github` |
| `dispatcher.py` | The scan engine: routing, dedup, depth/budget caps, timeouts, compliance gates |
| `ratelimit.py` | Per-module token bucket (in-memory + Redis Lua) |
| `quota.py` | Daily quota counter (in-memory + Redis) |
| `cache.py` | Response cache per `(module, entity)` with TTL (in-memory + Redis + Postgres) |
| `http.py` | Shared async client: backoff + full jitter, `Retry-After`, per-request timeout |
| `compliance.py` | Suppression/opt-out list + audit log (in-memory + Postgres) |
| `storage.py` | Persist entities/findings; `merge_findings_into_person` |
| `config.py` | `build_modules` / `build_dispatcher` wiring (picks Redis/Postgres or in-memory) |
| `api.py` | FastAPI router to drop into your app |
| `schema.sql` | Postgres DDL |

## Module interface

```python
class EnrichmentModule:
    name: str
    watched_types: frozenset[EntityType]   # inputs it accepts
    produced_types: frozenset[EntityType]  # what it can emit
    requires_api_key: bool
    async def handle(self, entity: Entity) -> list[Finding]: ...
```

`handle` returns `Finding` objects (each wrapping a produced `Entity` plus a
confidence score and the raw provider payload) rather than bare entities, so
provenance and confidence attach at the moment of production. The dispatcher stamps
`module`, `parent` and `timestamp` — a module cannot forge its own provenance.
Return `[]` for "queried successfully, nothing found". Raise `RateLimited`,
`QuotaExceeded` or `UpstreamError` instead of swallowing them so the dispatcher can
react.

## Dispatcher guarantees

- **Routing** — an entity only reaches modules whose `watched_types` include its type.
- **Dedup** — entities are keyed by `(type, normalized_value)`; each is queried once
  per scan. Normalization folds Gmail dots/tags, `+1` NANP phones, `www.`/scheme on
  domains, etc.
- **Depth & budget** — `max_depth` hops from the seed; `max_requests` provider calls
  per scan (cache hits are free and never counted).
- **Rate limiting** — per-module token bucket sized to the provider's documented
  limits; one chatty provider can't starve the others.
- **Resilience** — exponential backoff with full jitter on 429/5xx, honoring
  `Retry-After`; per-request timeout; a module error/timeout skips one lookup;
  `QuotaExceeded` disables that module for the rest of the scan and logs it. Only a
  suppressed **seed** aborts the scan.
- **Caching** — responses cached per `(module, entity)` with a per-module TTL.
- **Provenance** — every finding stores source module, timestamp, confidence and the
  parent entity that led to it. `merge_findings_into_person` folds them into a
  profile; agreement between independent sources raises confidence (capped at 1.0).

### Concurrency caveat

The scan runs a pool of workers. "Disable module for the rest of the scan" stops
*subsequent* calls; calls already in flight when a `QuotaExceeded` fires may still
complete (at most `workers - 1` extra). Set `workers=1` if you need strict
serialization. The request-budget counter is exact.

## Compliance (built in, not optional)

1. **Suppression / opt-out** — every seed *and* every discovered/produced entity is
   checked against the suppression list before it is queried or stored. A suppressed
   seed aborts the scan; a suppressed discovered entity is dropped and logged.
2. **Audit log** — each scan records requester ID, stated purpose, seed and outcome
   (start and end). Suppression hits are logged with the stage they occurred at.
3. **Official sources only** — modules call documented provider APIs under their
   terms. There is deliberately **no** proxy/IP pool and **no** API-key rotation;
   working around a provider's rate limits or ToS is out of scope. Don't add a module
   that scrapes a site whose terms forbid it.

The API layer **requires** `requester_id` (from your auth, not the request body) and
a `purpose` string on every scan.

## Initial modules

| Module | Watches | Produces | Key | Notes |
|---|---|---|---|---|
| `hibp` | email | breach | required | Official HIBP API v3; 404 = no breaches |
| `hunter` | domain | email, full_name, organization | required | `domain-search`; carries Hunter's per-email confidence |
| `dns_rdap` | domain | domain, organization, email | none | Google DoH (MX) + rdap.org (registration) |
| `gravatar` | email | full_name, url, account, image | none | Public Gravatar profile JSON |
| `github` | username, email | full_name, location, organization, url, email, account, image, username | optional token | REST API; token only raises rate limits |

## Usage

```python
from enrichment import build_dispatcher, Entity, EntityType, ScanSettings

dispatcher = build_dispatcher(
    module_config={"hibp": {"api_key": HIBP_KEY}, "hunter": {"api_key": HUNTER_KEY}},
    settings=ScanSettings(max_depth=2, max_requests=100),
    redis=redis_client,     # optional; omit for in-memory
    pg_pool=asyncpg_pool,   # optional; omit for in-memory
)

result = await dispatcher.scan(
    Entity(EntityType.EMAIL, "person@example.com"),
    requester_id="analyst-42", purpose="fraud review, case #123",
)
result.profile    # merged attributes with provenance
result.findings   # every finding, each traceable to module + parent
result.stats      # requests, cache hits, disabled modules, timings
```

### FastAPI

```python
from enrichment import build_dispatcher
from enrichment.api import make_router

dispatcher = build_dispatcher(redis=redis, pg_pool=pool, module_config=CONFIG)
app.include_router(make_router(dispatcher, person_repo=my_repo,
                               requester_dep=my_auth_dependency))
```

`POST /enrichment/scan` runs a scan; `GET /enrichment/modules` lists what's enabled.
Replace `resolve_requester` with your auth dependency so the audit trail records the
real principal.

## Configuration

Per-module fields (`ModuleConfig`): `enabled`, `api_key`, `requests_per_second`,
`burst`, `daily_quota`, `timeout_seconds`, `cache_ttl_seconds`. Defaults come from
`config.DEFAULT_LIMITS` and env vars `ENRICH_<NAME>_API_KEY` /
`ENRICH_<NAME>_ENABLED`; override per deployment to match your plan's documented
limits. Set `daily_quota` to your plan cap so the layer stops a module locally
before the provider bills or blocks you.

## Adding a module

1. Subclass `EnrichmentModule`, set `name`/`watched_types`/`produced_types`,
   implement `handle`.
2. Register it in `modules/__init__.py`.
3. Add rate/quota defaults in `config.DEFAULT_LIMITS`.
4. Only call official APIs whose terms permit this use.

## Merging into your person records

`merge_findings_into_person(seed, findings)` returns a provider-agnostic profile
(scalar attributes keep the highest-confidence value; multi-valued types accumulate
a confidence-sorted, deduped list; every value keeps a provenance trail). Implement
the `PersonRepository` protocol to write that into your schema; `schema.sql` shows
the raw-graph tables and a suggested `enrichment_profile JSONB` column.

## Tests

```bash
cd enrichment && pip install httpx pytest pytest-asyncio && python3 -m pytest -q
```

36 tests cover normalization, routing, dedup, depth/budget caps, suppression
(seed + produced), audit logging, quota disabling, timeouts, error containment,
token-bucket pacing, cache hits, HTTP backoff/`Retry-After`, per-module response
parsing, and profile merging. All provider calls are mocked (`httpx.MockTransport`);
the suite needs no network, Redis or Postgres.
