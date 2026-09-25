"""Configuration and wiring.

``build_modules`` turns a plain config dict (typically loaded from env/secrets)
into live module instances, skipping any that are disabled or missing a required
key. ``build_dispatcher`` assembles the whole stack, choosing Redis/Postgres
backends when their clients are supplied and falling back to in-memory otherwise —
so the same code runs in tests, locally, and in production.

Rate-per-second and daily-quota defaults below are conservative starting points;
set them to each provider's documented limits for your plan.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from .dispatcher import Dispatcher, ScanSettings
from .http import HttpClient
from .modules import ALL_MODULES
from .modules.base import ModuleConfig

log = logging.getLogger("enrichment.config")

# Conservative defaults per module: (requests_per_second, burst, daily_quota).
# Override per deployment/plan.
DEFAULT_LIMITS: dict[str, tuple[float, int, int | None]] = {
    "hibp": (0.1, 1, 1000),      # HIBP asks for gentle pacing per key
    "hunter": (2.0, 4, 500),     # depends on plan
    "dns_rdap": (10.0, 20, None),
    "gravatar": (5.0, 10, None),
    "github": (1.0, 5, 5000),    # 5000/hr authenticated
}


def module_config_from_env(name: str, overrides: dict[str, Any] | None = None) -> ModuleConfig:
    rps, burst, quota = DEFAULT_LIMITS.get(name, (1.0, 1, None))
    key_env = f"ENRICH_{name.upper()}_API_KEY"
    cfg = ModuleConfig(
        enabled=os.getenv(f"ENRICH_{name.upper()}_ENABLED", "1") not in ("0", "false", "False"),
        api_key=os.getenv(key_env),
        requests_per_second=rps, burst=burst, daily_quota=quota,
    )
    if overrides:
        for k, v in overrides.items():
            setattr(cfg, k, v)
    return cfg


def build_modules(
    config: dict[str, dict[str, Any]] | None,
    http: HttpClient,
) -> list:
    """Instantiate enabled, correctly-configured modules.

    ``config`` maps module name -> field overrides for :class:`ModuleConfig`.
    Missing entries fall back to env + defaults. A module that requires an API key
    it does not have is skipped with a warning, not an error.
    """
    from .errors import ConfigurationError
    config = config or {}
    out = []
    for name, cls in ALL_MODULES.items():
        cfg = module_config_from_env(name, config.get(name))
        if not cfg.enabled:
            continue
        try:
            out.append(cls(cfg, http))
        except ConfigurationError as exc:
            log.warning("skipping module %s: %s", name, exc)
    return out


def build_dispatcher(
    *,
    module_config: dict[str, dict[str, Any]] | None = None,
    settings: ScanSettings | None = None,
    redis=None,
    pg_pool=None,
    http: HttpClient | None = None,
) -> Dispatcher:
    """Wire the full stack. Pass ``redis`` and/or ``pg_pool`` to use them; omit for
    in-memory backends (tests, single-process dev)."""
    from .cache import InMemoryCache, PostgresCache, RedisCache
    from .compliance import (InMemoryAuditLog, InMemorySuppressionList,
                             PostgresAuditLog, PostgresSuppressionList)
    from .quota import InMemoryQuotaTracker, RedisQuotaTracker
    from .ratelimit import InMemoryRateLimiter, RedisRateLimiter
    from .storage import InMemoryStorage, PostgresStorage

    http = http or HttpClient()
    modules = build_modules(module_config, http)

    if redis is not None:
        cache = RedisCache(redis)
        rate = RedisRateLimiter(redis)
        for m in modules:
            rate.configure(m.name, m.config.requests_per_second, m.config.burst)
        quota = RedisQuotaTracker(redis)
    else:
        cache, rate, quota = InMemoryCache(), InMemoryRateLimiter(), InMemoryQuotaTracker()

    if pg_pool is not None:
        suppression = PostgresSuppressionList(pg_pool)
        audit = PostgresAuditLog(pg_pool)
        storage = PostgresStorage(pg_pool)
        if redis is None:
            from .cache import PostgresCache
            cache = PostgresCache(pg_pool)
    else:
        suppression, audit, storage = (InMemorySuppressionList(), InMemoryAuditLog(),
                                       InMemoryStorage())

    return Dispatcher(modules, cache=cache, rate_limiter=rate, quota=quota,
                      suppression=suppression, audit=audit, storage=storage,
                      settings=settings or ScanSettings())
