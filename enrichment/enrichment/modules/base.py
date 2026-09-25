"""Common module interface and per-module configuration.

A module is a self-contained adapter to one data source. It declares which entity
types it accepts (``watched_types``) and can emit (``produced_types``), and it
implements ``handle(entity) -> list[Finding]``. Everything cross-cutting — routing,
dedup, rate limiting, quota, caching, retries, compliance — lives in the
dispatcher, so a module only has to translate one provider's response into
Findings.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..entities import Entity, EntityType, Finding
from ..errors import ConfigurationError
from ..http import HttpClient


@dataclass
class ModuleConfig:
    enabled: bool = True
    api_key: str | None = None
    requests_per_second: float = 1.0
    burst: int | None = None            # token-bucket capacity; defaults to ~rps
    daily_quota: int | None = None      # None = unlimited
    timeout_seconds: float = 15.0
    cache_ttl_seconds: int = 86_400     # 24h
    extra: dict[str, Any] = field(default_factory=dict)


class EnrichmentModule(ABC):
    #: unique, stable identifier used in config, cache keys, quotas and provenance
    name: str = ""
    #: entity types this module accepts as input
    watched_types: frozenset[EntityType] = frozenset()
    #: entity types this module can emit
    produced_types: frozenset[EntityType] = frozenset()
    #: whether ``config.api_key`` must be present
    requires_api_key: bool = False
    #: short note on the terms under which this source may be used (for the registry)
    terms_note: str = ""

    def __init__(self, config: ModuleConfig, http: HttpClient) -> None:
        self.config = config
        self.http = http
        if self.requires_api_key and not (config.api_key and config.api_key.strip()):
            raise ConfigurationError(f"module {self.name!r} requires an API key")

    def accepts(self, entity: Entity) -> bool:
        return entity.type in self.watched_types

    @abstractmethod
    async def handle(self, entity: Entity) -> list[Finding]:
        """Query the source for ``entity`` and return Findings.

        Implementations should raise :class:`~enrichment.errors.RateLimited` /
        ``QuotaExceeded`` / ``UpstreamError`` rather than swallowing them, so the
        dispatcher can back off, disable, or skip appropriately. Returning ``[]``
        means "queried successfully, nothing found".
        """
        raise NotImplementedError
