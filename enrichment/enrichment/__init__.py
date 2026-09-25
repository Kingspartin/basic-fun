"""SpiderFoot-style multi-source enrichment layer.

Public surface:

    from enrichment import Entity, EntityType, build_dispatcher, ScanSettings

    dispatcher = build_dispatcher(module_config={...})
    result = await dispatcher.scan(
        Entity(EntityType.EMAIL, "person@example.com"),
        requester_id="analyst-42", purpose="fraud-review case #123",
        max_depth=2, max_requests=100,
    )
    # result.profile   -> merged person profile with provenance
    # result.findings  -> every finding, traceable to module + parent entity
    # result.stats     -> requests, cache hits, disabled modules, timings
"""
from __future__ import annotations

from .config import build_dispatcher, build_modules
from .dispatcher import Dispatcher, ScanResult, ScanSettings
from .entities import Entity, EntityType, Finding, normalize
from .modules.base import EnrichmentModule, ModuleConfig

__all__ = [
    "Entity", "EntityType", "Finding", "normalize",
    "EnrichmentModule", "ModuleConfig",
    "Dispatcher", "ScanResult", "ScanSettings",
    "build_dispatcher", "build_modules",
]
