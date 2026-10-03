import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from enrichment.entities import Entity, EntityType, Finding  # noqa: E402
from enrichment.http import HttpClient  # noqa: E402
from enrichment.modules.base import EnrichmentModule, ModuleConfig  # noqa: E402


def http_for(handler) -> HttpClient:
    """HttpClient backed by an httpx MockTransport, with near-zero backoff."""
    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    return HttpClient(client, base_backoff=0.001, max_backoff=0.02, max_retries=3)


def make_module(name, watched, produced, handler, **cfg_kwargs):
    """Build a fake module whose handle() delegates to ``handler(entity)``."""
    calls = []

    class _Fake(EnrichmentModule):
        pass

    _Fake.name = name
    _Fake.watched_types = frozenset(watched)
    _Fake.produced_types = frozenset(produced)

    async def handle(self, entity):
        calls.append(entity)
        return await handler(entity)

    _Fake.handle = handle
    _Fake.__abstractmethods__ = frozenset()  # handle is now provided
    inst = _Fake(ModuleConfig(**cfg_kwargs), http=None)
    inst.calls = calls
    return inst


@pytest.fixture
def E():
    return Entity


@pytest.fixture
def F():
    return Finding
