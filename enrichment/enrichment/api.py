"""FastAPI integration.

Drop this router into your existing app. It exposes the enrichment layer as an
endpoint that your current search flow can call after it resolves a seed
identifier. Two compliance fields are **required** on every request — ``requester_id``
(who is asking) and ``purpose`` (why) — and both are written to the audit log
before any provider is queried.

Wiring into an existing search:

    from enrichment.api import make_router
    from enrichment import build_dispatcher
    dispatcher = build_dispatcher(redis=redis, pg_pool=pool, module_config=CONFIG)
    app.include_router(make_router(dispatcher, person_repo=my_repo))

Replace ``resolve_requester`` with your real auth dependency so ``requester_id``
comes from the authenticated principal, not the request body.
"""
from __future__ import annotations

from typing import Any

try:
    from fastapi import APIRouter, Depends, HTTPException
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover - only needed when serving HTTP
    raise ImportError("enrichment.api requires fastapi and pydantic") from exc

from .dispatcher import Dispatcher
from .entities import Entity, EntityType
from .storage import PersonRepository, merge_findings_into_person


class ScanRequest(BaseModel):
    seed_type: EntityType
    seed_value: str = Field(min_length=1, max_length=320)
    purpose: str = Field(min_length=3, max_length=500,
                         description="Stated, lawful purpose; recorded in the audit log.")
    max_depth: int | None = Field(default=None, ge=0, le=4)
    max_requests: int | None = Field(default=None, ge=1, le=1000)
    persist_person: bool = True


class ScanResponse(BaseModel):
    scan_id: str
    aborted: bool
    abort_reason: str | None
    profile: dict[str, Any]
    findings: list[dict[str, Any]]
    stats: dict[str, Any]
    person_id: str | None = None


async def resolve_requester() -> str:
    """Replace with your auth dependency. Returning a fixed value here would defeat
    the audit trail, so this default refuses rather than guessing an identity."""
    raise HTTPException(status_code=501,
                        detail="wire resolve_requester to your auth layer")


def make_router(
    dispatcher: Dispatcher,
    *,
    person_repo: PersonRepository | None = None,
    requester_dep=resolve_requester,
) -> "APIRouter":
    router = APIRouter(prefix="/enrichment", tags=["enrichment"])

    @router.post("/scan", response_model=ScanResponse)
    async def scan(req: ScanRequest, requester_id: str = Depends(requester_dep)) -> ScanResponse:
        seed = Entity(req.seed_type, req.seed_value)
        result = await dispatcher.scan(
            seed, requester_id=requester_id, purpose=req.purpose,
            max_depth=req.max_depth, max_requests=req.max_requests,
        )
        person_id = None
        if req.persist_person and person_repo is not None and not result.aborted:
            profile = merge_findings_into_person(seed, result.findings).to_dict()
            person_id = await person_repo.upsert_person(profile)
        return ScanResponse(
            scan_id=result.scan_id, aborted=result.aborted, abort_reason=result.abort_reason,
            profile=result.profile,
            findings=[f.as_record() for f in result.findings],
            stats=result.stats, person_id=person_id,
        )

    @router.get("/modules")
    async def modules() -> list[dict[str, Any]]:
        return [{
            "name": m.name,
            "watched_types": sorted(t.value for t in m.watched_types),
            "produced_types": sorted(t.value for t in m.produced_types),
            "requires_api_key": m.requires_api_key,
            "enabled": m.config.enabled,
            "terms_note": m.terms_note,
        } for m in dispatcher.modules]

    return router
