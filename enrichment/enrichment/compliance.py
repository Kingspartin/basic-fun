"""Compliance controls: suppression/opt-out enforcement and audit logging.

These are not optional. The dispatcher checks the suppression list before it
queries *or* stores any entity (seed or discovered), and it writes an audit
record for every scan (requester, purpose, timestamp, outcome). Both are defined
as protocols so they can be backed by Postgres in production or in-memory in
tests, and so an organization can plug in its own system of record.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from .entities import Entity, EntityType, normalize

log = logging.getLogger("enrichment.compliance")


@runtime_checkable
class SuppressionList(Protocol):
    """Opt-out / do-not-process list.

    A subject who has opted out (or whom law requires we not process) must be
    matchable by any of their identifiers, so entries are keyed by
    ``(type, normalized_value)``.
    """

    async def is_suppressed(self, entity: Entity) -> bool: ...


@runtime_checkable
class AuditLog(Protocol):
    async def record_scan_start(self, record: "ScanAudit") -> None: ...
    async def record_scan_end(self, scan_id: str, summary: dict) -> None: ...
    async def record_suppressed(self, scan_id: str, entity: Entity, stage: str) -> None: ...


@dataclass
class ScanAudit:
    scan_id: str
    requester_id: str
    purpose: str
    seed_type: str
    seed_value: str  # store normalized, not raw, to avoid leaking formatting quirks
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class InMemorySuppressionList:
    """Suppression list backed by a set of normalized keys. Good for tests and
    small deployments; swap for :class:`PostgresSuppressionList` in production."""

    def __init__(self) -> None:
        self._keys: set[tuple[str, str]] = set()

    def add(self, entity_type: EntityType, value: str) -> None:
        self._keys.add((entity_type.value, normalize(entity_type, value)))

    def remove(self, entity_type: EntityType, value: str) -> None:
        self._keys.discard((entity_type.value, normalize(entity_type, value)))

    async def is_suppressed(self, entity: Entity) -> bool:
        return entity.key in self._keys


class InMemoryAuditLog:
    def __init__(self) -> None:
        self.scans: dict[str, dict] = {}
        self.suppressed: list[dict] = []

    async def record_scan_start(self, record: ScanAudit) -> None:
        self.scans[record.scan_id] = {
            "scan_id": record.scan_id,
            "requester_id": record.requester_id,
            "purpose": record.purpose,
            "seed_type": record.seed_type,
            "seed_value": record.seed_value,
            "started_at": record.started_at.isoformat(),
            "summary": None,
        }
        log.info("scan %s start requester=%s purpose=%r seed=%s:%s",
                 record.scan_id, record.requester_id, record.purpose,
                 record.seed_type, record.seed_value)

    async def record_scan_end(self, scan_id: str, summary: dict) -> None:
        if scan_id in self.scans:
            self.scans[scan_id]["summary"] = summary
        log.info("scan %s end %s", scan_id, summary)

    async def record_suppressed(self, scan_id: str, entity: Entity, stage: str) -> None:
        self.suppressed.append({
            "scan_id": scan_id, "stage": stage,
            "entity_type": entity.type.value, "entity_value": entity.normalized,
            "at": datetime.now(timezone.utc).isoformat(),
        })
        log.info("scan %s suppressed %s at %s", scan_id, entity, stage)


class PostgresSuppressionList:
    """Suppression list backed by the ``suppression_list`` table (see schema.sql).

    ``pool`` is an ``asyncpg`` pool. Kept import-free at module load so the rest
    of the package runs without asyncpg installed.
    """

    def __init__(self, pool) -> None:
        self._pool = pool

    async def is_suppressed(self, entity: Entity) -> bool:
        row = await self._pool.fetchval(
            "SELECT 1 FROM suppression_list WHERE entity_type = $1 AND normalized_value = $2 LIMIT 1",
            entity.type.value, entity.normalized,
        )
        return row is not None


class PostgresAuditLog:
    def __init__(self, pool) -> None:
        self._pool = pool

    async def record_scan_start(self, record: ScanAudit) -> None:
        await self._pool.execute(
            """INSERT INTO scan_audit (scan_id, requester_id, purpose, seed_type, seed_value, started_at)
               VALUES ($1,$2,$3,$4,$5,$6)
               ON CONFLICT (scan_id) DO NOTHING""",
            record.scan_id, record.requester_id, record.purpose,
            record.seed_type, record.seed_value, record.started_at,
        )

    async def record_scan_end(self, scan_id: str, summary: dict) -> None:
        import json
        await self._pool.execute(
            "UPDATE scan_audit SET ended_at = now(), summary = $2 WHERE scan_id = $1",
            scan_id, json.dumps(summary),
        )

    async def record_suppressed(self, scan_id: str, entity: Entity, stage: str) -> None:
        await self._pool.execute(
            """INSERT INTO suppression_hits (scan_id, entity_type, normalized_value, stage)
               VALUES ($1,$2,$3,$4)""",
            scan_id, entity.type.value, entity.normalized, stage,
        )
