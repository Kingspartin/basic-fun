"""Persistence of scan results and merge into person records.

Two responsibilities:

1. **Store the raw graph** — every entity node and every finding edge, with the
   parent entity, source module, timestamp and confidence — so any fact can be
   traced to the source that produced it and the identifier it came from.
2. **Merge into person records** — fold a scan's findings into a single profile.
   ``merge_findings_into_person`` produces a provider-agnostic profile dict; the
   ``PersonRepository`` protocol is the seam where you write it into *your* schema.
   The default in-memory repo shows the shape and is what the tests use.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .entities import Entity, EntityType, Finding


@runtime_checkable
class Storage(Protocol):
    async def persist_entity(self, scan_id: str, entity: Entity, depth: int,
                             parent: Entity | None) -> None: ...
    async def persist_finding(self, scan_id: str, finding: Finding) -> None: ...


class InMemoryStorage:
    def __init__(self) -> None:
        self.entities: dict[str, list[dict]] = defaultdict(list)
        self.findings: dict[str, list[Finding]] = defaultdict(list)

    async def persist_entity(self, scan_id, entity, depth, parent) -> None:
        self.entities[scan_id].append({
            "type": entity.type.value, "value": entity.value,
            "normalized": entity.normalized, "depth": depth,
            "parent": parent.cache_token() if parent else None,
        })

    async def persist_finding(self, scan_id, finding) -> None:
        self.findings[scan_id].append(finding)


class PostgresStorage:
    """Writes to ``scan_entities`` and ``findings`` (see schema.sql). ``pool`` is asyncpg."""

    def __init__(self, pool) -> None:
        self._pool = pool

    async def persist_entity(self, scan_id, entity, depth, parent) -> None:
        await self._pool.execute(
            """INSERT INTO scan_entities (scan_id, entity_type, entity_value, normalized_value, depth, parent_normalized)
               VALUES ($1,$2,$3,$4,$5,$6)
               ON CONFLICT (scan_id, entity_type, normalized_value) DO NOTHING""",
            scan_id, entity.type.value, entity.value, entity.normalized, depth,
            parent.normalized if parent else None,
        )

    async def persist_finding(self, scan_id, finding: Finding) -> None:
        import json
        r = finding.as_record()
        await self._pool.execute(
            """INSERT INTO findings
                 (scan_id, module, parent_type, parent_value, entity_type, entity_value,
                  normalized_value, confidence, label, raw, created_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now())""",
            scan_id, r["module"], r["parent_type"], r["parent_value"],
            r["entity_type"], r["entity_value"], r["entity_normalized"],
            r["confidence"], r["label"], json.dumps(r["raw"]),
        )


@runtime_checkable
class PersonRepository(Protocol):
    async def upsert_person(self, profile: dict[str, Any]) -> str:
        """Merge ``profile`` into your person store; return the person id."""
        ...


# Which entity types collapse to a single "best" value vs. accumulate as a list.
_SCALAR = {EntityType.FULL_NAME, EntityType.LOCATION}
_MULTI = {
    EntityType.EMAIL: "emails", EntityType.PHONE: "phones",
    EntityType.USERNAME: "usernames", EntityType.DOMAIN: "domains",
    EntityType.URL: "urls", EntityType.ORGANIZATION: "organizations",
    EntityType.ACCOUNT: "accounts", EntityType.BREACH: "breaches",
    EntityType.IMAGE: "images", EntityType.IP_ADDRESS: "ip_addresses",
    EntityType.PGP_KEY: "pgp_keys",
}


@dataclass
class MergedProfile:
    seed: dict[str, str]
    attributes: dict[str, Any] = field(default_factory=dict)
    # attribute value -> provenance list [{module, confidence, parent, timestamp}]
    provenance: dict[str, list[dict]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"seed": self.seed, "attributes": self.attributes,
                "provenance": self.provenance}


def merge_findings_into_person(seed: Entity, findings: list[Finding]) -> MergedProfile:
    """Fold findings into one profile.

    * multi-valued types accumulate a deduped, confidence-sorted list;
    * scalar types (name, location) keep the single highest-confidence value;
    * every attribute value keeps a provenance trail so nothing is un-sourced.

    Confidence for a repeated value is boosted when independent modules agree,
    capped at 1.0 — corroboration should raise trust, not overflow it.
    """
    prof = MergedProfile(seed={"type": seed.type.value, "value": seed.value})
    scalar_best: dict[EntityType, tuple[float, str]] = {}
    multi: dict[str, dict[str, float]] = defaultdict(dict)

    for f in findings:
        et, val = f.entity.type, f.entity.value
        pkey = f"{et.value}:{f.entity.normalized}"
        prof.provenance.setdefault(pkey, []).append({
            "module": f.module, "confidence": f.confidence,
            "parent": f.parent.cache_token() if f.parent else None,
            "label": f.label, "timestamp": f.timestamp.isoformat(),
        })
        if et in _SCALAR:
            cur = scalar_best.get(et)
            if cur is None or f.confidence > cur[0]:
                scalar_best[et] = (f.confidence, val)
        elif et in _MULTI:
            bucket = multi[_MULTI[et]]
            # corroboration bump: 1 - product of (1 - conf) across sources
            prev = bucket.get(val, 0.0)
            bucket[val] = 1.0 - (1.0 - prev) * (1.0 - f.confidence)

    for et, (conf, val) in scalar_best.items():
        prof.attributes[et.value] = {"value": val, "confidence": round(conf, 3)}
    for field_name, values in multi.items():
        prof.attributes[field_name] = [
            {"value": v, "confidence": round(c, 3)}
            for v, c in sorted(values.items(), key=lambda kv: kv[1], reverse=True)
        ]
    return prof


class InMemoryPersonRepository:
    def __init__(self) -> None:
        self.people: dict[str, dict] = {}

    async def upsert_person(self, profile: dict[str, Any]) -> str:
        seed = profile["seed"]
        pid = f"{seed['type']}:{seed['value']}"
        self.people[pid] = profile
        return pid
