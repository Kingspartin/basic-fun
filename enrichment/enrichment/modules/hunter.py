"""Hunter.io — domain -> email addresses, people and organization (official API v2).

Uses the ``domain-search`` endpoint. Hunter's own per-email ``confidence`` (0-100)
is carried straight through onto the produced email findings. A 401 is a bad key;
429 is surfaced as RateLimited by the HTTP layer; Hunter's "you're out of
searches" also arrives as 429, which the dispatcher treats as a skip/backoff.
"""
from __future__ import annotations

from ..entities import Entity, EntityType, Finding
from ..errors import ConfigurationError, QuotaExceeded, UpstreamError
from .base import EnrichmentModule

API = "https://api.hunter.io/v2/domain-search"


class HunterModule(EnrichmentModule):
    name = "hunter"
    watched_types = frozenset({EntityType.DOMAIN})
    produced_types = frozenset({EntityType.EMAIL, EntityType.FULL_NAME, EntityType.ORGANIZATION})
    requires_api_key = True
    terms_note = "Hunter.io official API v2; API key required; usage counts against your plan."

    async def handle(self, entity: Entity) -> list[Finding]:
        status, body = await self.http.get_json(
            API,
            params={"domain": entity.normalized, "api_key": self.config.api_key, "limit": 50},
            timeout=self.config.timeout_seconds,
        )
        if status == 401:
            raise ConfigurationError("Hunter: unauthorized (invalid API key)")
        if status in (402, 451):  # payment required / plan limit
            raise QuotaExceeded(f"Hunter: plan limit ({status})")
        if status != 200 or not isinstance(body, dict):
            raise UpstreamError(f"Hunter: unexpected status {status}", status)

        data = body.get("data") or {}
        findings: list[Finding] = []

        org = data.get("organization")
        if org:
            findings.append(Finding(entity=Entity(EntityType.ORGANIZATION, org),
                                    confidence=0.6, label="Hunter organization"))

        for e in data.get("emails", []) or []:
            value = e.get("value")
            if not value:
                continue
            conf = (e.get("confidence") or 0) / 100.0
            first, last, position = e.get("first_name"), e.get("last_name"), e.get("position")
            findings.append(Finding(
                entity=Entity(EntityType.EMAIL, value),
                confidence=round(max(0.3, conf), 3),
                label=position or "Hunter email",
                raw={k: e.get(k) for k in ("type", "confidence", "position", "department", "seniority")},
            ))
            if first and last:
                findings.append(Finding(
                    entity=Entity(EntityType.FULL_NAME, f"{first} {last}"),
                    confidence=round(min(0.7, max(0.4, conf)), 3),
                    label=position or "Hunter contact",
                    raw={"email": value, "position": position},
                ))
        return findings
