"""Have I Been Pwned — email -> breach names (official API v3).

Uses the official ``breachedaccount`` endpoint with an ``hibp-api-key``. Per HIBP
terms this requires a paid key and a descriptive User-Agent; there is no scraping
and no key rotation. 404 means "no breaches for this address" (a successful,
empty result), not an error.
"""
from __future__ import annotations

from urllib.parse import quote

from ..entities import Entity, EntityType, Finding
from ..errors import ConfigurationError, UpstreamError
from .base import EnrichmentModule

API = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"


class HaveIBeenPwnedModule(EnrichmentModule):
    name = "hibp"
    watched_types = frozenset({EntityType.EMAIL})
    produced_types = frozenset({EntityType.BREACH})
    requires_api_key = True
    terms_note = "HIBP official API v3; paid API key required; official rate limits only."

    async def handle(self, entity: Entity) -> list[Finding]:
        url = API.format(account=quote(entity.normalized, safe=""))
        status, body = await self.http.get_json(
            url,
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": self.config.api_key},
            timeout=self.config.timeout_seconds,
        )
        if status == 404:
            return []  # queried fine; no breaches
        if status == 401:
            raise ConfigurationError("HIBP: unauthorized (invalid API key)")
        if status == 403:
            raise UpstreamError("HIBP: forbidden (missing/blocked User-Agent)", 403)
        if status != 200 or not isinstance(body, list):
            raise UpstreamError(f"HIBP: unexpected status {status}", status)

        findings: list[Finding] = []
        for b in body:
            name = b.get("Name") or b.get("Title")
            if not name:
                continue
            findings.append(Finding(
                entity=Entity(EntityType.BREACH, name),
                confidence=0.98,  # HIBP is authoritative for breach membership
                label=f"Breach: {b.get('Title', name)}",
                raw={k: b.get(k) for k in
                     ("Title", "Domain", "BreachDate", "PwnCount", "DataClasses", "IsVerified")},
            ))
        return findings
