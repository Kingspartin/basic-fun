"""DNS + RDAP — domain -> mail infrastructure and registration facts.

Keyless and public: Google DNS-over-HTTPS for MX records and rdap.org for
registration (registrar, registrant org, dates, contact email where the registry
publishes it). Mail-server hosts are emitted as low-confidence domain leads and
sink to the bottom of the merged profile; registration facts ride in ``raw``.
"""
from __future__ import annotations

from ..entities import Entity, EntityType, Finding
from ..errors import UpstreamError
from .base import EnrichmentModule

DOH = "https://dns.google/resolve"
RDAP = "https://rdap.org/domain/{domain}"


def _vcard_get(vcard: list, key: str) -> str | None:
    # vcardArray = ["vcard", [ [name, params, type, value], ... ]]
    try:
        for entry in vcard[1]:
            if entry[0] == key:
                return entry[3]
    except (IndexError, TypeError):
        pass
    return None


class DnsRdapModule(EnrichmentModule):
    name = "dns_rdap"
    watched_types = frozenset({EntityType.DOMAIN})
    produced_types = frozenset({EntityType.DOMAIN, EntityType.ORGANIZATION, EntityType.EMAIL})
    requires_api_key = False
    terms_note = "Google DNS-over-HTTPS + rdap.org; public, keyless."

    async def handle(self, entity: Entity) -> list[Finding]:
        domain = entity.normalized
        findings: list[Finding] = []

        # --- MX records ---
        status, body = await self.http.get_json(
            DOH, params={"name": domain, "type": "MX"}, timeout=self.config.timeout_seconds,
            headers={"accept": "application/dns-json"},
        )
        if status == 200 and isinstance(body, dict):
            for a in body.get("Answer", []) or []:
                if a.get("type") != 15:
                    continue
                host = str(a.get("data", "")).split()[-1].rstrip(".").lower()
                if host:
                    findings.append(Finding(
                        entity=Entity(EntityType.DOMAIN, host),
                        confidence=0.3, label="mail server (infrastructure)",
                        raw={"record": "MX", "of": domain},
                    ))

        # --- RDAP registration ---
        status, body = await self.http.get_json(
            RDAP.format(domain=domain), timeout=self.config.timeout_seconds,
        )
        if status == 200 and isinstance(body, dict):
            events = {e.get("eventAction"): e.get("eventDate") for e in body.get("events", []) or []}
            reg_raw = {"registration": events.get("registration"),
                       "expiration": events.get("expiration"),
                       "status": body.get("status")}
            for ent in body.get("entities", []) or []:
                roles = ent.get("roles") or []
                vcard = ent.get("vcardArray")
                fn = _vcard_get(vcard, "fn") if vcard else None
                email = _vcard_get(vcard, "email") if vcard else None
                if fn and ("registrar" in roles or "registrant" in roles):
                    findings.append(Finding(
                        entity=Entity(EntityType.ORGANIZATION, fn),
                        confidence=0.7 if "registrant" in roles else 0.5,
                        label=f"RDAP {'/'.join(roles)}", raw=reg_raw,
                    ))
                if email and "registrant" in roles:
                    findings.append(Finding(
                        entity=Entity(EntityType.EMAIL, email),
                        confidence=0.6, label="RDAP registrant email", raw=reg_raw,
                    ))
        elif status not in (200, 404):
            raise UpstreamError(f"RDAP: unexpected status {status}", status)

        return findings
